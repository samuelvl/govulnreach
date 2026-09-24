package source

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/storage/memory"
)

const (
	defaultMaxRepository  = 1 << 30
	defaultMaxExtracted   = 1 << 30
	defaultMaxFile        = 256 << 20
	defaultMaxFiles       = 100000
	defaultMaxSubmodules  = 100
	defaultMaxDepth       = 8
	defaultRequestTimeout = 10 * time.Minute
)

type Workspace struct {
	Dir     string
	cleanup string
}

func (w *Workspace) Close() error {
	if w == nil || w.cleanup == "" {
		return nil
	}
	dir := w.cleanup
	w.cleanup = ""
	return os.RemoveAll(dir)
}

type Loader struct {
	logger            *slog.Logger
	Client            any      // Kept for source compatibility. go-git owns the transport.
	APIBaseURL        *url.URL // Kept for source compatibility with older callers.
	MaxCompressedSize int64    // Deprecated. Use MaxRepositorySize.
	MaxRepositorySize int64
	MaxExtractedSize  int64
	MaxFileSize       int64
	MaxFileCount      int
	MaxSubmoduleCount int
	MaxRecursionDepth int
	RequestTimeout    time.Duration
}

func NewLoader(logger *slog.Logger) *Loader {
	return &Loader{
		logger:            logger,
		MaxRepositorySize: defaultMaxRepository,
		MaxExtractedSize:  defaultMaxExtracted,
		MaxFileSize:       defaultMaxFile,
		MaxFileCount:      defaultMaxFiles,
		MaxSubmoduleCount: defaultMaxSubmodules,
		MaxRecursionDepth: defaultMaxDepth,
		RequestTimeout:    defaultRequestTimeout,
	}
}

type sourceReference struct {
	remote string
	ref    string
	subdir string
}

func (l *Loader) Load(ctx context.Context, reference string) (*Workspace, error) {
	if l == nil {
		return nil, errors.New("source loader is nil")
	}
	if info, err := os.Stat(reference); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("source %q is not a directory", reference)
		}
		dir, err := filepath.Abs(reference)
		if err != nil {
			return nil, fmt.Errorf("resolve source %q: %w", reference, err)
		}
		l.logger.Debug("using local source", "directory", dir)
		return &Workspace{Dir: dir}, nil
	} else if isLocalPath(reference) {
		return nil, fmt.Errorf("source directory %q: %w", reference, err)
	}

	source, err := parseSource(reference)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, l.requestTimeout())
	defer cancel()

	l.logger.Info("listing Git remote", "remote", source.remote)
	refs, err := listRemote(ctx, source.remote)
	if err != nil {
		return nil, fmt.Errorf("list Git remote %q without credentials: %w", source.remote, err)
	}
	resolved, err := resolveReference(source, refs)
	if err != nil {
		return nil, err
	}
	l.logger.Debug("resolved Git reference", "reference", source.ref, "ref", resolved.name, "commit", resolved.hash)

	root, err := createWorkspace()
	if err != nil {
		return nil, fmt.Errorf("create source workspace: %w", err)
	}
	workspace := &Workspace{Dir: root, cleanup: root}
	l.logger.Info("cloning Git remote", "remote", source.remote, "commit", resolved.hash)
	budget := &resourceBudget{loader: l}
	options := &git.CloneOptions{
		URL: source.remote, ReferenceName: resolved.name, SingleBranch: true,
		Depth: 1, Tags: git.AllTags,
	}
	repository, err := git.PlainCloneContext(ctx, root, options)
	if err != nil {
		_ = workspace.Close()
		return nil, fmt.Errorf("clone Git remote %q without credentials: %w", source.remote, err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		_ = workspace.Close()
		return nil, fmt.Errorf("open Git worktree: %w", err)
	}
	if err := worktree.Checkout(&git.CheckoutOptions{Hash: resolved.hash, Force: true}); err != nil {
		_ = workspace.Close()
		return nil, fmt.Errorf("checkout Git commit %s: %w", resolved.hash, err)
	}
	l.logger.Info("checked out Git commit", "commit", resolved.hash)
	if err := loadSubmodules(ctx, repository, root, budget, 0); err != nil {
		_ = workspace.Close()
		return nil, err
	}
	if err := budget.scan(root); err != nil {
		_ = workspace.Close()
		return nil, err
	}
	l.logger.Info("source checkout ready", "directory", root, "submodules", budget.submodules)
	dir, err := pathInside(root, filepath.Join(root, filepath.FromSlash(resolved.subdir)))
	if err != nil {
		_ = workspace.Close()
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		_ = workspace.Close()
		return nil, fmt.Errorf("source subdirectory %q does not exist: %w", resolved.subdir, err)
	}
	if !info.IsDir() {
		_ = workspace.Close()
		return nil, fmt.Errorf("source path %q is not a directory", resolved.subdir)
	}
	workspace.Dir = dir
	return workspace, nil
}

func isLocalPath(value string) bool {
	parsed, err := url.Parse(value)
	return (filepath.IsAbs(value) || strings.HasPrefix(value, ".") ||
		strings.ContainsAny(value, `/\`) || !strings.Contains(value, ":")) &&
		(err != nil || parsed.Scheme == "")
}

func parseSource(value string) (sourceReference, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || (parsed.Host == "" && parsed.Scheme != "file") {
		return sourceReference{}, fmt.Errorf("invalid source %q: expected a local directory or Git remote URL", value)
	}
	if parsed.User != nil || parsed.RawQuery != "" {
		return sourceReference{}, fmt.Errorf("invalid source %q: credentials and queries are not supported", value)
	}
	if parsed.Scheme == "https" && parsed.Host == "github.com" {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) >= 3 && parts[2] == "tree" {
			return sourceReference{}, fmt.Errorf("invalid source %q: use <remote>#<reference>[:<subdirectory>]", value)
		}
	}
	source := sourceReference{remote: value}
	if parsed.Fragment != "" {
		parts := strings.SplitN(parsed.Fragment, ":", 2)
		if parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
			return sourceReference{}, fmt.Errorf("invalid source fragment %q", parsed.Fragment)
		}
		source.ref = parts[0]
		if len(parts) == 2 {
			source.subdir = filepath.ToSlash(filepath.Clean(parts[1]))
		}
		source.remote = strings.SplitN(value, "#", 2)[0]
		return source, validateSubdir(source)
	}
	return source, nil
}

func validateSubdir(source sourceReference) error {
	if source.subdir == "." {
		return nil
	}
	if filepath.IsAbs(source.subdir) || source.subdir == ".." || strings.HasPrefix(source.subdir, "../") {
		return fmt.Errorf("invalid source subdirectory %q", source.subdir)
	}
	return nil
}

type resolvedReference struct {
	name   plumbing.ReferenceName
	hash   plumbing.Hash
	subdir string
}

func listRemote(ctx context.Context, remote string) ([]*plumbing.Reference, error) {
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remote}})
	return r.ListContext(ctx, &git.ListOptions{})
}

func resolveReference(source sourceReference, refs []*plumbing.Reference) (resolvedReference, error) {
	if len(refs) == 0 {
		return resolvedReference{}, fmt.Errorf("remote %q has no references", source.remote)
	}
	if source.ref != "" && len(source.ref) == 40 {
		hash := plumbing.NewHash(source.ref)
		if hash.IsZero() {
			return resolvedReference{}, fmt.Errorf("invalid Git commit %q", source.ref)
		}
		for _, ref := range refs {
			if ref.Type() == plumbing.HashReference && ref.Hash() == hash {
				return resolvedReference{name: ref.Name(), hash: hash, subdir: source.subdir}, nil
			}
		}
		return resolvedReference{name: plumbing.ReferenceName("refs/heads/" + source.ref), hash: hash, subdir: source.subdir}, nil
	}
	best := (*plumbing.Reference)(nil)
	bestLength := -1
	if source.ref == "" {
		for _, ref := range refs {
			if ref.Type() == plumbing.SymbolicReference && ref.Name() == plumbing.HEAD {
				for _, candidate := range refs {
					if candidate.Name() == ref.Target() && candidate.Type() == plumbing.HashReference {
						best = candidate
						break
					}
				}
			}
		}
	}
	for _, ref := range refs {
		if ref.Type() != plumbing.HashReference {
			continue
		}
		short := strings.TrimPrefix(strings.TrimPrefix(ref.Name().String(), "refs/heads/"), "refs/tags/")
		if source.ref == "" {
			if best != nil {
				continue
			}
			if ref.Name().String() < best.Name().String() {
				best = ref
			}
			continue
		}
		if source.ref == short || strings.HasPrefix(source.ref, short+"/") {
			if len(short) > bestLength {
				best, bestLength = ref, len(short)
			}
		}
	}
	if best == nil {
		return resolvedReference{}, fmt.Errorf("resolve Git reference %q: not found", source.ref)
	}
	if source.ref != "" {
		sourceSubdir := strings.TrimPrefix(source.ref, strings.TrimPrefix(strings.TrimPrefix(best.Name().String(), "refs/heads/"), "refs/tags/"))
		sourceSubdir = strings.TrimPrefix(sourceSubdir, "/")
		if source.subdir == "" {
			source.subdir = sourceSubdir
		}
	}
	return resolvedReference{name: best.Name(), hash: best.Hash(), subdir: source.subdir}, nil
}

type resourceBudget struct {
	loader          *Loader
	files           int
	bytes           int64
	repositoryBytes int64
	submodules      int
}

func loadSubmodules(ctx context.Context, repository *git.Repository, root string, budget *resourceBudget, depth int) error {
	if depth >= budget.loader.maxDepth() {
		return fmt.Errorf("submodule recursion exceeds %d levels", budget.loader.maxDepth())
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return fmt.Errorf("open worktree for submodules: %w", err)
	}
	submodules, err := worktree.Submodules()
	if err != nil {
		return fmt.Errorf("read submodules: %w", err)
	}
	for _, submodule := range submodules {
		budget.submodules++
		if budget.submodules > budget.loader.maxSubmodules() {
			return fmt.Errorf("repository contains more than %d submodules", budget.loader.maxSubmodules())
		}
		budget.loader.logger.Info("loading submodule", "path", submodule.Config().Path, "depth", depth+1, "count", budget.submodules)
		if err := submodule.UpdateContext(ctx, &git.SubmoduleUpdateOptions{Init: true, Depth: 1}); err != nil {
			return fmt.Errorf("load submodule %q: %w", submodule.Config().Path, err)
		}
		subrepo, err := submodule.Repository()
		if err != nil {
			return fmt.Errorf("open submodule %q: %w", submodule.Config().Path, err)
		}
		status, err := submodule.Status()
		if err != nil {
			return fmt.Errorf("read submodule %q status: %w", submodule.Config().Path, err)
		}
		if status.Current != status.Expected {
			subrepoWorktree, err := subrepo.Worktree()
			if err != nil {
				return fmt.Errorf("open submodule %q worktree: %w", submodule.Config().Path, err)
			}
			if err := subrepoWorktree.Checkout(&git.CheckoutOptions{Hash: status.Expected, Force: true}); err != nil {
				return fmt.Errorf("checkout submodule %q at %s: %w", submodule.Config().Path, status.Expected, err)
			}
		}
		budget.loader.logger.Debug("loaded submodule", "path", submodule.Config().Path, "commit", status.Expected)
		if err := loadSubmodules(ctx, subrepo, filepath.Join(root, filepath.FromSlash(submodule.Config().Path)), budget, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (l *Loader) maxDepth() int {
	if l.MaxRecursionDepth > 0 {
		return l.MaxRecursionDepth
	}
	return defaultMaxDepth
}

func (l *Loader) requestTimeout() time.Duration {
	if l.RequestTimeout > 0 {
		return l.RequestTimeout
	}
	return defaultRequestTimeout
}

func createWorkspace() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	base := filepath.Join(home, ".local", "tmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create temporary directory %q: %w", base, err)
	}
	return os.MkdirTemp(base, "govulnreach-source-")
}

func (l *Loader) maxSubmodules() int {
	if l.MaxSubmoduleCount > 0 {
		return l.MaxSubmoduleCount
	}
	return defaultMaxSubmodules
}

func (b *resourceBudget) scan(root string) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode().IsRegular() {
			if isGitMetadata(path, root) {
				b.repositoryBytes += info.Size()
				if b.repositoryBytes > b.loader.maxRepository() {
					return fmt.Errorf("repository content exceeds %d bytes", b.loader.maxRepository())
				}
				return nil
			}
			b.files++
			b.bytes += info.Size()
			if info.Size() > b.loader.maxFile() {
				return fmt.Errorf("file %q exceeds %d bytes", path, b.loader.maxFile())
			}
			if b.files > b.loader.maxFiles() {
				return fmt.Errorf("workspace contains more than %d files", b.loader.maxFiles())
			}
			if b.bytes > b.loader.maxExtracted() {
				return fmt.Errorf("extracted content exceeds %d bytes", b.loader.maxExtracted())
			}
		}
		return nil
	})
	return err
}

func isGitMetadata(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts {
		if part == ".git" {
			return true
		}
	}
	return false
}

func (l *Loader) maxFile() int64 {
	if l.MaxFileSize > 0 {
		return l.MaxFileSize
	}
	return defaultMaxFile
}
func (l *Loader) maxFiles() int {
	if l.MaxFileCount > 0 {
		return l.MaxFileCount
	}
	return defaultMaxFiles
}
func (l *Loader) maxRepository() int64 {
	if l.MaxRepositorySize > 0 {
		return l.MaxRepositorySize
	}
	if l.MaxCompressedSize > 0 {
		return l.MaxCompressedSize
	}
	return defaultMaxRepository
}
func (l *Loader) maxExtracted() int64 {
	if l.MaxExtractedSize > 0 {
		return l.MaxExtractedSize
	}
	return defaultMaxExtracted
}

func pathInside(root, target string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(absRoot, absTarget)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	return absTarget, nil
}
