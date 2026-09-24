package source

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoaderLocalDirectory(t *testing.T) {
	dir, err := os.MkdirTemp(".", "loader-local-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	relative := filepath.Base(dir)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	loader := NewLoader(testLogger())
	workspace, err := loader.Load(context.Background(), relative)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if workspace.Dir != absolute {
		t.Fatalf("Workspace.Dir = %q, want %q", workspace.Dir, absolute)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestLoaderMissingLocalDirectory(t *testing.T) {
	_, err := NewLoader(testLogger()).Load(context.Background(), filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "source directory") {
		t.Fatalf("Load() error = %v, want local source error", err)
	}
}

func TestLoaderLocalGitRemote(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repository")
	runGit(t, "", "init", "-b", "main", repository)
	runGit(t, repository, "config", "user.email", "test@example.com")
	runGit(t, repository, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "cmd", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "cmd", "tool", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", ".")
	runGit(t, repository, "commit", "-m", "initial")
	commit := gitOutput(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "checkout", "-b", "release/1.0")
	remote := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, "", "clone", "--bare", repository, remote)

	workspace, err := NewLoader(testLogger()).Load(context.Background(), "file://"+remote+"#release/1.0:cmd/tool")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer workspace.Close()
	if _, err := os.Stat(filepath.Join(workspace.Dir, "main.go")); err != nil {
		t.Fatalf("selected source file is missing: %v", err)
	}
	workspace, err = NewLoader(testLogger()).Load(context.Background(), "file://"+remote+"#"+commit)
	if err != nil {
		t.Fatalf("Load() exact commit error = %v", err)
	}
	defer workspace.Close()
}

func runGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func gitOutput(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}
