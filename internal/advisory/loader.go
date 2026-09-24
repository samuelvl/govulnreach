package advisory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultOSVBaseURL  = "https://api.osv.dev/v1/vulns/"
	defaultMaxBodySize = 32 << 20
	maxErrorBodySize   = 8 << 10
	userAgent          = "govulnreach/OSV advisory loader"
)

var osvIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Loader struct {
	Client      *http.Client
	BaseURL     *url.URL
	MaxBodySize int64
}

func NewLoader() *Loader {
	baseURL, err := url.Parse(defaultOSVBaseURL)
	if err != nil {
		panic(fmt.Sprintf("parse default OSV URL: %v", err))
	}
	return &Loader{
		Client:      &http.Client{Timeout: 30 * time.Second},
		BaseURL:     baseURL,
		MaxBodySize: defaultMaxBodySize,
	}
}

type referenceKind uint8

const (
	localReference referenceKind = iota
	remoteReference
)

type classifiedReference struct {
	kind referenceKind
	path string
	id   string
}

func classifyReference(reference string) (classifiedReference, error) {
	if reference == "" {
		return classifiedReference{}, errors.New("advisory reference cannot be empty")
	}

	if _, err := os.Stat(reference); err == nil {
		return classifiedReference{kind: localReference, path: reference}, nil
	}

	if isPathLike(reference) {
		return classifiedReference{kind: localReference, path: reference}, nil
	}
	if osvIDPattern.MatchString(reference) {
		return classifiedReference{kind: remoteReference, id: reference}, nil
	}
	return classifiedReference{}, fmt.Errorf("invalid advisory reference %q: expected a local file path or exact OSV ID", reference)
}

func isPathLike(reference string) bool {
	return filepath.IsAbs(reference) ||
		strings.HasPrefix(reference, ".") ||
		strings.ContainsAny(reference, `/\`) ||
		strings.HasSuffix(reference, ".json")
}

func (l *Loader) Load(ctx context.Context, reference, format string) (*Advisory, error) {
	classified, err := classifyReference(reference)
	if err != nil {
		return nil, err
	}

	switch classified.kind {
	case localReference:
		info, err := os.Stat(classified.path)
		if err != nil {
			return nil, fmt.Errorf("read advisory file %q: %w", classified.path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("read advisory file %q: not a regular file", classified.path)
		}

		file, err := os.Open(classified.path)
		if err != nil {
			return nil, fmt.Errorf("read advisory file %q: %w", classified.path, err)
		}
		defer file.Close()

		info, err = file.Stat()
		if err != nil {
			return nil, fmt.Errorf("read advisory file %q: stat: %w", classified.path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("read advisory file %q: not a regular file", classified.path)
		}

		maxBodySize := int64(defaultMaxBodySize)
		if l != nil && l.MaxBodySize > 0 {
			maxBodySize = l.MaxBodySize
		}
		if info.Size() > maxBodySize {
			return nil, fmt.Errorf("read advisory file %q: file exceeds %d bytes", classified.path, maxBodySize)
		}
		data, err := io.ReadAll(io.LimitReader(file, maxBodySize+1))
		if err != nil {
			return nil, fmt.Errorf("read advisory file %q: %w", classified.path, err)
		}
		if int64(len(data)) > maxBodySize {
			return nil, fmt.Errorf("read advisory file %q: file exceeds %d bytes", classified.path, maxBodySize)
		}
		result, err := Parse(format, data)
		if err != nil {
			return nil, fmt.Errorf("parse advisory file %q: %w", classified.path, err)
		}
		return result, nil
	case remoteReference:
		if format != "osv" {
			return nil, fmt.Errorf("remote advisory reference %q supports only the %q format", classified.id, "osv")
		}
		return l.loadRemote(ctx, classified.id)
	default:
		return nil, errors.New("unknown advisory reference type")
	}
}

func (l *Loader) loadRemote(ctx context.Context, id string) (*Advisory, error) {
	if l == nil {
		return nil, errors.New("OSV advisory loader is nil")
	}
	if l.BaseURL == nil {
		return nil, errors.New("OSV advisory loader has no base URL")
	}
	requestURL := *l.BaseURL
	requestURL.Path = strings.TrimSuffix(requestURL.Path, "/") + "/" + id
	requestURL.RawPath = strings.TrimSuffix(requestURL.RawPath, "/") + "/" + url.PathEscape(id)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("fetch OSV advisory %q: create request: %w", id, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	client := l.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch OSV advisory %q: request failed: %w", id, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBodySize))
		if readErr != nil {
			return nil, fmt.Errorf("fetch OSV advisory %q: server returned %s: read error body: %w", id, response.Status, readErr)
		}
		message := strings.TrimSpace(string(body))
		if response.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("fetch OSV advisory %q: not found; use the exact case-sensitive OSV ID", id)
		}
		if message == "" {
			return nil, fmt.Errorf("fetch OSV advisory %q: server returned %s", id, response.Status)
		}
		return nil, fmt.Errorf("fetch OSV advisory %q: server returned %s: %s", id, response.Status, message)
	}

	maxBodySize := l.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = defaultMaxBodySize
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch OSV advisory %q: read response: %w", id, err)
	}
	if int64(len(data)) > maxBodySize {
		return nil, fmt.Errorf("fetch OSV advisory %q: response body exceeds %d bytes", id, maxBodySize)
	}
	result, err := Parse("osv", data)
	if err != nil {
		return nil, fmt.Errorf("parse OSV advisory %q: %w", id, err)
	}
	return result, nil
}
