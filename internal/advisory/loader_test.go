package advisory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validOSV = `{
	"id": "GO-2025-4155",
	"affected": [{
		"package": {"ecosystem": "Go", "name": "example.com/module"},
		"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
	}]
}`

func TestClassifyReference(t *testing.T) {
	file := filepath.Join(t.TempDir(), "GO-2025-4155")
	if err := os.WriteFile(file, []byte(validOSV), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		reference string
		kind      referenceKind
		wantPath  bool
		wantID    string
		wantErr   string
	}{
		{name: "existing file takes precedence", reference: file, kind: localReference, wantPath: true},
		{name: "OSV ID", reference: "GO-2025-4155", kind: remoteReference, wantID: "GO-2025-4155"},
		{name: "GHSA ID", reference: "GHSA-wf45-q9ch-q8gh", kind: remoteReference, wantID: "GHSA-wf45-q9ch-q8gh"},
		{name: "missing JSON path", reference: filepath.Join(t.TempDir(), "missing.json"), kind: localReference, wantPath: true},
		{name: "missing relative path", reference: "missing/advisory", kind: localReference, wantPath: true},
		{name: "malformed identifier", reference: "not_an_id", wantErr: "invalid advisory reference"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyReference(tt.reference)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("classifyReference() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifyReference() error = %v", err)
			}
			if got.kind != tt.kind || (tt.wantPath && got.path != tt.reference) || got.id != tt.wantID {
				t.Fatalf("classifyReference() = %+v", got)
			}
		})
	}
}

func TestLoaderLocalFile(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		requests++
	}))
	t.Cleanup(server.Close)

	path := filepath.Join(t.TempDir(), "GO-2025-4155")
	if err := os.WriteFile(path, []byte(validOSV), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := NewLoader()
	loader.Client = server.Client()
	loader.BaseURL, _ = url.Parse(server.URL + "/")

	got, err := loader.Load(context.Background(), path, "osv")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.ID != "GO-2025-4155" {
		t.Fatalf("Load() ID = %q", got.ID)
	}
	if requests != 0 {
		t.Fatalf("local file contacted HTTP server %d times", requests)
	}
}

func TestLoaderRemote(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		reference string
		format    string
		wantErr   string
		wantPath  string
	}{
		{name: "valid ID", body: validOSV, reference: "GO-2025-4155"},
		{name: "case preserved", body: validOSV, reference: "gO-2025-4155", wantPath: "/v1/vulns/gO-2025-4155"},
		{name: "not found", status: http.StatusNotFound, reference: "GO-2025-4155", wantErr: "exact case-sensitive OSV ID"},
		{name: "server error", status: http.StatusServiceUnavailable, reference: "GO-2025-4155", wantErr: "503 Service Unavailable"},
		{name: "invalid JSON", body: "{", reference: "GO-2025-4155", wantErr: "decode OSV advisory"},
		{name: "invalid advisory", body: `{"id":"GO-2025-4155"}`, reference: "GO-2025-4155", wantErr: "at least one affected module"},
		{name: "unsupported format", body: validOSV, reference: "GO-2025-4155", format: "cve", wantErr: "supports only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				gotPath = request.URL.EscapedPath()
				status := tt.status
				if status == 0 {
					status = http.StatusOK
				}
				response.WriteHeader(status)
				_, _ = response.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			loader := NewLoader()
			loader.Client = server.Client()
			loader.BaseURL, _ = url.Parse(server.URL + "/v1/vulns/")
			format := tt.format
			if format == "" {
				format = "osv"
			}
			got, err := loader.Load(context.Background(), tt.reference, format)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.ID != "GO-2025-4155" {
				t.Fatalf("Load() ID = %q", got.ID)
			}
			wantPath := tt.wantPath
			if wantPath == "" {
				wantPath = "/v1/vulns/GO-2025-4155"
			}
			if gotPath != wantPath {
				t.Fatalf("request path = %q", gotPath)
			}
		})
	}
}

func TestLoaderFailures(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		loader := NewLoader()
		_, err := loader.Load(context.Background(), "./missing.json", "osv")
		if err == nil || !strings.Contains(err.Error(), `read advisory file "./missing.json"`) {
			t.Fatalf("Load() error = %v", err)
		}
	})

	t.Run("oversized local file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "advisory.json")
		if err := os.WriteFile(path, []byte(validOSV), 0o600); err != nil {
			t.Fatal(err)
		}
		loader := NewLoader()
		loader.MaxBodySize = 1
		_, err := loader.Load(context.Background(), path, "osv")
		if err == nil || !strings.Contains(err.Error(), "exceeds 1 bytes") {
			t.Fatalf("Load() error = %v, want file-size error", err)
		}
	})

	t.Run("non-regular local file", func(t *testing.T) {
		path := t.TempDir()
		loader := NewLoader()
		_, err := loader.Load(context.Background(), path, "osv")
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Load() error = %v, want regular-file error", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		t.Cleanup(server.Close)
		loader := NewLoader()
		loader.Client = server.Client()
		loader.BaseURL, _ = url.Parse(server.URL + "/")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := loader.Load(ctx, "GO-2025-4155", "osv")
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Load() error = %v, want canceled context", err)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(validOSV))
		}))
		t.Cleanup(server.Close)
		loader := NewLoader()
		loader.Client = server.Client()
		loader.BaseURL, _ = url.Parse(server.URL + "/")
		loader.MaxBodySize = 1
		_, err := loader.Load(context.Background(), "GO-2025-4155", "osv")
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("Load() error = %v, want response-size error", err)
		}
	})
}
