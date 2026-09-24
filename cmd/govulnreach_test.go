package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samuelvl/govulnreach/internal/advisory"
)

type testAdvisoryLoader struct {
	advisory *advisory.Advisory
	err      error
}

func (l testAdvisoryLoader) Load(context.Context, string, string) (*advisory.Advisory, error) {
	return l.advisory, l.err
}

func TestRunAdvisoryFormat(t *testing.T) {
	testdata := filepath.Join("testdata")
	fixture := filepath.Join(testdata, "missing-module")
	base := []string{
		"--source", filepath.Join(fixture, "app"),
		"--advisory", filepath.Join(fixture, "advisory.json"),
	}
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "default OSV", args: base},
		{name: "explicit OSV", args: append(append([]string{}, base...), "--advisory-format", "osv")},
		{name: "unsupported", args: append(append([]string{}, base...), "--advisory-format", "cve"), wantErr: "unsupported advisory format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run(tt.args, &stdout, &stderr)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("run() error = %v, want containing %q", err, tt.wantErr)
			}
			if tt.wantErr == "" && !bytes.Contains(stdout.Bytes(), []byte(`"@context": "https://openvex.dev/ns/v0.2.0"`)) {
				t.Fatalf("stdout is not OpenVEX JSON: %s", stdout.String())
			}
		})
	}
}

func TestRunDefaults(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	testdata := filepath.Join(workingDirectory, "testdata")
	fixture := filepath.Join(testdata, "missing-module", "app")
	if err := os.Chdir(fixture); err != nil {
		t.Fatalf("change to fixture directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"--advisory", filepath.Join(testdata, "missing-module", "advisory.json")}, &stdout, &stderr); err != nil {
		t.Fatalf("run() with default source and package: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"@context": "https://openvex.dev/ns/v0.2.0"`)) {
		t.Fatalf("stdout is not OpenVEX JSON: %s", stdout.String())
	}
}

func TestRunRequiresAdvisory(t *testing.T) {
	if err := Run(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || err.Error() != "--advisory is required" {
		t.Fatalf("run() error = %v, want required advisory error", err)
	}
}

func TestRunRemoteAdvisory(t *testing.T) {
	fixture := filepath.Join("testdata", "missing-module")
	adv := &advisory.Advisory{
		ID: "GO-2025-4155",
		Affected: []advisory.Affected{{
			Module: "example.com/missing",
		}},
	}
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), Dependencies{Advisories: testAdvisoryLoader{advisory: adv}}, []string{
		"--source", filepath.Join(fixture, "app"),
		"--advisory", "GO-2025-4155",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"@context": "https://openvex.dev/ns/v0.2.0"`)) {
		t.Fatalf("stdout is not OpenVEX JSON: %s", stdout.String())
	}
}

func TestRunAdvisoryLoadError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), Dependencies{Advisories: testAdvisoryLoader{err: errors.New("load failed")}}, []string{
		"--advisory", "GO-2025-4155",
	}, &stdout, &stderr)
	if err == nil || err.Error() != "load failed" {
		t.Fatalf("run() error = %v, want load error", err)
	}
}
