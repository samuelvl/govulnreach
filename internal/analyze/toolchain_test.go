package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvironmentForSource(t *testing.T) {
	tests := []struct {
		name        string
		goVersion   string
		environment []string
		want        string
	}{
		{name: "patch version", goVersion: "1.21.8", want: "go1.21.8+auto"},
		{name: "Go 1.21 language version", goVersion: "1.21", want: "go1.21.0+auto"},
		{name: "old language version", goVersion: "1.20", want: "go1.20+auto"},
		{name: "explicit toolchain", goVersion: "1.21.8", environment: []string{"GOTOOLCHAIN=local"}, want: "local"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestFile(t, filepath.Join(directory, "go.mod"), "module example.com/test\n\ngo "+test.goVersion+"\n")
			environment, err := environmentForSource(directory, test.environment)
			if err != nil {
				t.Fatalf("environmentForSource() error = %v", err)
			}
			got, found := environmentValue(environment, "GOTOOLCHAIN")
			if !found || got != test.want {
				t.Fatalf("GOTOOLCHAIN = %q, %t; want %q, true", got, found, test.want)
			}
		})
	}
}

func TestEnvironmentForSourceWorkspace(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "module")
	if err := os.Mkdir(module, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.work"), "go 1.22.4\n")
	writeTestFile(t, filepath.Join(module, "go.mod"), "module example.com/test\n\ngo 1.21.8\n")

	environment, err := environmentForSource(module, nil)
	if err != nil {
		t.Fatalf("environmentForSource() error = %v", err)
	}
	if got, _ := environmentValue(environment, "GOTOOLCHAIN"); got != "go1.22.4+auto" {
		t.Fatalf("GOTOOLCHAIN = %q, want %q", got, "go1.22.4+auto")
	}

	environment, err = environmentForSource(module, []string{"GOWORK=off"})
	if err != nil {
		t.Fatalf("environmentForSource() with GOWORK=off error = %v", err)
	}
	if got, _ := environmentValue(environment, "GOTOOLCHAIN"); got != "go1.21.8+auto" {
		t.Fatalf("GOTOOLCHAIN with GOWORK=off = %q, want %q", got, "go1.21.8+auto")
	}
}

func TestEnvironmentForSourceWithoutVersion(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "go.mod"), "module example.com/test\n")
	environment := []string{"PATH=/bin"}

	got, err := environmentForSource(directory, environment)
	if err != nil {
		t.Fatalf("environmentForSource() error = %v", err)
	}
	if strings.Join(got, "\x00") != strings.Join(environment, "\x00") {
		t.Fatalf("environmentForSource() = %v, want %v", got, environment)
	}
}

func TestEnvironmentForSourceRejectsInvalidModule(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "go.mod"), "module example.com/test\n\ngo invalid\n")

	_, err := environmentForSource(directory, nil)
	if err == nil || !strings.Contains(err.Error(), "parse Go module") {
		t.Fatalf("environmentForSource() error = %v, want module parse error", err)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
