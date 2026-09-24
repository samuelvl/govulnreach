package analyze

import (
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
)

func analysisEnvironment(source string) ([]string, error) {
	return environmentForSource(source, os.Environ())
}

func environmentForSource(source string, environment []string) ([]string, error) {
	if _, found := environmentValue(environment, "GOTOOLCHAIN"); found {
		return environment, nil
	}
	goVersion, err := sourceGoVersion(source, environment)
	if err != nil {
		return nil, err
	}
	if goVersion == "" {
		return environment, nil
	}
	toolchain, err := toolchainForGoVersion(goVersion)
	if err != nil {
		return nil, err
	}
	return append(environment, "GOTOOLCHAIN="+toolchain+"+auto"), nil
}

func sourceGoVersion(source string, environment []string) (string, error) {
	source, err := filepath.Abs(source)
	if err != nil {
		return "", fmt.Errorf("resolve source for Go toolchain: %w", err)
	}

	goWork, goWorkSet := environmentValue(environment, "GOWORK")
	switch {
	case goWorkSet && goWork == "off":
	case goWorkSet && goWork != "" && goWork != "auto":
		return goVersionFromWorkFile(goWork)
	default:
		if path := findParentFile(source, "go.work"); path != "" {
			return goVersionFromWorkFile(path)
		}
	}

	if path := findParentFile(source, "go.mod"); path != "" {
		return goVersionFromModFile(path)
	}
	return "", nil
}

func findParentFile(directory, name string) string {
	for {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return ""
		}
		directory = parent
	}
}

func goVersionFromWorkFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Go workspace %q: %w", path, err)
	}
	file, err := modfile.ParseWork(path, data, nil)
	if err != nil {
		return "", fmt.Errorf("parse Go workspace %q: %w", path, err)
	}
	if file.Go == nil {
		return "", nil
	}
	return file.Go.Version, nil
}

func goVersionFromModFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Go module %q: %w", path, err)
	}
	file, err := modfile.Parse(path, data, nil)
	if err != nil {
		return "", fmt.Errorf("parse Go module %q: %w", path, err)
	}
	if file.Go == nil {
		return "", nil
	}
	return file.Go.Version, nil
}

func toolchainForGoVersion(goVersion string) (string, error) {
	toolchain := "go" + strings.TrimPrefix(goVersion, "go")
	if !version.IsValid(toolchain) {
		return "", fmt.Errorf("Go module declares invalid Go version %q", goVersion)
	}

	parts := strings.Split(strings.TrimPrefix(toolchain, "go"), ".")
	if len(parts) == 2 {
		minor, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", fmt.Errorf("Go module declares invalid Go version %q", goVersion)
		}
		if minor >= 21 {
			toolchain += ".0"
		}
	}
	return toolchain, nil
}

func environmentValue(environment []string, name string) (string, bool) {
	prefix := name + "="
	for i := len(environment) - 1; i >= 0; i-- {
		if strings.HasPrefix(environment[i], prefix) {
			return strings.TrimPrefix(environment[i], prefix), true
		}
	}
	return "", false
}
