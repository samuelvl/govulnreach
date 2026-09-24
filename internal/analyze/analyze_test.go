package analyze

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/samuelvl/govulnreach/internal/advisory"
)

func TestRunStdlib(t *testing.T) {
	result, err := Run(Options{Source: "testdata/stdlib", Package: "."}, &advisory.Advisory{
		ID: "GO-TEST-STDLIB",
		Affected: []advisory.Affected{{
			Module: "stdlib",
			Imports: []advisory.Import{{
				Path:    "crypto/x509",
				Symbols: []string{"Certificate.VerifyHostname"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "affected" || result.Reachability != "reachable" {
		t.Fatalf("status = %q, reachability = %q, want affected and reachable", result.Status, result.Reachability)
	}
	if len(result.Findings) != 1 || len(result.Findings[0].CallPath) == 0 {
		t.Fatalf("findings = %#v, want one reachable call path", result.Findings)
	}
	for _, dependency := range result.Dependencies {
		if dependency.Module == "stdlib" && strings.HasPrefix(dependency.Version, "v1.") {
			return
		}
	}
	t.Fatalf("dependencies = %#v, want versioned stdlib", result.Dependencies)
}

func TestModuleVersionReplacement(t *testing.T) {
	tests := []struct {
		name string
		give *packages.Module
		want string
	}{
		{
			name: "nil module has unknown version",
		},
		{
			name: "original module uses required version",
			give: &packages.Module{Path: "example.com/module", Version: "v0.25.5"},
			want: "v0.25.5",
		},
		{
			name: "local replacement has unknown version",
			give: &packages.Module{
				Path:    "example.com/module",
				Version: "v0.25.5",
				Replace: &packages.Module{Path: "/local/module", Dir: "/local/module"},
			},
		},
		{
			name: "versioned fork has unknown version",
			give: &packages.Module{
				Path:    "example.com/module",
				Version: "v0.25.5",
				Replace: &packages.Module{Path: "example.com/fork", Version: "v0.26.0"},
			},
		},
		{
			name: "same-path replacement uses replacement version",
			give: &packages.Module{
				Path:    "example.com/module",
				Version: "v0.25.5",
				Replace: &packages.Module{Path: "example.com/module", Version: "v0.26.0"},
			},
			want: "v0.26.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleVersion(tt.give); got != tt.want {
				t.Fatalf("moduleVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShortestPathSkipsMissingPackageMetadata(t *testing.T) {
	root := &packages.Package{PkgPath: "example.com/main"}
	meta := &metadata{
		root: root,
		packages: map[string]*packageInfo{
			root.PkgPath: {pkg: root, imports: []string{"example.com/missing"}},
		},
	}
	if got := shortestPath(meta, "example.com/target"); got != nil {
		t.Fatalf("shortestPath() = %v, want nil", got)
	}
}

func TestBuildSSACreatesVendoredImports(t *testing.T) {
	const root = "example.com/reachability/cmd/httputil"
	program, err := buildSSA("testdata/reachability", map[string]bool{
		root:                true,
		"net/http/httputil": true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entryFunctions(program, root); err != nil {
		t.Fatal(err)
	}
}

func TestSliceCandidates(t *testing.T) {
	const targetPackage = "github.com/go-openapi/swag/jsonutils"
	tests := []struct {
		name        string
		mainPackage string
		packagePath string
		want        bool
	}{
		{name: "reachable wrapper", mainPackage: "./cmd/wrapper", packagePath: "example.com/reachability/wrapper", want: true},
		{name: "dead wrapper", mainPackage: "./cmd/dead-package", packagePath: "example.com/reachability/deadwrapper", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := filepath.Clean("testdata/reachability")
			meta, err := loadMetadata(Options{Source: source, Package: tt.mainPackage})
			if err != nil {
				t.Fatal(err)
			}
			targetPackages := map[string]bool{targetPackage: true}
			candidates, _, err := sliceCandidates(source, nil, meta, candidatePackages(meta, targetPackages), []symbolTarget{{
				packagePath: targetPackage,
				symbol:      "WriteJSON",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if candidates[tt.packagePath] != tt.want {
				t.Fatalf("candidate %s = %t, want %t", tt.packagePath, candidates[tt.packagePath], tt.want)
			}
		})
	}
}

func TestStoredCallbackSummary(t *testing.T) {
	const targetPackage = "github.com/go-openapi/swag/jsonutils"
	source := filepath.Clean("testdata/reachability")
	meta, err := loadMetadata(Options{Source: source, Package: "./cmd/stored-callback"})
	if err != nil {
		t.Fatal(err)
	}
	targetPackages := map[string]bool{targetPackage: true}
	_, callbacks, err := sliceCandidates(source, nil, meta, candidatePackages(meta, targetPackages), []symbolTarget{{
		packagePath: targetPackage,
		symbol:      "WriteJSON",
	}})
	if err != nil {
		t.Fatal(err)
	}
	const runField = "example.com/reachability/callbackstore\x00Command\x00Run"
	if !callbacks.invokedFields[runField] {
		t.Fatalf("invoked fields = %#v, want %q", callbacks.invokedFields, runField)
	}
}

func TestCallbackParameterSummary(t *testing.T) {
	const targetPackage = "github.com/go-openapi/swag/jsonutils"
	source := filepath.Clean("testdata/reachability")
	meta, err := loadMetadata(Options{Source: source, Package: "./cmd/callback"})
	if err != nil {
		t.Fatal(err)
	}
	targetPackages := map[string]bool{targetPackage: true}
	_, callbacks, err := sliceCandidates(source, nil, meta, candidatePackages(meta, targetPackages), []symbolTarget{{
		packagePath: targetPackage,
		symbol:      "WriteJSON",
	}})
	if err != nil {
		t.Fatal(err)
	}
	const runFunction = "example.com/reachability/callbackhelper.Run"
	if !callbacks.invokedParams[runFunction][0] {
		t.Fatalf("invoked parameters = %#v, want parameter 0 of %q", callbacks.invokedParams, runFunction)
	}
}
