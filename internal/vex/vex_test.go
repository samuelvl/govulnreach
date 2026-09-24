package vex_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/samuelvl/govulnreach/internal/advisory"
	"github.com/samuelvl/govulnreach/internal/analyze"
	"github.com/samuelvl/govulnreach/internal/vex"
)

type openVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID          string            `json:"@id"`
		Identifiers map[string]string `json:"identifiers"`
	} `json:"products"`
	Status          string `json:"status"`
	StatusNotes     string `json:"status_notes"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement"`
	ActionStatement string `json:"action_statement"`
}

type caseManifest struct {
	Description string          `json:"description"`
	Source      string          `json:"source"`
	Package     string          `json:"package"`
	Expected    caseExpectation `json:"expected"`
}

type caseExpectation struct {
	Status           string   `json:"status"`
	Reachability     string   `json:"reachability"`
	Justification    string   `json:"justification"`
	FindingLevel     string   `json:"finding_level"`
	FindingOutcome   string   `json:"finding_outcome"`
	CallPathContains []string `json:"call_path_contains"`
}

type behaviorCase struct {
	Path     string
	Manifest caseManifest
	Advisory string
}

func TestBehaviorFixtures(t *testing.T) {
	fixtures := discoverCases(t, filepath.Join("testdata", "cases"))
	for _, fixture := range fixtures {
		t.Run(fixture.Path, func(t *testing.T) {
			adv := readAdvisory(t, fixture.Advisory)
			source := filepath.Join(filepath.Dir(fixture.Advisory), fixture.Manifest.Source)
			result, err := analyze.Run(analyze.Options{
				Source: source, Package: fixture.Manifest.Package,
			}, adv)
			if err != nil {
				t.Fatalf("analyze %s: %v", fixture.Path, err)
			}
			assertAnalysis(t, fixture.Path, fixture.Manifest.Expected, result)
		})
	}
}

func discoverCases(t *testing.T, root string) []behaviorCase {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !entry.IsDir() && entry.Name() == "case.json" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("discover behavior cases: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("discover behavior cases: no case.json files under %s", root)
	}
	sort.Strings(paths)

	fixtures := make([]behaviorCase, 0, len(paths))
	for _, manifestPath := range paths {
		casePath := filepath.Dir(manifestPath)
		var manifest caseManifest
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatalf("case %s: read manifest: %v", casePath, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			t.Fatalf("case %s: parse manifest: %v", casePath, err)
		}
		if strings.TrimSpace(manifest.Description) == "" {
			t.Fatalf("case %s: description is required", casePath)
		}
		if manifest.Source == "" {
			manifest.Source = "."
		}
		if manifest.Package == "" {
			manifest.Package = "."
		}
		if manifest.Expected.Status == "" || manifest.Expected.Reachability == "" {
			t.Fatalf("case %s: expected status and reachability are required", casePath)
		}
		advisoryPath := filepath.Join(casePath, "advisory.json")
		if _, err := os.Stat(advisoryPath); err != nil {
			t.Fatalf("case %s: advisory.json is required: %v", casePath, err)
		}
		relative, err := filepath.Rel(root, casePath)
		if err != nil {
			t.Fatalf("case %s: calculate relative path: %v", casePath, err)
		}
		fixtures = append(fixtures, behaviorCase{
			Path: filepath.ToSlash(relative), Manifest: manifest, Advisory: advisoryPath,
		})
	}
	return fixtures
}

func assertAnalysis(t *testing.T, path string, want caseExpectation, result *analyze.Result) {
	t.Helper()
	if result.Status != want.Status || result.Reachability != want.Reachability {
		t.Fatalf("case %s: status/reachability = %q/%q, want %q/%q", path, result.Status, result.Reachability, want.Status, want.Reachability)
	}
	if result.Justification != want.Justification {
		t.Fatalf("case %s: justification = %q, want %q", path, result.Justification, want.Justification)
	}
	if want.FindingLevel == "" && want.FindingOutcome == "" && len(want.CallPathContains) == 0 {
		return
	}
	if len(result.Findings) == 0 {
		t.Fatalf("case %s: no findings", path)
	}
	finding := result.Findings[0]
	if want.FindingLevel != "" && finding.Level != want.FindingLevel {
		t.Fatalf("case %s: finding level = %q, want %q", path, finding.Level, want.FindingLevel)
	}
	if want.FindingOutcome != "" && finding.Outcome != want.FindingOutcome {
		t.Fatalf("case %s: finding outcome = %q, want %q", path, finding.Outcome, want.FindingOutcome)
	}
	callPath := strings.Join(finding.CallPath, " -> ")
	for _, fragment := range want.CallPathContains {
		if !strings.Contains(callPath, fragment) {
			t.Fatalf("case %s: call path %q does not contain %q", path, callPath, fragment)
		}
	}
}

func TestEncodeOpenVEX(t *testing.T) {
	adv := readAdvisoryJSON(t, `{"schema_version":"1.9.0","id":"GO-TEST-ENCODER","summary":"encoder test","affected":[{"package":{"ecosystem":"Go","name":"example.com/vulnerable"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
	tests := []struct {
		name       string
		result     *analyze.Result
		status     string
		just       string
		wantAction bool
	}{
		{
			name: "affected",
			result: &analyze.Result{
				Product: analyze.Product{Name: "example.com/app", Version: "v1.0.0"},
				Status:  "affected", Reachability: "reachable",
				Findings: []analyze.Finding{{
					Level: "module", Module: "example.com/vulnerable", Version: "v0.1.0",
					Outcome: "module", DependencyPath: []string{"example.com/app", "example.com/vulnerable"},
					CallPath: []string{"main.main", "example.com/vulnerable.Call"},
				}},
			},
			status: "affected", wantAction: true,
		},
		{
			name: "not affected",
			result: &analyze.Result{
				Product: analyze.Product{Name: "example.com/app", Version: "v1.0.0"},
				Status:  "not_affected", Reachability: "unreachable", Justification: "code_not_reachable",
			},
			status: "not_affected", just: "vulnerable_code_not_in_execute_path",
		},
		{
			name: "under investigation",
			result: &analyze.Result{
				Product: analyze.Product{Name: "example.com/app", Version: "v1.0.0"},
				Status:  "under_investigation", Reachability: "unknown",
			},
			status: "under_investigation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := vex.Encode(&output, adv, tt.result); err != nil {
				t.Fatalf("encode VEX: %v", err)
			}
			var doc openVEXDocument
			if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
				t.Fatalf("decode VEX: %v", err)
			}
			if doc.Context != "https://openvex.dev/ns/v0.2.0" || doc.ID == "" || doc.Author == "" || doc.Version != 1 {
				t.Fatalf("invalid OpenVEX metadata: %+v", doc)
			}
			if _, err := time.Parse(time.RFC3339Nano, doc.Timestamp); err != nil {
				t.Fatalf("timestamp %q is invalid: %v", doc.Timestamp, err)
			}
			if len(doc.Statements) != 1 || doc.Statements[0].Status != tt.status {
				t.Fatalf("unexpected statements: %+v", doc.Statements)
			}
			stmt := doc.Statements[0]
			if len(stmt.Products) != 1 || stmt.Products[0].ID == "" || stmt.Products[0].Identifiers["purl"] == "" {
				t.Fatalf("invalid product: %+v", stmt.Products)
			}
			if tt.just != "" && stmt.Justification != tt.just {
				t.Fatalf("justification = %q, want %q", stmt.Justification, tt.just)
			}
			if tt.wantAction && stmt.ActionStatement == "" {
				t.Fatal("affected statement has no action statement")
			}
			if tt.name == "affected" && !strings.Contains(stmt.StatusNotes, "Dependency path:") {
				t.Fatalf("status notes omit dependency path: %q", stmt.StatusNotes)
			}
		})
	}
}

func readAdvisory(t *testing.T, path string) *advisory.Advisory {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read advisory: %v", err)
	}
	return readAdvisoryJSON(t, string(data))
}

func readAdvisoryJSON(t *testing.T, value string) *advisory.Advisory {
	t.Helper()
	adv, err := advisory.Parse("osv", []byte(value))
	if err != nil {
		t.Fatalf("parse advisory: %v", err)
	}
	return adv
}
