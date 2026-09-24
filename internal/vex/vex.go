package vex

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/samuelvl/govulnreach/internal/advisory"
	"github.com/samuelvl/govulnreach/internal/analyze"
)

const context = "https://openvex.dev/ns/v0.2.0"

type document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []statement `json:"statements"`
}

type statement struct {
	Vulnerability   vulnerability `json:"vulnerability"`
	Products        []product     `json:"products"`
	Status          string        `json:"status"`
	StatusNotes     string        `json:"status_notes,omitempty"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

type vulnerability struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

type product struct {
	ID            string         `json:"@id"`
	Identifiers   identifiers    `json:"identifiers"`
	Subcomponents []subcomponent `json:"subcomponents,omitempty"`
}

type subcomponent struct {
	ID          string      `json:"@id"`
	Identifiers identifiers `json:"identifiers"`
}

type identifiers struct {
	PURL string `json:"purl"`
}

func Encode(writer io.Writer, adv *advisory.Advisory, result *analyze.Result) error {
	doc := newDocument(adv, result)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("encode OpenVEX: %w", err)
	}
	return nil
}

func newDocument(adv *advisory.Advisory, result *analyze.Result) document {
	aliases := slices.Clone(adv.Aliases)
	slices.Sort(aliases)
	aliases = slices.Compact(aliases)
	notes := statusNotes(result)
	stmt := statement{
		Vulnerability: vulnerability{Name: adv.ID, Description: adv.Summary, Aliases: aliases},
		Products:      []product{openVEXProduct(result)},
		Status:        result.Status,
		StatusNotes:   notes,
	}
	switch result.Status {
	case "affected":
		stmt.ActionStatement = "Update or otherwise remediate the affected dependency."
	case "not_affected":
		stmt.Justification = openVEXJustification(result.Justification)
		if stmt.Justification == "" {
			stmt.ImpactStatement = notes
		}
	}
	return document{
		Context: context,
		ID:      "https://github.com/samuelvl/govulnreach/vex/" + strings.ToLower(rand.Text()),
		Author:  "govulnreach", Role: "Automated vulnerability reachability analysis",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Version: 1, Tooling: "govulnreach",
		Statements: []statement{stmt},
	}
}

func openVEXProduct(result *analyze.Result) product {
	purl := goPURL(result.Product.Name, result.Product.Version)
	seen := make(map[string]bool)
	components := make([]subcomponent, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.Version == "" {
			continue
		}
		dependencyPURL := goPURL(finding.Module, finding.Version)
		if dependencyPURL == purl || seen[dependencyPURL] {
			continue
		}
		seen[dependencyPURL] = true
		components = append(components, subcomponent{
			ID: dependencyPURL, Identifiers: identifiers{PURL: dependencyPURL},
		})
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })
	return product{ID: purl, Identifiers: identifiers{PURL: purl}, Subcomponents: components}
}

func statusNotes(result *analyze.Result) string {
	lines := []string{
		"Analysis level: " + analysisLevel(result.Findings) + ".",
		"Reachability: " + result.Reachability + ".",
	}
	details := make(map[string]bool)
	dependencyPaths := make(map[string]bool)
	callPaths := make(map[string]bool)
	for _, finding := range result.Findings {
		if finding.Detail != "" {
			name := finding.Module
			if finding.Package != "" {
				name = finding.Package
			}
			if finding.Symbol != "" {
				name += "." + finding.Symbol
			}
			details[name+": "+finding.Detail] = true
		}
		if len(finding.DependencyPath) > 0 {
			dependencyPaths[strings.Join(finding.DependencyPath, " -> ")] = true
		}
		if len(finding.CallPath) > 0 {
			callPaths[strings.Join(finding.CallPath, " -> ")] = true
		}
	}
	for _, detail := range sortedKeys(details) {
		lines = append(lines, detail+".")
	}
	for _, path := range sortedKeys(dependencyPaths) {
		lines = append(lines, "Dependency path: "+path+".")
	}
	for _, path := range sortedKeys(callPaths) {
		lines = append(lines, "Call path: "+path+".")
	}
	return strings.Join(lines, "\n")
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func analysisLevel(findings []analyze.Finding) string {
	level := "module"
	for _, finding := range findings {
		if finding.Level == "symbol" {
			return "symbol"
		}
		if finding.Level == "package" {
			level = "package"
		}
	}
	return level
}

func openVEXJustification(value string) string {
	switch value {
	case "code_not_present":
		return "component_not_present"
	case "code_not_reachable":
		return "vulnerable_code_not_in_execute_path"
	default:
		return ""
	}
}

func goPURL(name, version string) string {
	if version == "" {
		return "pkg:golang/" + name
	}
	return "pkg:golang/" + name + "@" + version
}
