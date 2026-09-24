package advisory

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

type Advisory struct {
	ID         string
	Aliases    []string
	Summary    string
	Details    string
	Source     string
	References []Reference
	Affected   []Affected
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Module  string
	Ranges  []Range
	Imports []Import
}

type Range struct {
	Events []Event
}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

type osvAdvisory struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Affected         []osvAffected  `json:"affected"`
	References       []Reference    `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type             string  `json:"type"`
		Repo             string  `json:"repo"`
		Events           []Event `json:"events"`
		DatabaseSpecific struct {
			ExtractedEvents []Event `json:"extracted_events"`
		} `json:"database_specific"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Imports []Import `json:"imports"`
	} `json:"ecosystem_specific"`
}

func Parse(format string, data []byte) (*Advisory, error) {
	switch format {
	case "osv":
		return parseOSV(data)
	default:
		return nil, fmt.Errorf("unsupported advisory format %q", format)
	}
}

func parseOSV(data []byte) (*Advisory, error) {
	var raw osvAdvisory
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode OSV advisory: %w", err)
	}
	if strings.TrimSpace(raw.ID) == "" {
		return nil, errors.New("OSV advisory ID is required")
	}
	if len(raw.Affected) == 0 {
		return nil, errors.New("OSV advisory must contain at least one affected module")
	}

	result := &Advisory{
		ID:         raw.ID,
		Aliases:    raw.Aliases,
		Summary:    raw.Summary,
		Details:    raw.Details,
		References: raw.References,
		Affected:   make([]Affected, 0, len(raw.Affected)),
	}
	if source, ok := raw.DatabaseSpecific["source"].(string); ok {
		result.Source = source
	}
	for i, item := range raw.Affected {
		if item.Package.Ecosystem != "" && item.Package.Ecosystem != "Go" && item.Package.Ecosystem != "Git" {
			return nil, fmt.Errorf("affected[%d]: unsupported ecosystem %q", i, item.Package.Ecosystem)
		}
		module := item.Package.Name
		if module == "" && len(item.Ranges) > 0 && item.Ranges[0].Repo != "" {
			module = gitRepoModule(item.Ranges[0].Repo)
		}
		if strings.TrimSpace(module) == "" {
			return nil, fmt.Errorf("affected[%d]: module name is required", i)
		}
		affected := Affected{Module: module, Imports: item.EcosystemSpecific.Imports}
		for j, rawRange := range item.Ranges {
			if rawRange.Type != "SEMVER" && rawRange.Type != "GIT" {
				return nil, fmt.Errorf("affected[%d].ranges[%d]: unsupported range type %q", i, j, rawRange.Type)
			}
			events := rawRange.Events
			if rawRange.Type == "GIT" && len(rawRange.DatabaseSpecific.ExtractedEvents) > 0 {
				events = rawRange.DatabaseSpecific.ExtractedEvents
			}
			if len(events) == 0 {
				return nil, fmt.Errorf("affected[%d].ranges[%d]: events are required", i, j)
			}
			for k, event := range events {
				if err := validateEvent(event); err != nil {
					return nil, fmt.Errorf("affected[%d].ranges[%d].events[%d]: %w", i, j, k, err)
				}
			}
			if err := validateEventOrder(events); err != nil {
				return nil, fmt.Errorf("affected[%d].ranges[%d]: %w", i, j, err)
			}
			affected.Ranges = append(affected.Ranges, Range{Events: events})
		}
		for j, imp := range affected.Imports {
			if strings.TrimSpace(imp.Path) == "" {
				return nil, fmt.Errorf("affected[%d].imports[%d]: package path is required", i, j)
			}
			for k, symbol := range imp.Symbols {
				if strings.TrimSpace(symbol) == "" {
					return nil, fmt.Errorf("affected[%d].imports[%d].symbols[%d]: symbol is required", i, j, k)
				}
			}
		}
		result.Affected = append(result.Affected, affected)
	}
	return result, nil
}

func gitRepoModule(repo string) string {
	repo = strings.TrimSuffix(strings.TrimSpace(repo), ".git")
	repo = strings.TrimPrefix(repo, "https://")
	repo = strings.TrimPrefix(repo, "http://")
	repo = strings.TrimPrefix(repo, "git@")
	repo = strings.TrimPrefix(repo, ":")
	return strings.TrimPrefix(repo, "//")
}

func validateEventOrder(events []Event) error {
	active := false
	for i, event := range events {
		switch {
		case event.Introduced != "":
			if active {
				return fmt.Errorf("events[%d]: introduced event requires the previous interval to end", i)
			}
			active = true
		case event.Fixed != "" || event.LastAffected != "":
			if !active {
				return fmt.Errorf("events[%d]: range endpoint requires an introduced event", i)
			}
			active = false
		}
	}
	return nil
}

func validateEvent(event Event) error {
	values := 0
	for _, value := range []string{event.Introduced, event.Fixed, event.LastAffected} {
		if value != "" {
			values++
		}
	}
	if values != 1 {
		return errors.New("exactly one of introduced, fixed, or last_affected is required")
	}
	if event.Introduced == "0" {
		return nil
	}
	for _, value := range []string{event.Introduced, event.Fixed, event.LastAffected} {
		if value != "" && !semver.IsValid(normalizeVersion(value)) {
			return fmt.Errorf("invalid semantic version %q", value)
		}
	}
	return nil
}

func (a Affected) ContainsVersion(version string) (bool, error) {
	version = normalizeVersion(version)
	if !semver.IsValid(version) {
		return false, fmt.Errorf("invalid module version %q", version)
	}
	if len(a.Ranges) == 0 {
		return true, nil
	}
	for _, versionRange := range a.Ranges {
		active := false
		start := "v0.0.0"
		for _, event := range versionRange.Events {
			switch {
			case event.Introduced != "":
				active = true
				start = normalizeVersion(event.Introduced)
			case event.Fixed != "":
				if active && semver.Compare(version, start) >= 0 && semver.Compare(version, normalizeVersion(event.Fixed)) < 0 {
					return true, nil
				}
				active = false
			case event.LastAffected != "":
				if active && semver.Compare(version, start) >= 0 && semver.Compare(version, normalizeVersion(event.LastAffected)) <= 0 {
					return true, nil
				}
				active = false
			}
		}
		if active && semver.Compare(version, start) >= 0 {
			return true, nil
		}
	}
	return false, nil
}

func normalizeVersion(version string) string {
	if version == "0" {
		return "v0.0.0"
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}
