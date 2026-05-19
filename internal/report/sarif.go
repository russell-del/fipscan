package report

import (
	"encoding/json"
	"io"

	"github.com/russell-del/fipscan/internal/findings"
)

// SARIF 2.1.0 renderer. Output is consumable by GitHub Code Scanning,
// Azure DevOps, and any other SARIF-aware viewer.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifMsg               `json:"shortDescription"`
	FullDescription      sarifMsg               `json:"fullDescription"`
	Help                 sarifMsg               `json:"help"`
	DefaultConfiguration sarifConfig            `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMsg        `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int       `json:"startLine"`
	StartColumn int       `json:"startColumn,omitempty"`
	Snippet     *sarifMsg `json:"snippet,omitempty"`
}

func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	case findings.SeverityLow:
		return "note"
	}
	return "none"
}

// rulesFromFindings derives the SARIF rules array from the set of unique
// rule IDs that fired. We keep findings as the single source of truth so
// the report package stays decoupled from the pattern catalog.
func rulesFromFindings(results []findings.Finding) []sarifRule {
	seen := map[string]bool{}
	var rules []sarifRule
	for _, f := range results {
		if seen[f.Rule] {
			continue
		}
		seen[f.Rule] = true
		rules = append(rules, sarifRule{
			ID:               f.Rule,
			Name:             f.Algorithm,
			ShortDescription: sarifMsg{Text: f.Algorithm + " is not FIPS 140-3 approved."},
			FullDescription:  sarifMsg{Text: f.Algorithm + " — " + f.Remediation},
			Help:             sarifMsg{Text: f.Remediation + " Reference: " + f.Reference + "."},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
			Properties: map[string]interface{}{
				"tags":      []string{"security", "fips140-3", "cryptography"},
				"reference": f.Reference,
			},
		})
	}
	return rules
}

func RenderSARIF(w io.Writer, results []findings.Finding, version string) error {
	sarifResults := make([]sarifResult, 0, len(results))
	for _, f := range results {
		sarifResults = append(sarifResults, sarifResult{
			RuleID:  f.Rule,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: f.Algorithm + ": " + f.Remediation},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region: sarifRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
						Snippet:     &sarifMsg{Text: f.Snippet},
					},
				},
			}},
		})
	}

	rules := rulesFromFindings(results)
	if rules == nil {
		rules = []sarifRule{}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "fipscan",
				Version:        version,
				InformationURI: "https://github.com/russell-del/fipscan",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
