package report

import (
	"encoding/json"
	"io"

	"github.com/russell-del/fipscan/internal/findings"
)

type JSONReport struct {
	Tool     string             `json:"tool"`
	Version  string             `json:"version"`
	Summary  map[string]int     `json:"summary"`
	Findings []findings.Finding `json:"findings"`
}

func RenderJSON(w io.Writer, results []findings.Finding, version string) error {
	if results == nil {
		results = []findings.Finding{}
	}
	report := JSONReport{
		Tool:     "fipscan",
		Version:  version,
		Summary:  summarise(results),
		Findings: results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// JSONDiffReport is the wire shape emitted when -show-resolved is on.
// The `Findings` field still carries the NEW findings (so existing
// scripts that look at .findings keep working) and `ResolvedFindings`
// is the additive list of things that disappeared since the baseline.
type JSONDiffReport struct {
	Tool             string             `json:"tool"`
	Version          string             `json:"version"`
	Mode             string             `json:"mode"`              // "diff"
	Summary          map[string]int     `json:"summary"`           // new-findings summary (existing shape)
	Findings         []findings.Finding `json:"findings"`          // new findings since baseline
	ResolvedSummary  map[string]int     `json:"resolved_summary"`  // counts for resolved
	ResolvedFindings []findings.Finding `json:"resolved_findings"` // baseline ∖ current
}

// RenderJSONDiff emits both the new findings and the resolved findings
// in a single document. Used when -show-resolved + -baseline are both
// set with -format json.
func RenderJSONDiff(w io.Writer, newFindings, resolved []findings.Finding, version string) error {
	if newFindings == nil {
		newFindings = []findings.Finding{}
	}
	if resolved == nil {
		resolved = []findings.Finding{}
	}
	report := JSONDiffReport{
		Tool:             "fipscan",
		Version:          version,
		Mode:             "diff",
		Summary:          summarise(newFindings),
		Findings:         newFindings,
		ResolvedSummary:  summarise(resolved),
		ResolvedFindings: resolved,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func summarise(fs []findings.Finding) map[string]int {
	s := map[string]int{
		"total":  len(fs),
		"high":   0,
		"medium": 0,
		"low":    0,
	}
	for _, f := range fs {
		switch f.Severity {
		case findings.SeverityHigh:
			s["high"]++
		case findings.SeverityMedium:
			s["medium"]++
		case findings.SeverityLow:
			s["low"]++
		}
	}
	return s
}
