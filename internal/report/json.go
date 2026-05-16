package report

import (
	"encoding/json"
	"io"

	"github.com/rbuilta/fipscan/internal/findings"
)

type JSONReport struct {
	Tool     string             `json:"tool"`
	Version  string             `json:"version"`
	Summary  map[string]int     `json:"summary"`
	Findings []findings.Finding `json:"findings"`
}

func RenderJSON(w io.Writer, results []findings.Finding, version string) error {
	summary := map[string]int{
		"total":  len(results),
		"high":   0,
		"medium": 0,
		"low":    0,
	}
	for _, f := range results {
		switch f.Severity {
		case findings.SeverityHigh:
			summary["high"]++
		case findings.SeverityMedium:
			summary["medium"]++
		case findings.SeverityLow:
			summary["low"]++
		}
	}
	if results == nil {
		results = []findings.Finding{}
	}
	report := JSONReport{
		Tool:     "fipscan",
		Version:  version,
		Summary:  summary,
		Findings: results,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
