package findings

type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

type Finding struct {
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column,omitempty"`
	Algorithm   string   `json:"algorithm"`
	Language    string   `json:"language"`
	Severity    Severity `json:"severity"`
	Snippet     string   `json:"snippet"`
	Rule        string   `json:"rule"`
	Remediation string   `json:"remediation"`
	Reference   string   `json:"reference,omitempty"`
}
