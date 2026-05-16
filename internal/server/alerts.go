package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rbuilta/fipscan/internal/audit"
	"github.com/rbuilta/fipscan/internal/findings"
)

// Alert payload sent to each AlertDestination. The "text" field is
// formatted as a one-liner so Slack and Microsoft Teams incoming
// webhooks render it sensibly out of the box; the full structured detail
// is also present for generic receivers (Discord, PagerDuty Events v2
// callers, internal webhooks, etc.).
type AlertPayload struct {
	AlertType        string             `json:"alert_type"` // "initial_findings" | "new_findings"
	Text             string             `json:"text"`       // Slack/Teams compatibility
	Target           Target             `json:"target"`
	ScanID           string             `json:"scan_id"`
	ScanURL          string             `json:"scan_url,omitempty"`
	NewFindings      []findings.Finding `json:"new_findings"`
	NewFindingsCount int                `json:"new_findings_count"`
	Summary          ScanSummary        `json:"summary"`
	GeneratedAt      time.Time          `json:"generated_at"`
}

// alertLogger is a single shared logger so dispatch lines line up with
// the other server / scheduler messages on stderr.
var alertLogger = log.New(os.Stderr, "[alerts] ", log.LstdFlags)

// dispatchAlerts compares the just-finished scan against the previous
// scan for the target, decides which destinations meet the severity
// threshold, and POSTs the payload to each in parallel (fire-and-forget).
//
// If prevScanID is empty (first scan ever for this target), every
// finding is treated as new — operators usually want to know on the
// first scan after adding a target, not just on regressions.
//
// publicURL, when non-empty, is prefixed to the per-scan URL embedded in
// the payload so receivers can click through to the scan-detail page.
func dispatchAlerts(store *Store, target Target, rec ScanRecord, prevScanID, publicURL string, auditor *audit.Logger) {
	if rec.Error != "" || len(rec.Findings) == 0 {
		return
	}
	dests, err := store.ListAlerts()
	if err != nil || len(dests) == 0 {
		return
	}

	var (
		newOnes []findings.Finding
		alertType = "new_findings"
	)
	if prevScanID == "" {
		newOnes = rec.Findings
		alertType = "initial_findings"
	} else {
		prev, ok, _ := store.GetScan(prevScanID)
		if ok {
			newOnes = diffFindings(rec.Findings, prev.Findings)
		} else {
			newOnes = rec.Findings
			alertType = "initial_findings"
		}
	}
	if len(newOnes) == 0 {
		return
	}

	scanURL := ""
	if publicURL != "" {
		scanURL = strings.TrimRight(publicURL, "/") + "/scans/" + rec.ID
	}

	for _, d := range dests {
		filtered := filterBySeverity(newOnes, d.MinSeverity)
		if len(filtered) == 0 {
			continue
		}
		payload := AlertPayload{
			AlertType:        alertType,
			Text:             summaryText(target, rec, filtered, alertType),
			Target:           target,
			ScanID:           rec.ID,
			ScanURL:          scanURL,
			NewFindings:      filtered,
			NewFindingsCount: len(filtered),
			Summary:          rec.Summary,
			GeneratedAt:      time.Now().UTC(),
		}
		go postAlert(d, payload, auditor)
	}
}

func postAlert(d AlertDestination, payload AlertPayload, auditor *audit.Logger) {
	body, err := json.Marshal(payload)
	if err != nil {
		alertLogger.Printf("marshal payload for %s: %v", d.Name, err)
		if auditor != nil {
			auditor.Emit(audit.AlertDeliveryFailed(d.ID, d.Name, payload.ScanID, "marshal: "+err.Error()))
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		alertLogger.Printf("build request for %s: %v", d.Name, err)
		if auditor != nil {
			auditor.Emit(audit.AlertDeliveryFailed(d.ID, d.Name, payload.ScanID, err.Error()))
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fipscan/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		alertLogger.Printf("POST %s: %v", d.Name, err)
		if auditor != nil {
			auditor.Emit(audit.AlertDeliveryFailed(d.ID, d.Name, payload.ScanID, err.Error()))
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		alertLogger.Printf("POST %s: HTTP %d", d.Name, resp.StatusCode)
		if auditor != nil {
			auditor.Emit(audit.AlertDeliveryFailed(d.ID, d.Name, payload.ScanID,
				fmt.Sprintf("HTTP %d", resp.StatusCode)))
		}
		return
	}
	alertLogger.Printf("delivered to %s (%d new findings, scan %s)",
		d.Name, payload.NewFindingsCount, payload.ScanID[:8])
	if auditor != nil {
		auditor.Emit(audit.AlertDelivered(d.ID, d.Name, payload.ScanID, payload.NewFindingsCount))
	}
}

// diffFindings returns findings in current that aren't present in
// previous, keyed by (rule + algorithm + file). Line numbers are
// deliberately excluded from the key so a recompile / line-shift in
// source code doesn't generate noisy re-alerts.
func diffFindings(current, previous []findings.Finding) []findings.Finding {
	prev := make(map[string]struct{}, len(previous))
	for _, f := range previous {
		prev[findingKey(f)] = struct{}{}
	}
	out := make([]findings.Finding, 0)
	for _, f := range current {
		if _, ok := prev[findingKey(f)]; !ok {
			out = append(out, f)
		}
	}
	return out
}

func findingKey(f findings.Finding) string {
	return f.Rule + "|" + f.Algorithm + "|" + f.File
}

var sevRank = map[findings.Severity]int{
	findings.SeverityHigh:   3,
	findings.SeverityMedium: 2,
	findings.SeverityLow:    1,
}

func filterBySeverity(fs []findings.Finding, minSev string) []findings.Finding {
	thresh, ok := sevRank[findings.Severity(strings.ToUpper(minSev))]
	if !ok {
		thresh = sevRank[findings.SeverityHigh]
	}
	out := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		if sevRank[f.Severity] >= thresh {
			out = append(out, f)
		}
	}
	return out
}

// testPayload is the synthetic payload sent by the "Test" button so
// operators can verify their Slack / Teams / webhook configuration
// without waiting for a real diff.
func testPayload() AlertPayload {
	now := time.Now().UTC()
	f := findings.Finding{
		File:        "testdata/example.go",
		Line:        42,
		Algorithm:   "MD5",
		Language:    "Go",
		Severity:    findings.SeverityHigh,
		Snippet:     `md5.Sum(data)`,
		Rule:        "FIPS-HASH-001",
		Remediation: "Replace crypto/md5 with crypto/sha256.",
		Reference:   "FIPS 180-4",
	}
	return AlertPayload{
		AlertType:        "test",
		Text:             "fipscan: test alert — MD5 (FIPS-HASH-001) at testdata/example.go:42",
		Target:           Target{ID: "test-target", Type: TargetRepo, Value: "example/repo"},
		ScanID:           "test-scan",
		ScanURL:          "",
		NewFindings:      []findings.Finding{f},
		NewFindingsCount: 1,
		Summary:          ScanSummary{Total: 1, High: 1},
		GeneratedAt:      now,
	}
}

// summaryText renders the one-line message used by Slack/Teams.
func summaryText(t Target, rec ScanRecord, fs []findings.Finding, alertType string) string {
	verb := "new"
	if alertType == "initial_findings" {
		verb = "initial"
	}
	highest := ""
	for _, f := range fs {
		if f.Severity == findings.SeverityHigh {
			highest = "HIGH"
			break
		}
		if f.Severity == findings.SeverityMedium && highest == "" {
			highest = "MEDIUM"
		}
	}
	if highest == "" {
		highest = "LOW"
	}
	return fmt.Sprintf("fipscan: %d %s %s finding(s) on %s (%s) — top: %s [%s]",
		len(fs), verb, highest, t.Value, t.Type,
		fs[0].Algorithm, fs[0].Rule)
}
