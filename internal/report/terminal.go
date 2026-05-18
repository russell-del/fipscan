package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/rbuilta/fipscan/internal/findings"
)

func RenderTerminal(w io.Writer, results []findings.Finding) {
	if len(results) == 0 {
		fmt.Fprintln(w, "FIPS 140-3 Readiness Scan — no findings.")
		return
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Severity != results[j].Severity {
			return sevWeight(results[i].Severity) > sevWeight(results[j].Severity)
		}
		if results[i].File != results[j].File {
			return results[i].File < results[j].File
		}
		return results[i].Line < results[j].Line
	})

	bySev := map[findings.Severity]int{}
	for _, f := range results {
		bySev[f.Severity]++
	}

	fmt.Fprintf(w, "FIPS 140-3 Readiness Scan — %d finding(s)\n", len(results))
	fmt.Fprintf(w, "  HIGH: %d   MEDIUM: %d   LOW: %d\n\n",
		bySev[findings.SeverityHigh],
		bySev[findings.SeverityMedium],
		bySev[findings.SeverityLow],
	)

	for _, f := range results {
		fmt.Fprintf(w, "[%s] %s — %s\n", f.Severity, f.Algorithm, f.Rule)
		fmt.Fprintf(w, "  %s:%d  (%s)\n", f.File, f.Line, f.Language)
		fmt.Fprintf(w, "    %s\n", f.Snippet)
		fmt.Fprintf(w, "    -> %s\n", f.Remediation)
		if f.Reference != "" {
			fmt.Fprintf(w, "    ref: %s\n", f.Reference)
		}
		fmt.Fprintln(w)
	}
}

// RenderResolved emits a "resolved since baseline" section to w.
// Designed to be called *after* RenderTerminal of the new-findings
// list when -show-resolved is on. Compact one-liner per entry —
// resolved findings are good news, not action items.
func RenderResolved(w io.Writer, resolved []findings.Finding) {
	if len(resolved) == 0 {
		fmt.Fprintln(w, "Resolved since baseline: none.")
		return
	}
	bySev := map[findings.Severity]int{}
	for _, f := range resolved {
		bySev[f.Severity]++
	}
	fmt.Fprintf(w, "Resolved since baseline — %d finding(s)\n", len(resolved))
	fmt.Fprintf(w, "  HIGH: %d   MEDIUM: %d   LOW: %d\n\n",
		bySev[findings.SeverityHigh],
		bySev[findings.SeverityMedium],
		bySev[findings.SeverityLow],
	)
	for _, f := range resolved {
		fmt.Fprintf(w, "  ✓ [%s] %s  (was %s:%d, %s)\n",
			f.Severity, f.Algorithm, f.File, f.Line, f.Rule)
	}
	fmt.Fprintln(w)
}

func sevWeight(s findings.Severity) int {
	switch s {
	case findings.SeverityHigh:
		return 3
	case findings.SeverityMedium:
		return 2
	case findings.SeverityLow:
		return 1
	}
	return 0
}
