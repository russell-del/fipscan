package report

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/rbuilta/fipscan/internal/findings"
)

// ANSI color codes used by the terminal renderer. Centralised so it's
// easy to tune the palette and audit what we emit.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiGreen  = "\x1b[32m"
	ansiCyan   = "\x1b[36m"
)

// colorScheme decides whether ANSI escapes are emitted. Off when:
//   - explicit -no-color flag (caller's choice)
//   - NO_COLOR env var present (https://no-color.org/)
//   - stdout isn't a TTY (piping to a file / SARIF / CI logs)
type colorScheme struct{ enabled bool }

// detectColor consults the flag, env, and TTY state and returns the
// resulting scheme. The flag overrides everything; otherwise NO_COLOR
// disables; otherwise we check the TTY.
func detectColor(noColor bool) colorScheme {
	if noColor {
		return colorScheme{}
	}
	if os.Getenv("NO_COLOR") != "" {
		return colorScheme{}
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return colorScheme{}
	}
	return colorScheme{enabled: (fi.Mode() & os.ModeCharDevice) != 0}
}

func (c colorScheme) wrap(escape, s string) string {
	if !c.enabled {
		return s
	}
	return escape + s + ansiReset
}

func (c colorScheme) sev(s findings.Severity) string {
	switch s {
	case findings.SeverityHigh:
		return c.wrap(ansiBold+ansiRed, string(s))
	case findings.SeverityMedium:
		return c.wrap(ansiBold+ansiYellow, string(s))
	case findings.SeverityLow:
		return c.wrap(ansiBlue, string(s))
	}
	return string(s)
}

// RenderTerminal writes a human-readable report to w. NoColor disables
// ANSI escapes regardless of TTY state; otherwise colors are emitted
// only when stdout is a TTY and NO_COLOR isn't set.
func RenderTerminal(w io.Writer, results []findings.Finding, noColor bool) {
	c := detectColor(noColor)
	renderTerminalColored(w, results, c)
}

func renderTerminalColored(w io.Writer, results []findings.Finding, c colorScheme) {
	if len(results) == 0 {
		fmt.Fprintln(w, c.wrap(ansiGreen, "FIPS 140-3 Readiness Scan — no findings."))
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

	fmt.Fprintf(w, "%s — %d finding(s)\n", c.wrap(ansiBold, "FIPS 140-3 Readiness Scan"), len(results))
	fmt.Fprintf(w, "  %s: %d   %s: %d   %s: %d\n\n",
		c.wrap(ansiBold+ansiRed, "HIGH"), bySev[findings.SeverityHigh],
		c.wrap(ansiBold+ansiYellow, "MEDIUM"), bySev[findings.SeverityMedium],
		c.wrap(ansiBlue, "LOW"), bySev[findings.SeverityLow],
	)

	for _, f := range results {
		fmt.Fprintf(w, "[%s] %s — %s\n", c.sev(f.Severity), f.Algorithm, c.wrap(ansiCyan, f.Rule))
		fmt.Fprintf(w, "  %s:%d  (%s)\n", c.wrap(ansiBold, f.File), f.Line, f.Language)
		fmt.Fprintf(w, "    %s\n", c.wrap(ansiDim, f.Snippet))
		fmt.Fprintf(w, "    -> %s\n", f.Remediation)
		if f.Reference != "" {
			fmt.Fprintf(w, "    %s %s\n", c.wrap(ansiDim, "ref:"), f.Reference)
		}
		fmt.Fprintln(w)
	}
}

// RenderResolved emits a "resolved since baseline" section to w.
// Designed to be called *after* RenderTerminal of the new-findings
// list when -show-resolved is on. Compact one-liner per entry —
// resolved findings are good news, not action items.
func RenderResolved(w io.Writer, resolved []findings.Finding, noColor bool) {
	c := detectColor(noColor)
	if len(resolved) == 0 {
		fmt.Fprintln(w, c.wrap(ansiDim, "Resolved since baseline: none."))
		return
	}
	bySev := map[findings.Severity]int{}
	for _, f := range resolved {
		bySev[f.Severity]++
	}
	fmt.Fprintf(w, "%s — %d finding(s)\n",
		c.wrap(ansiBold+ansiGreen, "Resolved since baseline"), len(resolved))
	fmt.Fprintf(w, "  HIGH: %d   MEDIUM: %d   LOW: %d\n\n",
		bySev[findings.SeverityHigh],
		bySev[findings.SeverityMedium],
		bySev[findings.SeverityLow],
	)
	for _, f := range resolved {
		fmt.Fprintf(w, "  %s [%s] %s  %s\n",
			c.wrap(ansiGreen, "✓"),
			f.Severity, f.Algorithm,
			c.wrap(ansiDim, fmt.Sprintf("(was %s:%d, %s)", f.File, f.Line, f.Rule)))
	}
	fmt.Fprintln(w)
}

// RenderWaived emits the "waived inline" section. Same shape as
// RenderResolved — informational rather than actionable.
func RenderWaived(w io.Writer, waived []findings.Finding, noColor bool) {
	c := detectColor(noColor)
	if len(waived) == 0 {
		return
	}
	fmt.Fprintf(w, "%s — %d finding(s)\n",
		c.wrap(ansiBold+ansiDim, "Waived by inline fipscan:waive comments"), len(waived))
	for _, f := range waived {
		fmt.Fprintf(w, "  %s [%s] %s  %s\n",
			c.wrap(ansiDim, "—"),
			f.Severity, f.Algorithm,
			c.wrap(ansiDim, fmt.Sprintf("%s:%d, %s", f.File, f.Line, f.Rule)))
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
