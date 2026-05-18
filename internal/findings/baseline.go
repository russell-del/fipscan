package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Baseline is a snapshot of findings captured at a point in time. The
// scan flow can write one (`-baseline-write file.json`) and later diff
// against it (`-baseline file.json`) so adopting fipscan on a codebase
// with 500 existing findings doesn't drown the next PR.
type Baseline struct {
	Version     string    `json:"version"`     // fipscan version that wrote this
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
}

// WriteBaseline writes results to path as pretty JSON.
func WriteBaseline(path, version string, results []Finding) error {
	b := Baseline{
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Findings:    results,
	}
	data, err := json.MarshalIndent(&b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadBaseline loads a baseline file from disk.
func ReadBaseline(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, fmt.Errorf("read baseline %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return b, nil
}

// fingerprint produces a stable identity for a Finding that ignores
// version-bumps and line-shifts. Two findings are considered "the
// same" when their fingerprints match:
//
//   - Rule           — same rule firing
//   - File           — same source (file path / image ref / manifest)
//   - AlgorithmName  — Algorithm field with the trailing version stripped
//
// So `bcrypt 4.0.1` matches `bcrypt 4.0.2` (lockfile version bump
// shouldn't generate a "new" finding) and `md5.Sum(data)` at line 11
// matches the same call at line 13 (refactor moved the line).
//
// For container findings whose Algorithm is `ELF-NEEDED: libcrypto.so.3`
// the colon and everything after it is kept — different sonames are
// different findings.
func fingerprint(f Finding) string {
	return f.Rule + "|" + f.File + "|" + algorithmName(f.Algorithm)
}

// algorithmName strips the trailing version from a dep-style Algorithm
// field like "bcrypt 4.0.1" → "bcrypt", while leaving code-style
// Algorithm fields like "MD5" and "ELF-NEEDED: libcrypto.so.3"
// unchanged.
func algorithmName(s string) string {
	i := strings.Index(s, " ")
	if i <= 0 {
		return s
	}
	// Don't strip if everything after the space starts with a non-version
	// token (e.g. "ELF-NEEDED:" — keep the soname).
	rest := s[i+1:]
	if strings.HasPrefix(rest, "ELF-") || strings.HasPrefix(s, "ELF-") {
		return s
	}
	return s[:i]
}

// Diff returns the subset of current that doesn't appear in baseline
// (by fingerprint). Order is preserved.
func Diff(current []Finding, baseline Baseline) []Finding {
	seen := make(map[string]struct{}, len(baseline.Findings))
	for _, f := range baseline.Findings {
		seen[fingerprint(f)] = struct{}{}
	}
	out := make([]Finding, 0)
	for _, f := range current {
		if _, ok := seen[fingerprint(f)]; !ok {
			out = append(out, f)
		}
	}
	return out
}
