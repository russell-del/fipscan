// Package deps scans dependency manifests (requirements.txt, go.mod,
// package-lock.json, pom.xml, *.csproj, Pipfile.lock, pyproject.toml,
// uv.lock, poetry.lock, Cargo.lock, yarn.lock, Gemfile.lock,
// composer.lock) and flags packages whose FIPS 140-3 posture is
// problematic — known weak crypto libraries, non-FIPS-validated
// variants where a FIPS variant exists, and packages implementing
// algorithms that aren't on the FIPS approved list.
package deps

import "strings"

// CatalogEntry describes one package whose presence in a manifest is
// FIPS-relevant.
//
// AffectedVersions optionally narrows the entry to a version range
// (see ParseConstraints for accepted syntax). Empty means "applies to
// all versions". Multiple entries can target the same (ecosystem, name)
// with different version ranges and severities — e.g. one HIGH entry
// for the CVE-affected window and one MEDIUM entry for everything
// outside it.
type CatalogEntry struct {
	Ecosystem        string // "pypi" | "npm" | "go" | "maven" | "nuget" | "cargo" | "rubygems" | "composer"
	Name             string // canonical package name (case as commonly written)
	AffectedVersions string // optional, e.g. "<1.3.0" or ">=1.0,<2.0"
	RuleID           string
	Severity         string // "HIGH" | "MEDIUM" | "LOW"
	Reason           string
	Remediation      string
	Reference        string
}

// indexedEntry pairs a catalog entry with its pre-parsed constraint
// set so Lookup doesn't re-parse on every dep.
type indexedEntry struct {
	Entry       CatalogEntry
	Constraints []Constraint
}

// catalogIndex: ecosystem → lowercased-name → list of matching entries.
// A name can have multiple entries when AffectedVersions partitions
// the version space into different severities.
var catalogIndex map[string]map[string][]indexedEntry

func init() {
	catalogIndex = make(map[string]map[string][]indexedEntry, 8)
	for _, e := range catalog {
		eco := strings.ToLower(e.Ecosystem)
		if catalogIndex[eco] == nil {
			catalogIndex[eco] = make(map[string][]indexedEntry)
		}
		cs, err := ParseConstraints(e.AffectedVersions)
		if err != nil {
			// Malformed AffectedVersions = catalog bug; skip the
			// entry rather than crash at startup.
			continue
		}
		key := canonName(e.Name)
		catalogIndex[eco][key] = append(catalogIndex[eco][key], indexedEntry{
			Entry:       e,
			Constraints: cs,
		})
	}
}

func canonName(n string) string { return strings.ToLower(n) }

// Lookup returns every catalog entry that applies to the (ecosystem,
// name, version) triple. Multiple matches are possible when several
// entries with different version ranges all overlap the input version.
//
// When version is "" (the manifest didn't pin one), only entries with
// no AffectedVersions constraint are returned — emitting a constrained
// finding without knowing the version would be a guess.
func Lookup(ecosystem, name, version string) []CatalogEntry {
	eco := catalogIndex[strings.ToLower(ecosystem)]
	if eco == nil {
		return nil
	}
	entries := eco[canonName(name)]
	if len(entries) == 0 {
		return nil
	}
	if version == "" {
		var out []CatalogEntry
		for _, e := range entries {
			if len(e.Constraints) == 0 {
				out = append(out, e.Entry)
			}
		}
		return out
	}
	v := ParseVersion(version)
	var out []CatalogEntry
	for _, e := range entries {
		if MatchAll(e.Constraints, v) {
			out = append(out, e.Entry)
		}
	}
	return out
}
