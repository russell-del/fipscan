// Package deps scans dependency manifests (requirements.txt, go.mod,
// package-lock.json, pom.xml, *.csproj, Pipfile.lock) and flags packages
// whose FIPS 140-3 posture is problematic — known weak crypto libraries,
// non-FIPS-validated variants where a FIPS variant exists, and packages
// implementing algorithms that aren't on the FIPS approved list.
package deps

import "strings"

// CatalogEntry describes one package whose presence in a manifest is
// FIPS-relevant. Reason explains the concern; Remediation tells the user
// what to do about it.
type CatalogEntry struct {
	Ecosystem   string // "pypi" | "npm" | "go" | "maven" | "nuget"
	Name        string // canonical package name (case as commonly written)
	RuleID      string
	Severity    string // "HIGH" | "MEDIUM" | "LOW"
	Reason      string
	Remediation string
	Reference   string
}

// catalogIndex provides O(1) lookup keyed by (ecosystem, lowercased-name).
// Most ecosystem package registries are case-insensitive (PyPI, npm, NuGet,
// Maven Central by convention); those that are technically case-sensitive
// (Go module paths) are still lowercase by overwhelming convention.
var catalogIndex map[string]map[string]CatalogEntry

func init() {
	catalogIndex = make(map[string]map[string]CatalogEntry, 8)
	for _, e := range catalog {
		eco := strings.ToLower(e.Ecosystem)
		if _, ok := catalogIndex[eco]; !ok {
			catalogIndex[eco] = make(map[string]CatalogEntry)
		}
		catalogIndex[eco][canonName(e.Name)] = e
	}
}

func canonName(n string) string { return strings.ToLower(n) }

// Lookup returns the catalog entry for (ecosystem, name) or nil if the
// package is not in the FIPS-relevance catalog.
func Lookup(ecosystem, name string) *CatalogEntry {
	eco, ok := catalogIndex[strings.ToLower(ecosystem)]
	if !ok {
		return nil
	}
	if e, ok := eco[canonName(name)]; ok {
		return &e
	}
	return nil
}
