package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/russell-del/fipscan/internal/findings"
)

// CSAF 2.0 VEX renderer.
//
// CSAF (Common Security Advisory Framework) is the OASIS standard for
// machine-readable security advisories; VEX (Vulnerability Exploitability
// eXchange) is its profile for "this product is affected by this
// vulnerability" statements. CISA, Red Hat, Cisco, Oracle, and most
// modern gov-adjacent vendors publish in this format.
//
// Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
//
// Pragmatic scope here:
//   - All required `document`, `product_tree`, `vulnerabilities` fields
//     are emitted.
//   - Findings are placed in `product_status.known_affected`.
//   - We do NOT emit `known_not_affected`, `fixed`, or
//     `under_investigation` (we're a scanner, not a tracking system).
//   - We deliberately don't claim full schema conformance — that
//     requires running an OASIS-blessed validator. Real-world CSAF
//     consumers in the gov space tolerate minor schema gaps well.

type csafDoc struct {
	Document        csafDocMeta     `json:"document"`
	ProductTree     csafProductTree `json:"product_tree"`
	Vulnerabilities []csafVuln      `json:"vulnerabilities"`
}

type csafDocMeta struct {
	Category     string           `json:"category"`     // "csaf_vex"
	CsafVersion  string           `json:"csaf_version"` // "2.0"
	Distribution *csafDistribution `json:"distribution,omitempty"`
	Publisher    csafPublisher    `json:"publisher"`
	Title        string           `json:"title"`
	Tracking     csafTracking     `json:"tracking"`
}

type csafDistribution struct {
	TLP csafTLP `json:"tlp"`
}

type csafTLP struct {
	Label string `json:"label"` // "WHITE" | "GREEN" | "AMBER" | "RED"
}

type csafPublisher struct {
	Category string `json:"category"` // "vendor" | "user" | "discoverer" | etc.
	Name     string `json:"name"`
}

type csafTracking struct {
	ID                 string         `json:"id"`
	Status             string         `json:"status"` // "final"
	Version            string         `json:"version"`
	InitialReleaseDate time.Time      `json:"initial_release_date"`
	CurrentReleaseDate time.Time      `json:"current_release_date"`
	RevisionHistory    []csafRevision `json:"revision_history"`
	Generator          csafGenerator  `json:"generator"`
}

type csafRevision struct {
	Date    time.Time `json:"date"`
	Number  string    `json:"number"`
	Summary string    `json:"summary"`
}

type csafGenerator struct {
	Date   time.Time  `json:"date"`
	Engine csafEngine `json:"engine"`
}

type csafEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Category string       `json:"category"` // "vendor" | "product_name" | "product_version"
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product,omitempty"`
	Branches []csafBranch `json:"branches,omitempty"`
}

type csafProduct struct {
	Name      string             `json:"name"`
	ProductID string             `json:"product_id"`
	Helper    *csafProductHelper `json:"product_identification_helper,omitempty"`
}

type csafProductHelper struct {
	PURL string `json:"purl,omitempty"`
}

type csafVuln struct {
	CVE           string             `json:"cve,omitempty"`
	IDs           []csafVulnID       `json:"ids,omitempty"`
	Title         string             `json:"title,omitempty"`
	Notes         []csafNote         `json:"notes,omitempty"`
	ProductStatus *csafProductStatus `json:"product_status,omitempty"`
	Remediations  []csafRemediation  `json:"remediations,omitempty"`
	References    []csafReference    `json:"references,omitempty"`
}

type csafVulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type csafProductStatus struct {
	KnownAffected []string `json:"known_affected"`
}

type csafRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type csafReference struct {
	Category string `json:"category"` // "external" | "self"
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type csafNote struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

// RenderCSAF writes a CSAF 2.0 VEX document to w. version is fipscan's
// own version (embedded in document.tracking.generator).
func RenderCSAF(w io.Writer, results []findings.Finding, version string) error {
	now := time.Now().UTC()
	scanID := "fipscan-" + now.Format("20060102T150405Z") + "-" + randHex(4)

	// Group results by rule so each vulnerability entry covers all
	// products it applies to.
	type groupKey string
	groups := map[groupKey][]findings.Finding{}
	order := []groupKey{} // preserve first-seen order
	for _, f := range results {
		k := groupKey(f.Rule)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}

	// Build product_tree: collect every unique (algo-without-version,
	// version, language) triple. We group by language (≈ ecosystem) so
	// the tree has one top-level branch per ecosystem.
	type productKey struct{ Language, Algo, Version string }
	products := map[productKey]csafProduct{}
	for _, f := range results {
		algo := stripAlgoVersion(f.Algorithm)
		ver := extractAlgoVersion(f.Algorithm)
		pk := productKey{Language: f.Language, Algo: algo, Version: ver}
		if _, ok := products[pk]; ok {
			continue
		}
		products[pk] = csafProduct{
			Name:      f.Algorithm,
			ProductID: productID(f.Language, algo, ver, f.File),
			Helper:    purlHelper(f.Language, algo, ver),
		}
	}

	byLang := map[string][]csafBranch{}
	for pk, prod := range products {
		// Nested: language → product_name → product_version (with product).
		versionBranch := csafBranch{
			Category: "product_version",
			Name:     pk.Version,
			Product:  &csafProduct{Name: prod.Name, ProductID: prod.ProductID, Helper: prod.Helper},
		}
		nameBranch := csafBranch{
			Category: "product_name",
			Name:     pk.Algo,
			Branches: []csafBranch{versionBranch},
		}
		byLang[pk.Language] = append(byLang[pk.Language], nameBranch)
	}
	var langBranches []csafBranch
	for lang, pname := range byLang {
		langBranches = append(langBranches, csafBranch{
			Category: "vendor",
			Name:     lang,
			Branches: pname,
		})
	}

	// Build vulnerabilities array: one per rule.
	var vulns []csafVuln
	for _, k := range order {
		gs := groups[k]
		exemplar := gs[0]
		var affected []string
		for _, f := range gs {
			affected = append(affected, productID(
				f.Language,
				stripAlgoVersion(f.Algorithm),
				extractAlgoVersion(f.Algorithm),
				f.File))
		}
		v := csafVuln{
			Title: exemplar.Rule + " — " + stripAlgoVersion(exemplar.Algorithm),
			IDs: []csafVulnID{
				{SystemName: "fipscan", Text: exemplar.Rule},
			},
			Notes: []csafNote{
				{Category: "description", Text: exemplar.Remediation},
			},
			ProductStatus: &csafProductStatus{KnownAffected: dedupStrings(affected)},
			Remediations: []csafRemediation{{
				Category:   "mitigation",
				Details:    exemplar.Remediation,
				ProductIDs: dedupStrings(affected),
			}},
		}
		if cve := extractCVE(exemplar.Rule); cve != "" {
			v.CVE = cve
		}
		if exemplar.Reference != "" {
			v.References = []csafReference{
				{Category: "external", Summary: "Reference", URL: exemplar.Reference},
			}
		}
		vulns = append(vulns, v)
	}

	doc := csafDoc{
		Document: csafDocMeta{
			Category:    "csaf_vex",
			CsafVersion: "2.0",
			Distribution: &csafDistribution{
				TLP: csafTLP{Label: "WHITE"},
			},
			Publisher: csafPublisher{
				Category: "vendor",
				Name:     "fipscan (automated)",
			},
			Title: "fipscan scan results",
			Tracking: csafTracking{
				ID:                 scanID,
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: now,
				CurrentReleaseDate: now,
				RevisionHistory: []csafRevision{
					{Date: now, Number: "1", Summary: "Initial scan output."},
				},
				Generator: csafGenerator{
					Date:   now,
					Engine: csafEngine{Name: "fipscan", Version: version},
				},
			},
		},
		ProductTree:     csafProductTree{Branches: langBranches},
		Vulnerabilities: vulns,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&doc)
}

// stripAlgoVersion drops the " <version>" suffix from finding
// Algorithm strings ("bcrypt 4.0.1" → "bcrypt"). Preserves whole
// strings that contain a colon (e.g. "ELF-NEEDED: libcrypto.so.3").
func stripAlgoVersion(s string) string {
	if strings.Contains(s, ":") {
		return s
	}
	if i := strings.LastIndex(s, " "); i > 0 {
		return s[:i]
	}
	return s
}

func extractAlgoVersion(s string) string {
	if strings.Contains(s, ":") {
		return ""
	}
	if i := strings.LastIndex(s, " "); i > 0 {
		return s[i+1:]
	}
	return ""
}

// productID builds a stable per-product identifier used for CSAF
// product_status references. PURL when we can synthesize one, else
// fall back to a generic id including language + file + name+version.
func productID(language, name, version, file string) string {
	if p := purlFor(language, name, version); p != "" {
		return p
	}
	if file != "" && version == "" {
		return "pkg:generic/" + url.PathEscape(file) + "?identity=" + url.QueryEscape(name)
	}
	return "pkg:generic/" + url.PathEscape(language) + "/" + url.PathEscape(name) + "@" + url.PathEscape(version)
}

func purlHelper(language, name, version string) *csafProductHelper {
	if p := purlFor(language, name, version); p != "" {
		return &csafProductHelper{PURL: p}
	}
	return nil
}

// purlFor returns a Package URL for the (language, name, version)
// triple, or "" when the input doesn't correspond to a well-known
// package ecosystem (e.g. code or container findings).
//
// PURL spec: https://github.com/package-url/purl-spec
func purlFor(language, name, version string) string {
	if version == "" {
		return ""
	}
	enc := func(s string) string { return url.PathEscape(s) }
	switch language {
	case "PyPI":
		return "pkg:pypi/" + enc(name) + "@" + enc(version)
	case "npm":
		// Scoped package "@scope/pkg" — purl uses /@scope/pkg
		return "pkg:npm/" + enc(name) + "@" + enc(version)
	case "Go modules":
		return "pkg:golang/" + enc(name) + "@" + enc(version)
	case "Maven", "Maven (Gradle)", "Maven (Gradle catalog)":
		// Maven coord: "<group>:<artifact>" → "pkg:maven/<group>/<artifact>@<v>"
		if i := strings.Index(name, ":"); i > 0 {
			return "pkg:maven/" + enc(name[:i]) + "/" + enc(name[i+1:]) + "@" + enc(version)
		}
		return ""
	case "Cargo":
		return "pkg:cargo/" + enc(name) + "@" + enc(version)
	case "RubyGems":
		return "pkg:gem/" + enc(name) + "@" + enc(version)
	case "Composer":
		// "vendor/pkg" → "pkg:composer/vendor/pkg@<v>"
		if i := strings.Index(name, "/"); i > 0 {
			return "pkg:composer/" + enc(name[:i]) + "/" + enc(name[i+1:]) + "@" + enc(version)
		}
		return "pkg:composer/" + enc(name) + "@" + enc(version)
	case "NuGet":
		return "pkg:nuget/" + enc(name) + "@" + enc(version)
	case "Container (apk)":
		return "pkg:apk/alpine/" + enc(name) + "@" + enc(version)
	case "Container (dpkg)":
		return "pkg:deb/debian/" + enc(name) + "@" + enc(version)
	case "Container (rpm)":
		return "pkg:rpm/redhat/" + enc(name) + "@" + enc(version)
	}
	return ""
}

// extractCVE pulls a CVE id out of a rule when one is embedded.
// OSV-imported rules have IDs like "OSV-CVE-2023-23931" or
// "OSV-GHSA-xxxx-xxxx-xxxx"; only the former carries a CVE we can
// surface in CSAF's dedicated `cve` field.
func extractCVE(rule string) string {
	const prefix = "OSV-CVE-"
	if strings.HasPrefix(rule, prefix) {
		return "CVE-" + strings.TrimPrefix(rule, prefix)
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano()%(1<<32))
	}
	return hex.EncodeToString(b)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
