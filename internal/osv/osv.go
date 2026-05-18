// Package osv ingests Open Source Vulnerabilities (osv.dev) data and
// converts crypto-relevant entries into fipscan catalog entries.
//
// We deliberately avoid the heavyweight `osv-schema` Go reference
// library and parse a minimal subset of fields against the documented
// schema (https://ossf.github.io/osv-schema/) — keeps the zero-dep
// posture intact.
package osv

import (
	"strings"
)

// Vulnerability is the subset of the OSV schema (v1.6) we need to
// convert into a fipscan catalog entry.
type Vulnerability struct {
	ID       string      `json:"id"`
	Summary  string      `json:"summary"`
	Details  string      `json:"details"`
	Aliases  []string    `json:"aliases"`
	Affected []Affected  `json:"affected"`
	References []Reference `json:"references"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Type   string  `json:"type"` // "ECOSYSTEM" | "SEMVER" | "GIT"
	Events []Event `json:"events"`
}

// Event is one boundary in an OSV affected-version range. Exactly one
// of Introduced / Fixed / LastAffected is populated per event.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ImportedEntry mirrors deps.CatalogEntry exactly. We don't import
// deps here (would be a cycle since osv_entries.go lives in the deps
// package) — the codegen tool emits Go source that wraps these values
// in `deps.CatalogEntry{…}` literals.
type ImportedEntry struct {
	Ecosystem        string
	Name             string
	AffectedVersions string
	RuleID           string
	Severity         string
	Reason           string
	Remediation      string
	Reference        string
}

// cryptoKeywords decides whether a CVE summary/details suggests the
// vulnerability is about cryptography.
//
// Tight list, word-boundaried at lookup time. Avoids broad words like
// "key", "random", "encrypt", "verification" that match all manner of
// unrelated CVEs. False negatives here are easier to recover from
// (find via real customer findings and add to the package allowlist)
// than false positives (thousands of XSS / DoS / parser bug entries
// poisoning the catalog).
var (
	cryptoKeywords = []string{
		// generic
		"cryptograph", "cryptographic", "cryptographically",
		"fips",
		// libraries / impls
		"openssl", "boringssl", "wolfssl", "mbedtls", "libsodium",
		"libgcrypt", "gnutls", "bouncycastle", "nss",
		// protocols
		"tls", "ssl", "dtls", "ipsec", "ssh",
		// primitives
		"aes", "des", "3des", "rc4", "chacha", "chacha20",
		"salsa20", "blowfish", "twofish", "rsa", "ecdsa", "ecdh",
		"x25519", "ed25519", "secp256k1", "secp256r1", "prime256v1",
		"md5", "sha-1", "sha1", "md4", "hmac",
		"bcrypt", "scrypt", "pbkdf", "pbkdf2", "argon2",
		// pki
		"x.509", "x509",
	}

	cryptoPhrases = []string{
		"padding oracle",
		"timing attack",
		"side channel",
		"side-channel",
		"key derivation",
		"key exchange",
		"signature bypass",
		"signature verification",
		"certificate validation",
		"certificate verification",
		"insecure random",
		"weak random",
		"weak prng",
		"private key disclosure",
		"private key leak",
		"hash collision",
		"length extension",
	}
)

// IsCryptoRelevant returns true when the vulnerability is plausibly
// crypto-related. Two paths:
//   1. ANY affected package is in knownCryptoPackages (clean signal —
//      a CVE on cryptography / openssl / bouncycastle is always
//      crypto-relevant regardless of how the summary is phrased).
//   2. Otherwise, the summary or details contains a strong crypto
//      keyword (word-boundaried) or phrase.
//
// knownCryptoPackages keys are "<ecosystem>:<name>", both lowercased.
func (v Vulnerability) IsCryptoRelevant(knownCryptoPackages map[string]bool) bool {
	for _, a := range v.Affected {
		key := strings.ToLower(a.Package.Ecosystem) + ":" + strings.ToLower(a.Package.Name)
		if knownCryptoPackages[key] {
			return true
		}
	}
	// Surround with spaces so single-char-class keyword lookups have
	// a word boundary on both sides.
	text := " " + strings.ToLower(v.Summary+" "+v.Details) + " "
	for _, kw := range cryptoKeywords {
		// "tls" must not match "ttls", "tlsx", etc.; require space
		// before and either space or punctuation after.
		if strings.Contains(text, " "+kw+" ") ||
			strings.Contains(text, " "+kw+".") ||
			strings.Contains(text, " "+kw+",") ||
			strings.Contains(text, " "+kw+";") ||
			strings.Contains(text, " "+kw+"/") ||
			strings.Contains(text, " "+kw+":") {
			return true
		}
	}
	for _, ph := range cryptoPhrases {
		if strings.Contains(text, ph) {
			return true
		}
	}
	return false
}

// osvEcosystemToOurs maps OSV's ecosystem string to fipscan's internal
// ecosystem id. Ecosystems we don't ingest yet are deliberately absent.
var osvEcosystemToOurs = map[string]string{
	"PyPI":      "pypi",
	"npm":       "npm",
	"Go":        "go",
	"Maven":     "maven",
	"crates.io": "cargo",
	"RubyGems":  "rubygems",
	"Packagist": "composer",
	"NuGet":     "nuget",
}

// ToEntries converts the vulnerability into ImportedEntry records.
//
// Per-affected-package filtering: when the vulnerability is
// crypto-relevant ONLY via keyword match (the package itself isn't on
// the known-crypto allowlist), we emit entries only for affected
// packages that ARE on the allowlist. This stops a CVE that mentions
// "TLS" once in its details from polluting the catalog with entries
// for every unrelated package in its `affected` list.
//
// Returns nil when no affected package qualifies.
func (v Vulnerability) ToEntries(knownCryptoPackages map[string]bool) []ImportedEntry {
	var out []ImportedEntry
	for _, a := range v.Affected {
		eco, ok := osvEcosystemToOurs[a.Package.Ecosystem]
		if !ok {
			continue
		}
		key := strings.ToLower(a.Package.Ecosystem) + ":" + strings.ToLower(a.Package.Name)
		if !knownCryptoPackages[key] {
			// The package isn't a known crypto component. Skip it —
			// keyword matches at the vuln level are too noisy to
			// expand into entries for arbitrary packages.
			continue
		}
		constraint, encodable := rangesToConstraint(a.Ranges)
		if !encodable {
			continue
		}
		summary := strings.TrimSpace(v.Summary)
		if summary == "" {
			summary = v.ID
		}
		out = append(out, ImportedEntry{
			Ecosystem:        eco,
			Name:             strings.ToLower(a.Package.Name),
			AffectedVersions: constraint,
			RuleID:           "OSV-" + v.ID,
			Severity:         "MEDIUM",
			Reason:           summary + " (imported from osv.dev)",
			Remediation:      "Upgrade to a fixed version. See " + osvAdvisoryURL(v.ID) + " for details.",
			Reference:        osvAdvisoryURL(v.ID),
		})
	}
	return out
}

// rangesToConstraint folds the FIRST OSV range into a fipscan
// constraint string. Returns encodable=false when the range can't be
// expressed (no events, GIT range type, or only Introduced=0 with no
// upper bound — which would match every version and produce useless
// noise).
//
// Multiple disjoint ranges aren't yet supported by our constraint
// system; we take the first range. Acceptable for v1.8.0 — multi-range
// OSV entries are uncommon in the crypto-relevant subset.
func rangesToConstraint(ranges []Range) (string, bool) {
	for _, r := range ranges {
		if r.Type == "GIT" {
			continue
		}
		var clauses []string
		for _, e := range r.Events {
			switch {
			case e.Fixed != "":
				clauses = append(clauses, "<"+e.Fixed)
			case e.LastAffected != "":
				clauses = append(clauses, "<="+e.LastAffected)
			case e.Introduced != "" && e.Introduced != "0":
				clauses = append(clauses, ">="+e.Introduced)
			}
		}
		if len(clauses) == 0 {
			continue
		}
		return strings.Join(clauses, ","), true
	}
	return "", false
}

func osvAdvisoryURL(id string) string {
	return "https://osv.dev/vulnerability/" + id
}
