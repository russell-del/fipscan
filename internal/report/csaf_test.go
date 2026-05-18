package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rbuilta/fipscan/internal/findings"
)

func TestRenderCSAF_StructuralValidity(t *testing.T) {
	results := []findings.Finding{
		{
			File:        "uv.lock",
			Line:        14,
			Algorithm:   "bcrypt 4.1.2",
			Language:    "PyPI",
			Severity:    findings.SeverityHigh,
			Rule:        "FIPS-DEP-PYPI-003",
			Remediation: "Use PBKDF2 instead.",
			Reference:   "NIST SP 800-132",
		},
		{
			File:        "src/main.go",
			Line:        11,
			Algorithm:   "MD5",
			Language:    "Go",
			Severity:    findings.SeverityHigh,
			Rule:        "FIPS-HASH-001",
			Remediation: "Replace with SHA-256.",
			Reference:   "FIPS 180-4",
		},
		// Duplicate of the first finding in a different manifest —
		// should share a single vulnerability entry, with both
		// products listed as known_affected.
		{
			File:        "requirements.txt",
			Line:        5,
			Algorithm:   "bcrypt 4.0.1",
			Language:    "PyPI",
			Severity:    findings.SeverityHigh,
			Rule:        "FIPS-DEP-PYPI-003",
			Remediation: "Use PBKDF2 instead.",
			Reference:   "NIST SP 800-132",
		},
	}

	var buf bytes.Buffer
	if err := RenderCSAF(&buf, results, "1.10.0"); err != nil {
		t.Fatalf("RenderCSAF: %v", err)
	}

	// Round-trip parse — must be valid JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("emitted CSAF is not valid JSON: %v", err)
	}

	// Document required fields.
	doc := raw["document"].(map[string]interface{})
	if doc["category"] != "csaf_vex" {
		t.Errorf("document.category = %v, want csaf_vex", doc["category"])
	}
	if doc["csaf_version"] != "2.0" {
		t.Errorf("document.csaf_version = %v, want 2.0", doc["csaf_version"])
	}

	tracking := doc["tracking"].(map[string]interface{})
	for _, k := range []string{"id", "status", "version", "initial_release_date", "current_release_date", "revision_history"} {
		if _, ok := tracking[k]; !ok {
			t.Errorf("document.tracking missing required field: %s", k)
		}
	}
	if tracking["status"] != "final" {
		t.Errorf("tracking.status = %v, want final", tracking["status"])
	}

	pub := doc["publisher"].(map[string]interface{})
	if _, ok := pub["category"]; !ok {
		t.Error("publisher.category missing")
	}
	if _, ok := pub["name"]; !ok {
		t.Error("publisher.name missing")
	}

	// Vulnerabilities — should have 2 entries (one per unique rule).
	vulns := raw["vulnerabilities"].([]interface{})
	if len(vulns) != 2 {
		t.Errorf("vulnerabilities count = %d, want 2", len(vulns))
	}

	// The FIPS-DEP-PYPI-003 entry should have 2 known_affected
	// products (uv.lock entry + requirements.txt entry).
	for _, v := range vulns {
		vv := v.(map[string]interface{})
		ids := vv["ids"].([]interface{})
		ruleID := ids[0].(map[string]interface{})["text"].(string)
		if ruleID != "FIPS-DEP-PYPI-003" {
			continue
		}
		ps := vv["product_status"].(map[string]interface{})
		known := ps["known_affected"].([]interface{})
		if len(known) != 2 {
			t.Errorf("FIPS-DEP-PYPI-003 known_affected count = %d, want 2", len(known))
		}
		for _, p := range known {
			ps := p.(string)
			if !strings.HasPrefix(ps, "pkg:pypi/bcrypt") {
				t.Errorf("expected pypi purl, got %q", ps)
			}
		}
	}
}

func TestPurlFor(t *testing.T) {
	cases := []struct {
		lang, name, version, want string
	}{
		{"PyPI", "bcrypt", "4.0.1", "pkg:pypi/bcrypt@4.0.1"},
		{"npm", "node-forge", "1.3.1", "pkg:npm/node-forge@1.3.1"},
		{"Go modules", "golang.org/x/crypto", "0.18.0", "pkg:golang/golang.org%2Fx%2Fcrypto@0.18.0"},
		{"Maven", "org.bouncycastle:bcprov-jdk18on", "1.77", "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77"},
		{"Maven (Gradle)", "org.mindrot:jbcrypt", "0.4", "pkg:maven/org.mindrot/jbcrypt@0.4"},
		{"Cargo", "md5", "0.7.0", "pkg:cargo/md5@0.7.0"},
		{"RubyGems", "bcrypt", "3.1.22", "pkg:gem/bcrypt@3.1.22"},
		{"Composer", "phpseclib/phpseclib", "3.0.34", "pkg:composer/phpseclib/phpseclib@3.0.34"},
		{"NuGet", "BCrypt.Net-Next", "4.0.3", "pkg:nuget/BCrypt.Net-Next@4.0.3"},
		{"Container (apk)", "libcrypto3", "3.1.8-r1", "pkg:apk/alpine/libcrypto3@3.1.8-r1"},
		{"PyPI", "bcrypt", "", ""}, // no version → no purl
		{"Go", "MD5", "", ""},      // code finding, not a package
	}
	for _, c := range cases {
		got := purlFor(c.lang, c.name, c.version)
		if got != c.want {
			t.Errorf("purlFor(%q, %q, %q) = %q, want %q",
				c.lang, c.name, c.version, got, c.want)
		}
	}
}

func TestExtractCVE(t *testing.T) {
	cases := map[string]string{
		"OSV-CVE-2023-23931":     "CVE-2023-23931",
		"OSV-GHSA-xxxx-yyyy-zzz": "",
		"FIPS-DEP-PYPI-003":      "",
		"":                       "",
	}
	for in, want := range cases {
		if got := extractCVE(in); got != want {
			t.Errorf("extractCVE(%q) = %q, want %q", in, got, want)
		}
	}
}
