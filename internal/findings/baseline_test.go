package findings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiff(t *testing.T) {
	mk := func(rule, file, algo string) Finding {
		return Finding{Rule: rule, File: file, Algorithm: algo, Severity: SeverityHigh}
	}

	t.Run("identical scans produce empty diff", func(t *testing.T) {
		set := []Finding{
			mk("FIPS-HASH-001", "src/a.go", "MD5"),
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.1"),
		}
		baseline := Baseline{Findings: set}
		got := Diff(set, baseline)
		if len(got) != 0 {
			t.Errorf("identical scan should diff to 0, got %d", len(got))
		}
	})

	t.Run("version bump in dep is not a new finding", func(t *testing.T) {
		baseline := Baseline{Findings: []Finding{
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.1"),
		}}
		current := []Finding{
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.2"),
		}
		got := Diff(current, baseline)
		if len(got) != 0 {
			t.Errorf("bcrypt version bump shouldn't be a new finding, got %d", len(got))
		}
	})

	t.Run("line shift in code is not a new finding", func(t *testing.T) {
		baseline := Baseline{Findings: []Finding{
			{Rule: "FIPS-HASH-001", File: "src/a.go", Line: 11, Algorithm: "MD5", Severity: SeverityHigh},
		}}
		current := []Finding{
			{Rule: "FIPS-HASH-001", File: "src/a.go", Line: 13, Algorithm: "MD5", Severity: SeverityHigh},
		}
		got := Diff(current, baseline)
		if len(got) != 0 {
			t.Errorf("line-shift shouldn't be a new finding, got %d", len(got))
		}
	})

	t.Run("genuinely new finding surfaces", func(t *testing.T) {
		baseline := Baseline{Findings: []Finding{
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.1"),
		}}
		current := []Finding{
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.2"),
			mk("FIPS-DEP-PYPI-001", "uv.lock", "pycrypto 2.6.1"), // new!
		}
		got := Diff(current, baseline)
		if len(got) != 1 {
			t.Fatalf("expected 1 new finding, got %d", len(got))
		}
		if got[0].Rule != "FIPS-DEP-PYPI-001" {
			t.Errorf("wrong finding kept: %+v", got[0])
		}
	})

	t.Run("ELF DT_NEEDED sonames are not stripped", func(t *testing.T) {
		// Two different sonames should be two different findings;
		// the version-strip shouldn't collapse `libcrypto.so.3` to `libcrypto`.
		baseline := Baseline{Findings: []Finding{
			mk("FIPS-CONT-OPENSSL-001", "image:tag", "ELF-NEEDED: libcrypto.so.3"),
		}}
		current := []Finding{
			mk("FIPS-CONT-OPENSSL-001", "image:tag", "ELF-NEEDED: libssl.so.3"),
		}
		got := Diff(current, baseline)
		if len(got) != 1 {
			t.Errorf("libssl.so.3 ≠ libcrypto.so.3 should be a new finding, got %d", len(got))
		}
	})

	t.Run("write then read round-trip", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "baseline.json")
		results := []Finding{
			mk("FIPS-DEP-PYPI-003", "uv.lock", "bcrypt 4.0.1"),
		}
		if err := WriteBaseline(path, "1.9.0", results); err != nil {
			t.Fatal(err)
		}
		b, err := ReadBaseline(path)
		if err != nil {
			t.Fatal(err)
		}
		if b.Version != "1.9.0" {
			t.Errorf("version not preserved: %q", b.Version)
		}
		if len(b.Findings) != 1 || b.Findings[0].Algorithm != "bcrypt 4.0.1" {
			t.Errorf("findings not preserved: %+v", b.Findings)
		}
		_ = os.Remove(path)
	})
}
