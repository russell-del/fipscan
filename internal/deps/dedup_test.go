package deps

import (
	"testing"

	"github.com/russell-del/fipscan/internal/findings"
)

func TestDedup(t *testing.T) {
	mk := func(file, rule, algo string, sev findings.Severity) findings.Finding {
		return findings.Finding{File: file, Rule: rule, Algorithm: algo, Severity: sev}
	}

	t.Run("uv.lock outranks pyproject.toml for same package+rule", func(t *testing.T) {
		in := []findings.Finding{
			mk("project/pyproject.toml", "FIPS-DEP-PYPI-003", "bcrypt", "HIGH"),
			mk("project/uv.lock", "FIPS-DEP-PYPI-003", "bcrypt 5.0.0", "HIGH"),
		}
		out := Dedup(in)
		if len(out) != 1 {
			t.Fatalf("want 1 finding, got %d", len(out))
		}
		if out[0].File != "project/uv.lock" {
			t.Errorf("kept the wrong manifest: %q", out[0].File)
		}
	})

	t.Run("different rules for same package are kept (range split)", func(t *testing.T) {
		in := []findings.Finding{
			mk("requirements.txt", "FIPS-DEP-PYPI-006-CVE", "cryptography 30.0.0", "HIGH"),
			mk("requirements.txt", "FIPS-DEP-PYPI-006", "cryptography 30.0.0", "MEDIUM"),
		}
		out := Dedup(in)
		if len(out) != 2 {
			t.Errorf("different rules should both survive; got %d", len(out))
		}
	})

	t.Run("different packages with same rule both kept", func(t *testing.T) {
		in := []findings.Finding{
			mk("requirements.txt", "FIPS-DEP-PYPI-003", "bcrypt 4.0.1", "HIGH"),
			mk("requirements.txt", "FIPS-DEP-PYPI-003", "passlib 1.7.4", "HIGH"),
		}
		out := Dedup(in)
		if len(out) != 2 {
			t.Errorf("different packages should both survive; got %d", len(out))
		}
	})

	t.Run("code findings pass through untouched", func(t *testing.T) {
		in := []findings.Finding{
			mk("src/a.go", "FIPS-HASH-001", "MD5", "HIGH"),
			mk("src/b.go", "FIPS-HASH-001", "MD5", "HIGH"),
		}
		out := Dedup(in)
		if len(out) != 2 {
			t.Errorf("code findings must not be deduped (file/line context matters); got %d", len(out))
		}
	})

	t.Run("preserves order for kept findings", func(t *testing.T) {
		in := []findings.Finding{
			mk("requirements.txt", "FIPS-DEP-PYPI-003", "bcrypt 4.0.1", "HIGH"),
			mk("requirements.txt", "FIPS-DEP-PYPI-001", "pycrypto 2.6.1", "HIGH"),
			mk("uv.lock", "FIPS-DEP-PYPI-003", "bcrypt 5.0.0", "HIGH"),
		}
		out := Dedup(in)
		if len(out) != 2 {
			t.Fatalf("want 2, got %d", len(out))
		}
		// bcrypt entry should be replaced (now from uv.lock) but stay at index 0
		if out[0].File != "uv.lock" || out[0].Algorithm != "bcrypt 5.0.0" {
			t.Errorf("expected uv.lock bcrypt at index 0, got %+v", out[0])
		}
		if out[1].File != "requirements.txt" || out[1].Algorithm != "pycrypto 2.6.1" {
			t.Errorf("expected requirements.txt pycrypto at index 1, got %+v", out[1])
		}
	})
}
