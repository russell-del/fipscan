package findings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyWaivers(t *testing.T) {
	mk := func(rule, file string, line int) Finding {
		return Finding{Rule: rule, File: file, Line: line, Severity: SeverityHigh, Algorithm: "MD5"}
	}

	dir := t.TempDir()

	t.Run("same-line waiver with matching rule suppresses", func(t *testing.T) {
		path := filepath.Join(dir, "py-same-line.py")
		os.WriteFile(path, []byte(`import hashlib
h = hashlib.md5(x)  # fipscan:waive FIPS-HASH-001 reason="legacy compat"
`), 0o644)
		kept, waived := ApplyWaivers([]Finding{mk("FIPS-HASH-001", path, 2)})
		if len(kept) != 0 {
			t.Errorf("expected finding to be waived, %d kept", len(kept))
		}
		if len(waived) != 1 {
			t.Errorf("expected 1 waived, got %d", len(waived))
		}
	})

	t.Run("line-above waiver also matches", func(t *testing.T) {
		path := filepath.Join(dir, "go-line-above.go")
		os.WriteFile(path, []byte(`package x
// fipscan:waive FIPS-HASH-001 reason="approved"
h := md5.Sum(data)
`), 0o644)
		kept, waived := ApplyWaivers([]Finding{mk("FIPS-HASH-001", path, 3)})
		if len(kept) != 0 || len(waived) != 1 {
			t.Errorf("expected line-above waiver to match; kept=%d waived=%d", len(kept), len(waived))
		}
	})

	t.Run("wildcard waiver suppresses anything on the line", func(t *testing.T) {
		path := filepath.Join(dir, "wild.py")
		os.WriteFile(path, []byte(`h = hashlib.md5(x)  # fipscan:waive *
`), 0o644)
		kept, waived := ApplyWaivers([]Finding{mk("FIPS-HASH-001", path, 1)})
		if len(kept) != 0 || len(waived) != 1 {
			t.Errorf("wildcard should waive; kept=%d waived=%d", len(kept), len(waived))
		}
	})

	t.Run("waiver for a different rule does NOT suppress", func(t *testing.T) {
		path := filepath.Join(dir, "wrong.go")
		os.WriteFile(path, []byte(`// fipscan:waive FIPS-CIPHER-001 reason="DES is intentional"
h := md5.Sum(data)
`), 0o644)
		kept, waived := ApplyWaivers([]Finding{mk("FIPS-HASH-001", path, 2)})
		if len(kept) != 1 || len(waived) != 0 {
			t.Errorf("rule mismatch should NOT suppress; kept=%d waived=%d", len(kept), len(waived))
		}
	})

	t.Run("findings with no file path pass through", func(t *testing.T) {
		f := Finding{Rule: "FIPS-CONT-POSTURE-001", File: "alpine:3.19", Line: 1}
		kept, waived := ApplyWaivers([]Finding{f})
		if len(kept) != 1 || len(waived) != 0 {
			t.Errorf("container findings must pass through; kept=%d waived=%d", len(kept), len(waived))
		}
	})

	t.Run("multiple findings on a file are evaluated independently", func(t *testing.T) {
		path := filepath.Join(dir, "multi.py")
		os.WriteFile(path, []byte(`# line 1 — plain
import hashlib                                       # line 2
hashlib.md5(x)  # fipscan:waive FIPS-HASH-001        # line 3 (waived)
hashlib.sha1(x)                                      # line 4 (kept)
hashlib.md5(y)                                       # line 5 (kept, no nearby waiver)
`), 0o644)
		in := []Finding{
			mk("FIPS-HASH-001", path, 3),
			mk("FIPS-HASH-002", path, 4),
			mk("FIPS-HASH-001", path, 5),
		}
		kept, waived := ApplyWaivers(in)
		if len(kept) != 2 || len(waived) != 1 {
			t.Errorf("expected 2 kept + 1 waived, got kept=%d waived=%d", len(kept), len(waived))
		}
	})

	t.Run("reason is captured", func(t *testing.T) {
		path := filepath.Join(dir, "reason.py")
		os.WriteFile(path, []byte(`# fipscan:waive FIPS-HASH-001 reason="ATO approved"
hashlib.md5(x)
`), 0o644)
		// Inspect via the regex directly since ApplyWaivers doesn't
		// surface reasons in the kept/waived splits — that's fine,
		// the reason is for human review in the source code.
		ms := waiverRE.FindAllStringSubmatch("# fipscan:waive FIPS-HASH-001 reason=\"ATO approved\"", -1)
		if len(ms) != 1 || ms[0][2] != "ATO approved" {
			t.Errorf("reason not captured: %+v", ms)
		}
	})
}
