package deps

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want Version
	}{
		{"1.2.3", Version{1, 2, 3}},
		{"v1.2.3", Version{1, 2, 3}},
		{"1.10.0-r1", Version{1, 10, 0}},     // Alpine suffix
		{"1.10.0-11.el9", Version{1, 10, 0}}, // RHEL release suffix
		{"3.0.8+abi.7", Version{3, 0, 8}},    // build metadata
		{"1.0.0-rc.1", Version{1, 0, 0}},     // SemVer pre-release truncated
		{">=4.0.0", Version{4, 0, 0}},
		{"^1.2.3", Version{1, 2, 3}},
		{"  v1.2  ", Version{1, 2, 0}},
		{"", Version{0, 0, 0}},
		{"not-a-version", Version{0, 0, 0}},
	}
	for _, c := range cases {
		if got := ParseVersion(c.in); got != c.want {
			t.Errorf("ParseVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b Version
		want int
	}{
		{Version{1, 0, 0}, Version{2, 0, 0}, -1},
		{Version{2, 0, 0}, Version{1, 0, 0}, 1},
		{Version{1, 0, 0}, Version{1, 0, 0}, 0},
		{Version{1, 2, 3}, Version{1, 2, 4}, -1},
		{Version{1, 10, 0}, Version{1, 9, 0}, 1}, // 10 > 9 numerically
		{Version{1, 0, 0}, Version{0, 99, 99}, 1},
	}
	for _, c := range cases {
		got := cmpSign(Compare(c.a, c.b))
		if got != c.want {
			t.Errorf("Compare(%v, %v) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestConstraint(t *testing.T) {
	cases := []struct {
		spec, version string
		want          bool
	}{
		// node-forge CVE boundary
		{"<1.3.0", "1.2.5", true},
		{"<1.3.0", "1.3.0", false},
		{"<1.3.0", "1.3.1", false},
		// cryptography CVE-2023-23931 boundary
		{">=39.0.1", "39.0.0", false},
		{">=39.0.1", "39.0.1", true},
		{">=39.0.1", "39.1.0", true},
		// intersection
		{">=1.0,<2.0", "1.5.0", true},
		{">=1.0,<2.0", "2.0.0", false},
		{">=1.0,<2.0", "0.9.0", false},
		// edge cases
		{"", "1.0.0", true}, // empty = match anything
		{"==1.2.3", "1.2.3", true},
		{"==1.2.3", "1.2.4", false},
		{"!=1.2.3", "1.2.3", false},
		{"!=1.2.3", "1.2.4", true},
		// bare version is exact match
		{"4.2.7", "4.2.7", true},
		{"4.2.7", "4.2.8", false},
	}
	for _, c := range cases {
		cs, err := ParseConstraints(c.spec)
		if err != nil {
			t.Fatalf("ParseConstraints(%q): %v", c.spec, err)
		}
		v := ParseVersion(c.version)
		if got := MatchAll(cs, v); got != c.want {
			t.Errorf("ParseConstraints(%q).Matches(%q) = %v, want %v",
				c.spec, c.version, got, c.want)
		}
	}
}

func cmpSign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
