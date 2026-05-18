package osv

import "testing"

func TestIsCryptoRelevant(t *testing.T) {
	known := map[string]bool{
		"pypi:cryptography": true,
	}
	cases := []struct {
		name string
		v    Vulnerability
		want bool
	}{
		{
			name: "known crypto package always wins",
			v: Vulnerability{
				Summary:  "Buffer overflow in foo",
				Affected: []Affected{{Package: Package{Ecosystem: "PyPI", Name: "cryptography"}}},
			},
			want: true,
		},
		{
			name: "TLS keyword (word-boundaried)",
			v: Vulnerability{
				Summary: "Vulnerability in TLS handshake parsing",
			},
			want: true,
		},
		{
			name: "TLS inside another word — must NOT match",
			v: Vulnerability{
				Summary: "Vulnerability in TLSx parser", // hypothetical, "tlsx" is not "tls"
			},
			want: false,
		},
		{
			name: "X.509 keyword",
			v: Vulnerability{
				Summary: "X.509 certificate parsing bypass",
			},
			want: true,
		},
		{
			name: "padding oracle phrase",
			v: Vulnerability{
				Summary: "Padding oracle attack on CBC implementation",
			},
			want: true,
		},
		{
			name: "completely unrelated CVE — XSS",
			v: Vulnerability{
				Summary: "Stored XSS in user profile page",
			},
			want: false,
		},
		{
			name: "unrelated CVE — SQL injection",
			v: Vulnerability{
				Summary: "SQL injection in search endpoint",
			},
			want: false,
		},
		{
			name: "DoS — must NOT match (no crypto keyword)",
			v: Vulnerability{
				Summary: "Denial of service via large payload",
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.v.IsCryptoRelevant(known); got != c.want {
				t.Errorf("IsCryptoRelevant() = %v, want %v\n  vuln: %+v", got, c.want, c.v)
			}
		})
	}
}

func TestRangesToConstraint(t *testing.T) {
	cases := []struct {
		name      string
		ranges    []Range
		want      string
		encodable bool
	}{
		{
			name: "introduced 0 + fixed → upper bound only",
			ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{
				{Introduced: "0"}, {Fixed: "1.3.0"},
			}}},
			want: "<1.3.0", encodable: true,
		},
		{
			name: "explicit lower + upper",
			ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{
				{Introduced: "2.0.0"}, {Fixed: "2.5.0"},
			}}},
			want: ">=2.0.0,<2.5.0", encodable: true,
		},
		{
			name: "last_affected → <= constraint",
			ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{
				{Introduced: "0"}, {LastAffected: "1.5.0"},
			}}},
			want: "<=1.5.0", encodable: true,
		},
		{
			name: "GIT range type → skipped",
			ranges: []Range{{Type: "GIT", Events: []Event{
				{Introduced: "abc123"},
			}}},
			want: "", encodable: false,
		},
		{
			name: "introduced 0 only (no upper) → would match everything → reject",
			ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{
				{Introduced: "0"},
			}}},
			want: "", encodable: false,
		},
		{
			name:      "empty",
			ranges:    []Range{},
			want:      "",
			encodable: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, encodable := rangesToConstraint(c.ranges)
			if got != c.want || encodable != c.encodable {
				t.Errorf("rangesToConstraint(%+v) = (%q, %v), want (%q, %v)",
					c.ranges, got, encodable, c.want, c.encodable)
			}
		})
	}
}
