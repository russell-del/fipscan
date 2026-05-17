package deps

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a SemVer-ish three-component version used to evaluate
// catalog AffectedVersions constraints.
//
// Pragmatic limitations (documented intentionally):
//   - Only major.minor.patch is parsed. Anything after the version
//     proper (SemVer pre-release `-rc.1`, build metadata `+build.7`,
//     distro release `-11.el9`, Alpine `-r1`) is truncated.
//   - This means a constraint `>=1.0.0` will match `1.0.0-rc.1`.
//     Acceptable false-positive direction; catalog entries describe
//     CVE / EOL / FIPS-validation boundaries at major.minor.patch
//     granularity, not pre-release granularity.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion accepts pretty much any version string seen in the wild
// (`1.2.3`, `v1.2.3`, `^1.2.3`, `>=1.2.3`, `==1.2.3`, `1.10.0-r1`,
// `1.10.0-11.el9`) and returns the three-component truncation. Unparsable
// input yields the zero Version.
func ParseVersion(s string) Version {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "v=<>~^!= ")
	// Truncate at the first character that isn't a digit or '.'.
	cut := len(s)
	for i, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' {
			cut = i
			break
		}
	}
	s = strings.TrimRight(s[:cut], ".")
	if s == "" {
		return Version{}
	}
	parts := strings.Split(s, ".")
	var v Version
	if len(parts) > 0 {
		v.Major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		v.Minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		v.Patch, _ = strconv.Atoi(parts[2])
	}
	return v
}

// Compare returns -1, 0, +1 as a < b, a == b, a > b (component-wise).
func Compare(a, b Version) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	return cmpInt(a.Patch, b.Patch)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ConstraintOp is the relational operator in a single constraint clause.
type ConstraintOp int

const (
	OpAny ConstraintOp = iota
	OpLT
	OpLE
	OpGT
	OpGE
	OpEQ
	OpNE
)

// Constraint is one relational clause, e.g. `<1.3.0`. A ConstraintSet
// is the intersection of its clauses — all must match.
type Constraint struct {
	Op  ConstraintOp
	Ver Version
}

// ParseConstraints parses a comma-separated constraint spec like
// `>=1.0,<2.0`. Empty input returns nil — equivalent to "matches any".
//
// Accepted operators: `<`, `<=`, `>`, `>=`, `==`, `=`, `!=`. A bare
// version is treated as exact match (`==`).
func ParseConstraints(s string) ([]Constraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []Constraint
	for _, part := range strings.Split(s, ",") {
		c, err := parseSingleConstraint(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func parseSingleConstraint(s string) (Constraint, error) {
	if s == "" {
		return Constraint{}, fmt.Errorf("empty constraint")
	}
	var op ConstraintOp
	switch {
	case strings.HasPrefix(s, "<="):
		op = OpLE
		s = s[2:]
	case strings.HasPrefix(s, ">="):
		op = OpGE
		s = s[2:]
	case strings.HasPrefix(s, "!="):
		op = OpNE
		s = s[2:]
	case strings.HasPrefix(s, "=="):
		op = OpEQ
		s = s[2:]
	case strings.HasPrefix(s, "<"):
		op = OpLT
		s = s[1:]
	case strings.HasPrefix(s, ">"):
		op = OpGT
		s = s[1:]
	case strings.HasPrefix(s, "="):
		op = OpEQ
		s = s[1:]
	default:
		op = OpEQ
	}
	return Constraint{Op: op, Ver: ParseVersion(strings.TrimSpace(s))}, nil
}

// Matches reports whether v satisfies c.
func (c Constraint) Matches(v Version) bool {
	cmp := Compare(v, c.Ver)
	switch c.Op {
	case OpAny:
		return true
	case OpLT:
		return cmp < 0
	case OpLE:
		return cmp <= 0
	case OpGT:
		return cmp > 0
	case OpGE:
		return cmp >= 0
	case OpEQ:
		return cmp == 0
	case OpNE:
		return cmp != 0
	}
	return false
}

// MatchAll returns true when v satisfies every clause (intersection).
// A nil / empty constraint set is treated as "matches anything" so
// existing catalog entries without an AffectedVersions field continue
// to work unchanged.
func MatchAll(cs []Constraint, v Version) bool {
	for _, c := range cs {
		if !c.Matches(v) {
			return false
		}
	}
	return true
}
