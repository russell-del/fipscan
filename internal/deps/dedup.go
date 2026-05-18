package deps

import (
	"path/filepath"
	"strings"

	"github.com/rbuilta/fipscan/internal/findings"
)

// manifestPriority ranks dep manifest files. When the same package
// fires the same rule from multiple files in one project, Dedup keeps
// the finding from the highest-priority manifest. The intuition:
// lockfiles carry the resolved version that's actually installed, so
// they outrank declarative manifests.
//
// Code findings (anything whose rule doesn't begin "FIPS-DEP-") are
// passed through unchanged — file/line context matters for them.
var manifestPriority = map[string]int{
	// Python — lockfiles outrank declarative manifests.
	"uv.lock":          50,
	"poetry.lock":      40,
	"Pipfile.lock":     30,
	"pyproject.toml":   20,
	"requirements.txt": 10,
	// Node — same logic.
	"yarn.lock":         20,
	"package-lock.json": 10,
	// Ecosystems with a single manifest format (Go, Maven, NuGet,
	// Cargo, RubyGems, Composer) never collide so priority is moot
	// but we keep them listed for documentation.
	"go.mod":             10,
	"pom.xml":            10,
	"build.gradle":       10,
	"build.gradle.kts":   10,
	"libs.versions.toml": 20, // Authoritative source for projects using Version Catalogs
	"Cargo.lock":         10,
	"Gemfile.lock":       10,
	"composer.lock":      10,
}

// Dedup collapses duplicate dependency findings: for each (rule,
// package-name) pair, only the finding from the highest-priority
// manifest is kept. Code findings are returned unchanged.
//
// Order of input findings is preserved for kept entries — when a
// later finding outranks an earlier one, it replaces the earlier one
// in place so output position is stable.
func Dedup(in []findings.Finding) []findings.Finding {
	type key struct{ Rule, Pkg string }

	// best tracks, for each dep-finding key, the index of the
	// currently-kept finding in `out`.
	best := map[key]int{}
	out := make([]findings.Finding, 0, len(in))

	for _, f := range in {
		if !strings.HasPrefix(f.Rule, "FIPS-DEP-") {
			out = append(out, f)
			continue
		}
		k := key{Rule: f.Rule, Pkg: depPackageName(f.Algorithm)}
		if existing, seen := best[k]; seen {
			if manifestPriority[filepath.Base(f.File)] >
				manifestPriority[filepath.Base(out[existing].File)] {
				out[existing] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}

// depPackageName extracts the package name from a finding's Algorithm
// field. Dep findings format Algorithm as "<name> <version>" (or just
// "<name>" if the manifest didn't pin a version).
func depPackageName(algo string) string {
	if i := strings.Index(algo, " "); i > 0 {
		return algo[:i]
	}
	return algo
}
