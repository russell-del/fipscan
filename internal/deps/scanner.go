package deps

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/rbuilta/fipscan/internal/findings"
)

type parserFunc func(path string) ([]ParsedDep, error)

type ecosystemSpec struct {
	Ecosystem string
	Display   string
	Parser    parserFunc
}

// exactMatchers maps a literal filename to its ecosystem + parser.
var exactMatchers = map[string]ecosystemSpec{
	"go.mod":            {"go", "Go modules", parseGoMod},
	"package-lock.json": {"npm", "npm", parsePackageLock},
	"yarn.lock":         {"npm", "npm", parseYarnLock},
	"Pipfile.lock":      {"pypi", "PyPI", parsePipfileLock},
	"pom.xml":           {"maven", "Maven", parsePomXml},
	"pyproject.toml":    {"pypi", "PyPI", parsePyprojectToml},
	"poetry.lock":       {"pypi", "PyPI", parsePoetryLock},
	"uv.lock":           {"pypi", "PyPI", parseUvLock},
	"Cargo.lock":        {"cargo", "Cargo", parseCargoLock},
	"Gemfile.lock":      {"rubygems", "RubyGems", parseGemfileLock},
	"composer.lock":     {"composer", "Composer", parseComposerLock},
	"build.gradle":      {"maven", "Maven (Gradle)", parseGradle},
	"build.gradle.kts":  {"maven", "Maven (Gradle)", parseGradle},
	"libs.versions.toml": {"maven", "Maven (Gradle catalog)", parseGradleVersionCatalog},
}

// suffixMatchers covers extension-based matches (where the filename varies).
var suffixMatchers = []struct {
	Suffix string
	Spec   ecosystemSpec
}{
	{".csproj", ecosystemSpec{"nuget", "NuGet", parseCsproj}},
}

func isRequirementsFile(name string) bool {
	if !strings.HasSuffix(name, ".txt") {
		return false
	}
	if name == "requirements.txt" {
		return true
	}
	if strings.HasPrefix(name, "requirements-") {
		return true
	}
	if strings.HasSuffix(name, "-requirements.txt") {
		return true
	}
	return false
}

var requirementsSpec = ecosystemSpec{"pypi", "PyPI", parseRequirementsTxt}

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"dist":         true,
	"build":        true,
	"target":       true,
	"bin":          true,
	"obj":          true,
}

// Options control filtering applied during ScanPath.
type Options struct {
	ExcludePrefixes []string
}

// ScanPath walks root, dispatches each recognised manifest to its parser,
// and emits findings for any dependency whose package name appears in the
// FIPS-relevance catalog.
func ScanPath(root string, opts Options) ([]findings.Finding, error) {
	var results []findings.Finding

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if excluded(path, root, opts.ExcludePrefixes) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(path, root, opts.ExcludePrefixes) {
			return nil
		}
		spec, ok := matchManifest(d.Name())
		if !ok {
			return nil
		}
		parsed, parseErr := spec.Parser(path)
		if parseErr != nil {
			// Best-effort: skip unparseable manifests but don't abort the scan.
			return nil
		}
		for _, dep := range parsed {
			matches := Lookup(spec.Ecosystem, dep.Name, dep.Version)
			if len(matches) == 0 {
				continue
			}
			display := dep.Name
			if dep.Version != "" {
				display = dep.Name + " " + dep.Version
			}
			for _, entry := range matches {
				results = append(results, findings.Finding{
					File:        path,
					Line:        dep.Line,
					Algorithm:   display,
					Language:    spec.Display,
					Severity:    findings.Severity(entry.Severity),
					Snippet:     dep.Snippet,
					Rule:        entry.RuleID,
					Remediation: entry.Reason + " " + entry.Remediation,
					Reference:   entry.Reference,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return results, nil
}

func excluded(path, root string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, p := range prefixes {
		p = strings.TrimSuffix(p, "/")
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

func matchManifest(name string) (ecosystemSpec, bool) {
	if s, ok := exactMatchers[name]; ok {
		return s, true
	}
	if isRequirementsFile(name) {
		return requirementsSpec, true
	}
	for _, sm := range suffixMatchers {
		if strings.HasSuffix(name, sm.Suffix) {
			return sm.Spec, true
		}
	}
	return ecosystemSpec{}, false
}
