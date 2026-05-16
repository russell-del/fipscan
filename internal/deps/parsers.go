package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"regexp"
	"strings"
)

// ParsedDep is one dependency extracted from a manifest, before catalog
// lookup. Name is canonical (lowercased) for case-insensitive ecosystems.
type ParsedDep struct {
	Name    string
	Version string
	Line    int
	Snippet string
}

// findLineFor returns the 1-based line number where needle first appears
// in data, or 1 if not found. Used by JSON/XML parsers to attribute a
// dependency back to a source line without writing a tracking parser.
func findLineFor(data []byte, needle string) int {
	idx := bytes.Index(data, []byte(needle))
	if idx < 0 {
		return 1
	}
	return bytes.Count(data[:idx], []byte("\n")) + 1
}

// ============================================================================
// requirements.txt — pip / setuptools install requirements
// ============================================================================

var reqLineRE = regexp.MustCompile(
	`^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:([=<>!~]=?)\s*([A-Za-z0-9.\-+*]+))?`)

func parseRequirementsTxt(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	s := bufio.NewScanner(f)
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// pip directives (-r, -e, --index-url, etc.)
		if strings.HasPrefix(line, "-") {
			continue
		}
		// VCS / URL deps (too varied to parse reliably for v0.3)
		if strings.Contains(line, "://") || strings.HasPrefix(line, "git+") {
			continue
		}
		// Strip env markers: "package==1.0; python_version<'3.10'"
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := reqLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, ParsedDep{
			Name:    strings.ToLower(m[1]),
			Version: m[3],
			Line:    lineNum,
			Snippet: strings.TrimSpace(raw),
		})
	}
	return out, s.Err()
}

// ============================================================================
// pyproject.toml — PEP 621 [project] dependencies + Poetry sections
//
// Two declaration styles in the wild:
//
//   [project]
//   dependencies = ["django>=4.2", "requests"]
//
//   [tool.poetry.dependencies]
//   django = "^4.2"
//   requests = "*"
//
// We do a section-aware line scan rather than pulling in a TOML parser —
// keeps the binary dependency-free and covers >95% of real manifests.
// ============================================================================

var (
	pep621EntryRE   = regexp.MustCompile(`"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([=<>!~]=?[^"]*)?"`)
	poetryDepLineRE = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"`)
)

func parsePyprojectToml(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	s := bufio.NewScanner(f)
	section := ""
	inPEP621Deps := false
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(strings.Trim(trimmed, "[]"))
			inPEP621Deps = false
			continue
		}
		if section == "project" {
			if strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "= [") {
				inPEP621Deps = true
				// Some files put the first entry on the same line.
				for _, m := range pep621EntryRE.FindAllStringSubmatch(trimmed, -1) {
					out = append(out, ParsedDep{
						Name:    strings.ToLower(m[1]),
						Version: cleanVersionSpec(m[2]),
						Line:    lineNum,
						Snippet: strings.TrimSpace(raw),
					})
				}
				if strings.Contains(trimmed, "]") {
					inPEP621Deps = false
				}
				continue
			}
			if inPEP621Deps {
				if strings.HasPrefix(trimmed, "]") {
					inPEP621Deps = false
					continue
				}
				if m := pep621EntryRE.FindStringSubmatch(trimmed); m != nil {
					out = append(out, ParsedDep{
						Name:    strings.ToLower(m[1]),
						Version: cleanVersionSpec(m[2]),
						Line:    lineNum,
						Snippet: strings.TrimSpace(raw),
					})
				}
			}
		}
		if isPoetryDepsSection(section) {
			if m := poetryDepLineRE.FindStringSubmatch(trimmed); m != nil {
				if strings.EqualFold(m[1], "python") {
					continue
				}
				out = append(out, ParsedDep{
					Name:    strings.ToLower(m[1]),
					Version: cleanPoetrySpec(m[2]),
					Line:    lineNum,
					Snippet: strings.TrimSpace(raw),
				})
			}
		}
	}
	return out, s.Err()
}

func isPoetryDepsSection(s string) bool {
	if s == "tool.poetry.dependencies" || s == "tool.poetry.dev-dependencies" {
		return true
	}
	return strings.HasPrefix(s, "tool.poetry.group.") && strings.HasSuffix(s, ".dependencies")
}

func cleanVersionSpec(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimLeft(s, "=<>!~ ")
}

func cleanPoetrySpec(s string) string {
	return strings.TrimLeft(s, "^~>=< ")
}

// ============================================================================
// Pipfile.lock — pipenv lockfile (JSON)
// ============================================================================

type pipfileLockEntry struct {
	Version string `json:"version"`
}

type pipfileLock struct {
	Default map[string]pipfileLockEntry `json:"default"`
	Develop map[string]pipfileLockEntry `json:"develop"`
}

func parsePipfileLock(path string) ([]ParsedDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf pipfileLock
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	var out []ParsedDep
	for _, group := range []map[string]pipfileLockEntry{pf.Default, pf.Develop} {
		for name, info := range group {
			out = append(out, ParsedDep{
				Name:    strings.ToLower(name),
				Version: strings.TrimPrefix(info.Version, "=="),
				Line:    findLineFor(data, `"`+name+`"`),
				Snippet: name + " " + info.Version,
			})
		}
	}
	return out, nil
}

// ============================================================================
// go.mod — Go modules manifest
// ============================================================================

func parseGoMod(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	s := bufio.NewScanner(f)
	lineNum := 0
	inRequireBlock := false
	for s.Scan() {
		lineNum++
		raw := s.Text()
		trimmed := strings.TrimSpace(raw)
		if i := strings.Index(trimmed, "//"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && trimmed == ")" {
			inRequireBlock = false
			continue
		}
		var fields []string
		switch {
		case inRequireBlock:
			fields = strings.Fields(trimmed)
		case strings.HasPrefix(trimmed, "require "):
			fields = strings.Fields(strings.TrimPrefix(trimmed, "require "))
		default:
			continue
		}
		if len(fields) < 2 {
			continue
		}
		out = append(out, ParsedDep{
			Name:    fields[0],
			Version: fields[1],
			Line:    lineNum,
			Snippet: strings.TrimSpace(raw),
		})
	}
	return out, s.Err()
}

// ============================================================================
// package-lock.json — npm lockfile (v1, v2, v3)
// ============================================================================

type packageLockEntry struct {
	Version string `json:"version"`
}

type packageLock struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`     // v2/v3
	Dependencies    map[string]packageLockEntry `json:"dependencies"` // v1
}

func parsePackageLock(path string) ([]ParsedDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pl packageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, err
	}
	var out []ParsedDep
	if len(pl.Packages) > 0 {
		for key, info := range pl.Packages {
			if key == "" {
				continue // root project
			}
			name := extractNpmPkgName(key)
			if name == "" {
				continue
			}
			out = append(out, ParsedDep{
				Name:    strings.ToLower(name),
				Version: info.Version,
				Line:    findLineFor(data, `"`+key+`"`),
				Snippet: name + " " + info.Version,
			})
		}
	} else {
		for name, info := range pl.Dependencies {
			out = append(out, ParsedDep{
				Name:    strings.ToLower(name),
				Version: info.Version,
				Line:    findLineFor(data, `"`+name+`"`),
				Snippet: name + " " + info.Version,
			})
		}
	}
	return out, nil
}

// extractNpmPkgName turns "node_modules/foo" / "node_modules/@scope/foo" /
// "node_modules/foo/node_modules/bar" into the package name string.
func extractNpmPkgName(key string) string {
	parts := strings.Split(key, "node_modules/")
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "@") {
		seg := strings.SplitN(last, "/", 3)
		if len(seg) >= 2 {
			return seg[0] + "/" + seg[1]
		}
	}
	return strings.SplitN(last, "/", 2)[0]
}

// ============================================================================
// pom.xml — Maven project descriptor
// ============================================================================

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pomDepMgmt struct {
	Dependencies []pomDep `xml:"dependencies>dependency"`
}

type pomProject struct {
	XMLName              xml.Name   `xml:"project"`
	Dependencies         []pomDep   `xml:"dependencies>dependency"`
	DependencyManagement pomDepMgmt `xml:"dependencyManagement"`
}

func parsePomXml(path string) ([]ParsedDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p pomProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	var out []ParsedDep
	addOne := func(d pomDep) {
		if d.GroupID == "" || d.ArtifactID == "" {
			return
		}
		name := strings.ToLower(d.GroupID + ":" + d.ArtifactID)
		out = append(out, ParsedDep{
			Name:    name,
			Version: d.Version,
			Line:    findLineFor(data, "<artifactId>"+d.ArtifactID+"</artifactId>"),
			Snippet: name + " " + d.Version,
		})
	}
	for _, d := range p.Dependencies {
		addOne(d)
	}
	for _, d := range p.DependencyManagement.Dependencies {
		addOne(d)
	}
	return out, nil
}

// ============================================================================
// *.csproj — .NET MSBuild project file
// ============================================================================

type csprojRef struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

type csprojItemGroup struct {
	PackageReferences []csprojRef `xml:"PackageReference"`
}

type csprojProject struct {
	XMLName    xml.Name          `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

func parseCsproj(path string) ([]ParsedDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p csprojProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	var out []ParsedDep
	for _, ig := range p.ItemGroups {
		for _, ref := range ig.PackageReferences {
			if ref.Include == "" {
				continue
			}
			out = append(out, ParsedDep{
				Name:    ref.Include, // canonName lowercases at lookup time
				Version: ref.Version,
				Line:    findLineFor(data, `Include="`+ref.Include+`"`),
				Snippet: ref.Include + " " + ref.Version,
			})
		}
	}
	return out, nil
}
