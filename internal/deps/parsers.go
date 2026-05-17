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
// [[package]]-array TOML lockfiles — uv.lock, poetry.lock, Cargo.lock
//
// All three formats serialise the resolved dependency set as a sequence
// of TOML arrays-of-tables:
//
//   [[package]]
//   name = "django"
//   version = "4.2.7"
//
//   [[package]]
//   name = "requests"
//   version = "2.31.0"
//
// poetry.lock additionally nests sub-sections like [package.dependencies]
// inside each [[package]] block; we ignore those (we only need name +
// version per package, not the dep graph). Sticking to section-aware
// line scanning keeps the binary dep-free.
// ============================================================================

var tomlKVRE = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"`)

func parsePackageArrayTOML(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	var cur ParsedDep
	curStartLine := 0
	inPackage := false
	inPackageSubsection := false

	flush := func() {
		if cur.Name != "" {
			cur.Line = curStartLine
			if cur.Snippet == "" {
				cur.Snippet = cur.Name + " " + cur.Version
			}
			out = append(out, cur)
		}
		cur = ParsedDep{}
		curStartLine = 0
	}

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// [[package]] — array-of-tables, opens a new package block.
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			section := strings.TrimSpace(strings.Trim(trimmed, "[]"))
			flush()
			if section == "package" {
				inPackage = true
				inPackageSubsection = false
				curStartLine = lineNum
			} else {
				inPackage = false
				inPackageSubsection = false
			}
			continue
		}
		// [section] — single table. poetry.lock has [package.dependencies]
		// and [package.extras] nested under the current [[package]] which
		// we want to skip without flushing.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section := strings.TrimSpace(strings.Trim(trimmed, "[]"))
			if inPackage && strings.HasPrefix(section, "package.") {
				inPackageSubsection = true
				continue
			}
			flush()
			inPackage = false
			inPackageSubsection = false
			continue
		}

		if !inPackage || inPackageSubsection {
			continue
		}
		m := tomlKVRE.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		switch m[1] {
		case "name":
			cur.Name = strings.ToLower(m[2])
			cur.Snippet = trimmed
		case "version":
			cur.Version = m[2]
		}
	}
	flush()
	return out, s.Err()
}

// Thin wrappers exist so scanner.go can register each filename with its
// own ecosystem string ("pypi" vs "cargo"). The parsing is identical.
func parseUvLock(path string) ([]ParsedDep, error)     { return parsePackageArrayTOML(path) }
func parsePoetryLock(path string) ([]ParsedDep, error) { return parsePackageArrayTOML(path) }
func parseCargoLock(path string) ([]ParsedDep, error)  { return parsePackageArrayTOML(path) }

// ============================================================================
// yarn.lock — Yarn classic / berry lockfile (custom format, YAML-ish)
//
// Top-level entries look like:
//   "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.0":
//     version "7.16.7"
//     resolved "..."
//
//   acorn@^8.4.1:
//     version "8.7.0"
//
// We capture the package name from the FIRST spec on the descriptor
// line and the resolved version from the indented `version` line.
// ============================================================================

var (
	yarnTopRE     = regexp.MustCompile(`^"?(@?[A-Za-z0-9._/-]+)@`)
	yarnVersionRE = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)
)

func parseYarnLock(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	var cur ParsedDep
	inEntry := false

	flush := func() {
		if cur.Name != "" {
			if cur.Snippet == "" {
				cur.Snippet = cur.Name + " " + cur.Version
			}
			out = append(out, cur)
		}
		cur = ParsedDep{}
		inEntry = false
	}

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// Indented line — only `version "..."` is interesting.
		if raw[0] == ' ' || raw[0] == '\t' {
			if !inEntry {
				continue
			}
			if m := yarnVersionRE.FindStringSubmatch(raw); m != nil {
				cur.Version = m[1]
			}
			continue
		}
		// Top-level descriptor line.
		flush()
		if m := yarnTopRE.FindStringSubmatch(raw); m != nil {
			cur.Name = strings.ToLower(m[1])
			cur.Line = lineNum
			cur.Snippet = strings.TrimSpace(raw)
			inEntry = true
		}
	}
	flush()
	return out, s.Err()
}

// ============================================================================
// Gemfile.lock — Bundler lockfile (Ruby)
//
// Format:
//
//   GEM
//     remote: https://rubygems.org/
//     specs:
//       bcrypt (3.1.20)
//       rails (7.1.2)
//         actioncable (= 7.1.2)
//
//   PLATFORMS
//     ruby
//
//   DEPENDENCIES
//     bcrypt
//     rails (~> 7.1)
//
// Installed gems live at exactly 4-space indent inside any `specs:`
// block (GEM, GIT, PATH all use the same shape). Transitive deps
// listed under a gem are at 6+ spaces — we skip them via the regex
// anchor.
// ============================================================================

var gemfileLockRE = regexp.MustCompile(`^    ([a-z][a-z0-9_.-]*)\s+\(([^)]+)\)\s*$`)

func parseGemfileLock(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		m := gemfileLockRE.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		out = append(out, ParsedDep{
			Name:    strings.ToLower(m[1]),
			Version: m[2],
			Line:    lineNum,
			Snippet: strings.TrimSpace(raw),
		})
	}
	return out, s.Err()
}

// ============================================================================
// composer.lock — Composer lockfile (PHP)
//
// JSON. Top-level `packages` (runtime) and `packages-dev` arrays each
// contain objects with `name` (vendor/package) and `version`.
// ============================================================================

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

func parseComposerLock(path string) ([]ParsedDep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cl composerLock
	if err := json.Unmarshal(data, &cl); err != nil {
		return nil, err
	}
	var out []ParsedDep
	for _, group := range [][]composerPkg{cl.Packages, cl.PackagesDev} {
		for _, p := range group {
			if p.Name == "" {
				continue
			}
			out = append(out, ParsedDep{
				Name:    strings.ToLower(p.Name),
				Version: strings.TrimPrefix(p.Version, "v"),
				Line:    findLineFor(data, `"name": "`+p.Name+`"`),
				Snippet: p.Name + " " + p.Version,
			})
		}
	}
	return out, nil
}

// ============================================================================
// build.gradle / build.gradle.kts — Gradle build scripts (Groovy + Kotlin DSL)
//
// We match short-notation dependency declarations:
//
//   implementation 'org.bouncycastle:bcprov-jdk18on:1.77'
//   api "org.bouncycastle:bcpkix-jdk18on:1.77"
//   implementation("org.mindrot:jbcrypt:0.4")   // Kotlin DSL paren style
//
// Configuration names covered: implementation, api, compileOnly,
// runtimeOnly, testImplementation, testRuntimeOnly,
// androidTestImplementation, kapt, annotationProcessor, classpath,
// compile (legacy), testCompile (legacy).
//
// Not supported in v1.6 (uncommon enough that misses are acceptable;
// add when a customer reports it):
//   - Map notation: `implementation group: 'X', name: 'Y', version: 'Z'`
//   - Variable substitution: `implementation "${var}:..."`
//   - File / project deps (we naturally skip these — they don't match
//     the group:artifact:version regex)
// ============================================================================

// gradleConfigRE matches a line that contains a dep-configuration
// keyword. gradleCoordRE matches a quoted Maven coordinate anywhere
// on the line. Splitting in two passes lets us match wrappers like
// `implementation(platform("group:artifact:version"))` and
// `api(enforcedPlatform("..."))` that a single anchored regex would
// miss.
var (
	gradleConfigRE = regexp.MustCompile(
		`\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|` +
			`testRuntimeOnly|androidTestImplementation|kapt|annotationProcessor|` +
			`classpath|compile|testCompile)\b`)
	gradleCoordRE = regexp.MustCompile(
		`['"]([A-Za-z0-9._-]+):([A-Za-z0-9._-]+):([A-Za-z0-9._+-]+)['"]`)
)

func parseGradle(path string) ([]ParsedDep, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ParsedDep
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for s.Scan() {
		lineNum++
		raw := s.Text()
		trimmed := strings.TrimSpace(raw)
		// Cheap comment skip; doesn't handle multi-line /* */ blocks
		// but those are rare in dep declarations.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		if !gradleConfigRE.MatchString(raw) {
			continue
		}
		m := gradleCoordRE.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1] + ":" + m[2]) // group:artifact, matches pom.xml convention
		out = append(out, ParsedDep{
			Name:    name,
			Version: m[3],
			Line:    lineNum,
			Snippet: strings.TrimSpace(raw),
		})
	}
	return out, s.Err()
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
