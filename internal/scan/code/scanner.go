package code

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rbuilta/fipscan/internal/findings"
)

var languageByExt = map[string]string{
	".py":    "Python",
	".go":    "Go",
	".java":  "Java",
	".kt":    "Kotlin",
	".kts":   "Kotlin",
	".scala": "Scala",
	".js":    "JavaScript",
	".ts":    "TypeScript",
	".mjs":   "JavaScript",
	".cjs":   "JavaScript",
	".cs":    "C#",
	".rb":    "Ruby",
	".php":   "PHP",
	".rs":    "Rust",
	".swift": "Swift",
	".c":     "C/C++",
	".cc":    "C/C++",
	".cpp":   "C/C++",
	".cxx":   "C/C++",
	".h":     "C/C++",
	".hh":    "C/C++",
	".hpp":   "C/C++",
	".hxx":   "C/C++",
}

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

const (
	maxFileBytes = 5 * 1024 * 1024 // skip anything over 5 MiB (likely vendored / minified)
	maxLineBytes = 1 * 1024 * 1024
)

// Options control filtering applied during ScanPath.
type Options struct {
	// ExcludePrefixes is a list of repo-relative paths to skip. Each value
	// matches either an exact file path or any path under that directory
	// (i.e. "testdata" excludes "testdata/foo.py").
	ExcludePrefixes []string
}

// ScanPath walks root, applies the pattern set to every supported source
// file it encounters, and returns the collected findings.
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
		ext := strings.ToLower(filepath.Ext(path))
		lang, ok := languageByExt[ext]
		if !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}
		fileFindings, err := scanFile(path, ext, lang)
		if err != nil {
			return nil
		}
		results = append(results, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return results, nil
}

// excluded returns true when path is the same as, or rooted under, any of
// the prefixes (each expressed as a repo-relative slash-separated path).
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

func scanFile(path, ext, lang string) ([]findings.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []findings.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if isCommentOnly(trimmed, ext) {
			continue
		}
		for _, p := range Patterns {
			if !langMatches(p, ext) {
				continue
			}
			loc := p.Regex.FindStringIndex(line)
			if loc == nil {
				continue
			}
			results = append(results, findings.Finding{
				File:        path,
				Line:        lineNum,
				Column:      loc[0] + 1,
				Algorithm:   p.Algorithm,
				Language:    lang,
				Severity:    findings.Severity(p.Severity),
				Snippet:     truncate(strings.TrimSpace(line), 200),
				Rule:        p.Rule,
				Remediation: p.Remediation,
				Reference:   p.Reference,
			})
		}
	}
	return results, scanner.Err()
}

func langMatches(p Pattern, ext string) bool {
	for _, e := range p.Languages {
		if e == ext {
			return true
		}
	}
	return false
}

func isCommentOnly(line, ext string) bool {
	if line == "" {
		return true
	}
	switch ext {
	case ".py", ".rb":
		return strings.HasPrefix(line, "#")
	case ".php":
		return strings.HasPrefix(line, "//") ||
			strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "/*")
	case ".go", ".java", ".kt", ".kts", ".scala",
		".js", ".ts", ".mjs", ".cjs", ".cs",
		".rs", ".swift",
		".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
