package findings

import (
	"bufio"
	"os"
	"regexp"
)

// Waiver represents an in-source request to suppress a finding. Parsed
// from comments containing `fipscan:waive <rule-id> reason="..."`
// (with the rule id, optional reason, comment syntax irrelevant).
type Waiver struct {
	Rule   string // matched rule ID, or "*" for wildcard
	Reason string // optional explanation
	File   string // file the waiver lives in
	Line   int    // 1-based line of the waiver
}

// waiverRE matches:
//
//	fipscan:waive FIPS-HASH-001
//	fipscan:waive FIPS-HASH-001 reason="approved for legacy compat"
//	fipscan:waive *               reason="this whole line is intentional"
//
// We don't constrain the surrounding comment syntax — the marker is
// distinctive enough that false positives don't occur in practice.
// Works equally well in //, #, /*…*/, ' ' (Python docstring) contexts.
var waiverRE = regexp.MustCompile(
	`fipscan:waive\s+(\*|[A-Z][A-Z0-9-]+)(?:\s+reason="([^"]*)")?`)

// ApplyWaivers splits findings into (kept, waived) based on inline
// `fipscan:waive` markers in the corresponding source files.
//
// A waiver applies when:
//   - It appears on the same line as the finding, OR the line above.
//   - The waiver rule equals the finding rule exactly, OR the waiver
//     uses the wildcard "*".
//
// Findings whose File can't be read (container image refs, missing
// files) are passed through unchanged.
func ApplyWaivers(in []Finding) (kept, waived []Finding) {
	type fileWaivers map[int][]Waiver
	cache := map[string]fileWaivers{}

	loadFile := func(path string) fileWaivers {
		if w, ok := cache[path]; ok {
			return w
		}
		out := fileWaivers{}
		f, err := os.Open(path)
		if err != nil {
			cache[path] = out
			return out
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		ln := 0
		for s.Scan() {
			ln++
			for _, m := range waiverRE.FindAllStringSubmatch(s.Text(), -1) {
				out[ln] = append(out[ln], Waiver{
					Rule:   m[1],
					Reason: m[2],
					File:   path,
					Line:   ln,
				})
			}
		}
		cache[path] = out
		return out
	}

	for _, f := range in {
		if f.File == "" || f.Line == 0 {
			kept = append(kept, f)
			continue
		}
		ws := loadFile(f.File)
		if len(ws) == 0 {
			kept = append(kept, f)
			continue
		}
		matched := false
		for _, ln := range []int{f.Line, f.Line - 1} {
			for _, w := range ws[ln] {
				if w.Rule == "*" || w.Rule == f.Rule {
					waived = append(waived, f)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			kept = append(kept, f)
		}
	}
	return kept, waived
}
