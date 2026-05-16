package container

import (
	"bufio"
	"bytes"
	"strings"
)

// Package is a single installed system package picked out of a dpkg or
// apk database. Database is the source (e.g. "dpkg", "apk"); helpful for
// disambiguating package names across distros.
type Package struct {
	Database string
	Name     string
	Version  string
}

// ParseDpkgStatus parses /var/lib/dpkg/status (Debian / Ubuntu).
//
// The file is a series of RFC822-like blocks, one per package, separated
// by blank lines:
//
//	Package: openssl
//	Status: install ok installed
//	Version: 3.0.11-1ubuntu2
//	...
//
// Only blocks whose Status indicates "installed" are returned.
func ParseDpkgStatus(data []byte) []Package {
	var out []Package
	for _, block := range bytes.Split(data, []byte("\n\n")) {
		if len(bytes.TrimSpace(block)) == 0 {
			continue
		}
		var name, version, status string
		sc := bufio.NewScanner(bytes.NewReader(block))
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "Package: "):
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			case strings.HasPrefix(line, "Version: "):
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			case strings.HasPrefix(line, "Status: "):
				status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
			}
		}
		if name == "" {
			continue
		}
		// "install ok installed" — must end with "installed".
		if !strings.HasSuffix(status, "installed") {
			continue
		}
		out = append(out, Package{Database: "dpkg", Name: name, Version: version})
	}
	return out
}

// ParseApkInstalled parses /lib/apk/db/installed (Alpine).
//
// Blocks separated by blank lines; each line is "K:value" where K is a
// single letter (P=name, V=version, A=arch, O=origin, ...).
func ParseApkInstalled(data []byte) []Package {
	var out []Package
	for _, block := range bytes.Split(data, []byte("\n\n")) {
		if len(bytes.TrimSpace(block)) == 0 {
			continue
		}
		var name, version string
		sc := bufio.NewScanner(bytes.NewReader(block))
		for sc.Scan() {
			line := sc.Text()
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				name = line[2:]
			case 'V':
				version = line[2:]
			}
		}
		if name == "" {
			continue
		}
		out = append(out, Package{Database: "apk", Name: name, Version: version})
	}
	return out
}
