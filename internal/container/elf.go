package container

import (
	"bytes"
	"debug/elf"
	"strings"
)

// elfMagic is the 4-byte signature that begins every ELF file.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// elfBinaryDirs is the set of path prefixes (within an image rootfs) the
// scanner inspects for ELF binaries to gather DT_NEEDED dependencies.
// Sufficient for distroless-style images where the app + interpreter live
// in standard PATH-ish locations.
var elfBinaryDirs = []string{
	"usr/bin/", "usr/sbin/", "bin/", "sbin/",
	"usr/local/bin/", "usr/local/sbin/",
	"opt/", "app/", "srv/",
	"usr/lib/python3/", "usr/lib/python3.11/", "usr/lib/python3.12/",
}

// isELFCandidatePath reports whether p is in a directory worth peeking at
// for ELF binaries. Path is the slash-separated, no-leading-slash form
// produced by normalizePath in layers.go.
func isELFCandidatePath(p string) bool {
	for _, prefix := range elfBinaryDirs {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// hasELFMagic reports whether b begins with the ELF signature.
func hasELFMagic(b []byte) bool {
	return len(b) >= 4 && bytes.Equal(b[:4], elfMagic)
}

// extractELFNeeded returns the DT_NEEDED shared-object names from an ELF
// binary read into memory. Returns nil if the file isn't a valid ELF.
func extractELFNeeded(data []byte) []string {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer f.Close()
	needed, err := f.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil
	}
	return needed
}
