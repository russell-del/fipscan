// Package container scans OCI / Docker container images for FIPS 140-3
// posture: detects installed crypto packages (via apk/dpkg databases),
// the base OS (via /etc/os-release), and FIPS-mode markers.
//
// Layers are streamed directly from the registry; only a small set of
// "interesting" files is buffered in memory. The full image filesystem
// is never reassembled on disk.
package container

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"path"
	"strings"
)

// interesting is the closed set of paths the layer scanner extracts.
// Keep this small — anything not on the list is discarded as it streams.
var interesting = map[string]bool{
	"etc/os-release":                               true,
	"usr/lib/os-release":                           true,
	"var/lib/dpkg/status":                          true,
	"lib/apk/db/installed":                         true,
	"etc/system-fips":                              true,
	"etc/crypto-policies/back-ends/openssl.config": true,
	"etc/crypto-policies/state/current":            true,
	"var/lib/rpm/rpmdb.sqlite":                     true,
	"usr/lib/sysimage/rpm/rpmdb.sqlite":            true,
}

const (
	maxFileBytes       = 100 * 1024 * 1024       // per extracted non-ELF file
	maxELFBytes        = 50 * 1024 * 1024        // per ELF binary buffered for inspection
	maxLayerBytes      = 2 * 1024 * 1024 * 1024  // 2 GiB per layer (decompressed)
	maxELFInspections  = 100                     // overall cap per image to bound work
)

// ImageFS is the small in-memory representation of an image's relevant
// filesystem state after layers have been overlaid in order.
//
// Files holds the byte contents of known interesting paths.
// ELFNeeded maps an ELF binary's path to its DT_NEEDED entries.
type ImageFS struct {
	Files        map[string][]byte
	ELFNeeded    map[string][]string
	elfInspected int
}

func NewImageFS() *ImageFS {
	return &ImageFS{
		Files:     map[string][]byte{},
		ELFNeeded: map[string][]string{},
	}
}

// MergeLayer applies one gzipped tar layer to fs. Whiteouts (.wh.<name>
// and .wh..wh..opq) are honored so that upper layers can delete files /
// directory contents from lower layers. Only paths in `interesting` are
// kept; everything else is streamed past.
func (fs *ImageFS) MergeLayer(r io.Reader) error {
	gz, err := gzip.NewReader(io.LimitReader(r, maxLayerBytes))
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p := normalizePath(hdr.Name)
		if p == "" {
			continue
		}
		base := path.Base(p)

		// Whiteouts.
		if strings.HasPrefix(base, ".wh.") {
			if base == ".wh..wh..opq" {
				// Opaque directory: drop everything under path.Dir(p).
				prefix := path.Dir(p) + "/"
				for k := range fs.Files {
					if strings.HasPrefix(k, prefix) {
						delete(fs.Files, k)
					}
				}
				for k := range fs.ELFNeeded {
					if strings.HasPrefix(k, prefix) {
						delete(fs.ELFNeeded, k)
					}
				}
				continue
			}
			deleted := path.Join(path.Dir(p), strings.TrimPrefix(base, ".wh."))
			delete(fs.Files, deleted)
			delete(fs.ELFNeeded, deleted)
			continue
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}

		switch {
		case interesting[p]:
			data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
			if err != nil {
				return err
			}
			fs.Files[p] = data

		case isELFCandidatePath(p) && fs.elfInspected < maxELFInspections && hdr.Size > 0 && hdr.Size <= maxELFBytes:
			data, err := io.ReadAll(io.LimitReader(tr, maxELFBytes))
			if err != nil {
				return err
			}
			if !hasELFMagic(data) {
				continue
			}
			if needed := extractELFNeeded(data); len(needed) > 0 {
				fs.ELFNeeded[p] = needed
			}
			fs.elfInspected++
		}
	}
}

// normalizePath strips a leading "./" or "/" from a tar entry name and
// rejects parent-traversal segments.
func normalizePath(name string) string {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "/")
	if name == "" || strings.Contains(name, "..") {
		return ""
	}
	return name
}
