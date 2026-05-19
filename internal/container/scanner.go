package container

import (
	"encoding/json"
	"fmt"

	"github.com/russell-del/fipscan/internal/findings"
	"github.com/russell-del/fipscan/internal/registry"
)

// ScanImage pulls the image at the requested platform, streams its layers,
// inspects package DBs / ELF binaries / os-release, and returns
// FIPS-relevance findings.
func ScanImage(ref string, auth *registry.BasicAuth, plat registry.Platform) ([]findings.Finding, error) {
	r, err := registry.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	client := registry.NewClient(auth)

	// Manifest (possibly a manifest list / OCI index).
	rawManifest, mediaType, err := client.FetchManifest(r)
	if err != nil {
		return nil, err
	}
	if registry.IsManifestList(mediaType) {
		picked, err := selectPlatform(rawManifest, plat)
		if err != nil {
			return nil, err
		}
		r.Digest = picked
		r.Tag = ""
		rawManifest, _, err = client.FetchManifest(r)
		if err != nil {
			return nil, fmt.Errorf("fetch platform manifest: %w", err)
		}
	}

	var m struct {
		Layers []struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(m.Layers) == 0 {
		return nil, fmt.Errorf("manifest contained no layers")
	}

	fs := NewImageFS()
	for _, layer := range m.Layers {
		body, err := client.FetchBlob(r, layer.Digest)
		if err != nil {
			return nil, fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
		}
		err = fs.MergeLayer(body)
		_ = body.Close()
		if err != nil {
			return nil, fmt.Errorf("merge layer %s: %w", layer.Digest, err)
		}
	}

	return analyseFS(ref, fs), nil
}

// analyseFS turns the assembled in-memory filesystem into findings.
func analyseFS(imageRef string, fs *ImageFS) []findings.Finding {
	var pkgs []Package
	if data, ok := fs.Files["lib/apk/db/installed"]; ok {
		pkgs = append(pkgs, ParseApkInstalled(data)...)
	}
	if data, ok := fs.Files["var/lib/dpkg/status"]; ok {
		pkgs = append(pkgs, ParseDpkgStatus(data)...)
	}
	for _, p := range []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"} {
		if data, ok := fs.Files[p]; ok {
			pkgs = append(pkgs, ParseRPMDB(data)...)
		}
	}

	var results []findings.Finding
	for _, pkg := range pkgs {
		entry := Lookup(pkg)
		if entry == nil {
			continue
		}
		display := pkg.Name
		if pkg.Version != "" {
			display = pkg.Name + " " + pkg.Version
		}
		results = append(results, findings.Finding{
			File:        imageRef,
			Line:        1,
			Algorithm:   display,
			Language:    "Container (" + pkg.Database + ")",
			Severity:    findings.Severity(entry.Severity),
			Snippet:     pkg.Name + " " + pkg.Version,
			Rule:        entry.RuleID,
			Remediation: entry.Reason + " " + entry.Remediation,
			Reference:   entry.Reference,
		})
	}

	results = append(results, elfFindings(imageRef, fs)...)
	results = append(results, posturFinding(imageRef, fs))
	return results
}

// elfFindings inspects each ELF binary's DT_NEEDED dependencies, looks
// each soname up in the "elf" partition of the catalog, and emits one
// finding per unique (soname, binary) hit. De-duplication keeps the
// report readable when many binaries share the same libcrypto.
func elfFindings(imageRef string, fs *ImageFS) []findings.Finding {
	type hit struct {
		soname string
		entry  *CatalogEntry
	}
	emitted := map[string]bool{} // dedupe by soname
	var out []findings.Finding
	for binPath, needed := range fs.ELFNeeded {
		for _, so := range needed {
			if emitted[so] {
				continue
			}
			entry := Lookup(Package{Database: "elf", Name: so})
			if entry == nil {
				continue
			}
			emitted[so] = true
			out = append(out, findings.Finding{
				File:        imageRef,
				Line:        1,
				Algorithm:   "ELF-NEEDED: " + so,
				Language:    "Container (elf)",
				Severity:    findings.Severity(entry.Severity),
				Snippet:     "/" + binPath + "  →  " + so,
				Rule:        entry.RuleID,
				Remediation: entry.Reason + " " + entry.Remediation,
				Reference:   entry.Reference,
			})
			_ = hit{} // keep type around for future grouping
		}
	}
	return out
}

// posturFinding emits the single summary finding describing whether the
// image looks like it has FIPS mode activated. Always emitted; severity
// reflects the assessment.
func posturFinding(imageRef string, fs *ImageFS) findings.Finding {
	osData := fs.Files["etc/os-release"]
	if len(osData) == 0 {
		osData = fs.Files["usr/lib/os-release"]
	}
	id, version, pretty := ParseOsRelease(osData)

	_, hasFipsMarker := fs.Files["etc/system-fips"]
	_, hasCryptoPolicy := fs.Files["etc/crypto-policies/state/current"]

	severity := findings.SeverityMedium
	rule := "FIPS-CONT-POSTURE-001"
	reason := "Image base does not appear FIPS-enabled: no /etc/system-fips marker found."
	remediation := "Use a FIPS-enabled base image (RHEL UBI FIPS, Ubuntu Pro FIPS, Chainguard FIPS, Iron Bank) for FedRAMP / DoD deployments."

	if hasFipsMarker {
		severity = findings.SeverityLow
		reason = "Image appears FIPS-mode-enabled (/etc/system-fips present)."
		remediation = "Verify the running OpenSSL FIPS provider is at a CMVP-validated version (≥3.0.8) and crypto-policies are set to FIPS."
		rule = "FIPS-CONT-POSTURE-002"
	}
	if hasCryptoPolicy {
		reason += " /etc/crypto-policies state is present (RHEL-family)."
	}

	display := pretty
	if display == "" && id != "" {
		display = id + " " + version
	}
	if display == "" {
		display = "unknown base"
	}

	return findings.Finding{
		File:        imageRef,
		Line:        1,
		Algorithm:   "base image: " + display,
		Language:    "Container",
		Severity:    severity,
		Snippet:     display,
		Rule:        rule,
		Remediation: reason + " " + remediation,
		Reference:   "NIST FIPS 140-3 IG",
	}
}

// selectPlatform returns the digest of the manifest matching plat from a
// manifest list / OCI index. Variant match is enforced only when the
// requested plat carries one (so "linux/arm64" picks any arm64 manifest
// regardless of v8/v9 variant).
func selectPlatform(rawIndex []byte, plat registry.Platform) (string, error) {
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(rawIndex, &idx); err != nil {
		return "", err
	}
	for _, m := range idx.Manifests {
		if m.Platform.OS != plat.OS || m.Platform.Architecture != plat.Arch {
			continue
		}
		if plat.Variant != "" && m.Platform.Variant != plat.Variant {
			continue
		}
		return m.Digest, nil
	}
	return "", fmt.Errorf("no %s manifest in image index", plat)
}

