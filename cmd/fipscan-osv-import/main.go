// fipscan-osv-import — download OSV bulk dumps, filter to crypto-
// relevant entries, and emit Go source code that gets compiled into
// fipscan as `internal/deps/osv_entries.go`.
//
// Usage:
//   go run ./cmd/fipscan-osv-import [-ecosystems "PyPI,npm,..."] > internal/deps/osv_entries.go
//
// Or via the Makefile target:
//   make update-catalog
//
// The output is committed to the repo — fipscan is a single binary
// with no runtime catalog file, so the OSV-imported entries ship inside
// the binary alongside the hand-curated ones.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rbuilta/fipscan/internal/osv"
)

// knownCryptoPackages is the union of fipscan's hand-curated package
// catalog plus an allowlist of packages that aren't currently in the
// catalog but are obviously crypto-focused. The OSV filter uses this
// list as a fast-path so a CVE on `cryptography` or `openssl` is
// always considered crypto-relevant even if the summary text is
// awkwardly phrased.
//
// Keys: "<ecosystem>:<name>", both lowercase.
var knownCryptoPackages = map[string]bool{
	// PyPI
	"pypi:cryptography":      true,
	"pypi:pycrypto":          true,
	"pypi:pycryptodome":      true,
	"pypi:pyopenssl":         true,
	"pypi:m2crypto":          true,
	"pypi:bcrypt":            true,
	"pypi:passlib":           true,
	"pypi:pyjwt":             true,
	"pypi:cffi":              true,
	"pypi:argon2-cffi":       true,
	"pypi:scrypt":            true,
	"pypi:ed25519":           true,
	"pypi:fastecdsa":         true,
	"pypi:secp256k1":         true,
	"pypi:ecdsa":             true,
	"pypi:rsa":               true,
	// npm
	"npm:node-forge":     true,
	"npm:crypto-js":      true,
	"npm:bcrypt":         true,
	"npm:bcryptjs":       true,
	"npm:md5":            true,
	"npm:sha1":           true,
	"npm:jsonwebtoken":   true,
	"npm:jose":           true,
	"npm:jsrsasign":      true,
	"npm:tweetnacl":      true,
	"npm:elliptic":       true,
	"npm:secp256k1":      true,
	// Go
	"go:golang.org/x/crypto":                  true,
	"go:github.com/btcsuite/btcd/btcec":       true,
	"go:github.com/btcsuite/btcd/btcec/v2":    true,
	"go:github.com/decred/dcrd/dcrec/secp256k1": true,
	// Maven
	"maven:org.bouncycastle:bcprov-jdk15on": true,
	"maven:org.bouncycastle:bcprov-jdk18on": true,
	"maven:org.bouncycastle:bcpkix-jdk15on": true,
	"maven:org.bouncycastle:bcpkix-jdk18on": true,
	"maven:org.bouncycastle:bcpg-jdk15on":   true,
	"maven:org.bouncycastle:bcpg-jdk18on":   true,
	"maven:org.mindrot:jbcrypt":             true,
	// Cargo
	"cargo:openssl":      true,
	"cargo:rustls":       true,
	"cargo:ring":         true,
	"cargo:rsa":          true,
	"cargo:ed25519":      true,
	"cargo:ed25519-dalek": true,
	"cargo:secp256k1":    true,
	"cargo:k256":         true,
	"cargo:md5":          true,
	"cargo:md-5":         true,
	"cargo:sha1":         true,
	"cargo:sha-1":        true,
	"cargo:bcrypt":       true,
	// RubyGems
	"rubygems:bcrypt":     true,
	"rubygems:bcrypt-ruby": true,
	"rubygems:scrypt":     true,
	"rubygems:argon2":     true,
	"rubygems:rbnacl":     true,
	"rubygems:openssl":    true,
	"rubygems:jwt":        true,
	// Composer
	"composer:phpseclib/phpseclib":   true,
	"composer:paragonie/halite":      true,
	"composer:paragonie/random_compat": true,
	"composer:mdanter/ecc":           true,
	"composer:web3p/ethereum-tx":     true,
	"composer:firebase/php-jwt":      true,
	// NuGet
	"nuget:bcrypt.net-next":       true,
	"nuget:portable.bouncycastle": true,
	"nuget:bouncycastle.netcore":  true,
	"nuget:bouncycastle":          true,
}

func main() {
	eco := flag.String("ecosystems", strings.Join(osv.BulkEcosystems, ","),
		"Comma-separated OSV ecosystems to import.")
	flag.Parse()

	ecosystems := strings.Split(*eco, ",")
	for i, e := range ecosystems {
		ecosystems[i] = strings.TrimSpace(e)
	}

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	all := []osv.ImportedEntry{}
	stats := map[string]int{}

	for _, eco := range ecosystems {
		logf("=== %s ===", eco)
		t0 := time.Now()
		vulns, err := osv.FetchEcosystem(eco)
		if err != nil {
			logf("  fetch failed: %v", err)
			continue
		}
		logf("  downloaded %d vulnerabilities in %s", len(vulns), time.Since(t0).Round(time.Second))
		kept := 0
		for _, v := range vulns {
			if !v.IsCryptoRelevant(knownCryptoPackages) {
				continue
			}
			entries := v.ToEntries(knownCryptoPackages)
			if len(entries) == 0 {
				continue
			}
			all = append(all, entries...)
			kept++
		}
		stats[eco] = kept
		logf("  crypto-relevant: %d (yielded %d ImportedEntry rows)", kept, len(all))
	}

	// Stable sort so the generated file diffs cleanly across re-runs.
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Ecosystem != all[j].Ecosystem {
			return all[i].Ecosystem < all[j].Ecosystem
		}
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].RuleID < all[j].RuleID
	})

	emit(os.Stdout, all, stats)
}

func emit(w *os.File, entries []osv.ImportedEntry, stats map[string]int) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	statLines := make([]string, 0, len(stats))
	for k, v := range stats {
		statLines = append(statLines, fmt.Sprintf("//   %s: %d", k, v))
	}
	sort.Strings(statLines)

	fmt.Fprintln(bw, "// Code generated by cmd/fipscan-osv-import. DO NOT EDIT.")
	fmt.Fprintln(bw, "//")
	fmt.Fprintln(bw, "// Regenerate with: make update-catalog")
	fmt.Fprintln(bw, "//")
	fmt.Fprintf(bw, "// Source: osv.dev bulk dump, generated %s.\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintln(bw, "//")
	fmt.Fprintln(bw, "// Per-ecosystem crypto-relevant counts:")
	for _, line := range statLines {
		fmt.Fprintln(bw, line)
	}
	fmt.Fprintln(bw)
	fmt.Fprintln(bw, "package deps")
	fmt.Fprintln(bw)
	fmt.Fprintln(bw, "// osvCatalog is the OSV-derived catalog. It's indexed alongside")
	fmt.Fprintln(bw, "// the hand-curated `catalog` slice in catalog.go's init().")
	fmt.Fprintln(bw, "var osvCatalog = []CatalogEntry{")
	for _, e := range entries {
		fmt.Fprintf(bw,
			"\t{Ecosystem: %q, Name: %q, AffectedVersions: %q, RuleID: %q, Severity: %q, Reason: %q, Remediation: %q, Reference: %q},\n",
			e.Ecosystem, e.Name, e.AffectedVersions, e.RuleID, e.Severity, e.Reason, e.Remediation, e.Reference)
	}
	fmt.Fprintln(bw, "}")
}
