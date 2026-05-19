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

	"github.com/russell-del/fipscan/internal/osv"
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
	// ---- PyPI ----
	"pypi:cryptography":   true,
	"pypi:pycrypto":       true,
	"pypi:pycryptodome":   true,
	"pypi:pycryptodomex":  true,
	"pypi:pyopenssl":      true,
	"pypi:m2crypto":       true,
	"pypi:bcrypt":         true,
	"pypi:passlib":        true,
	"pypi:pyjwt":          true,
	"pypi:python-jose":    true,
	"pypi:jwcrypto":       true,
	"pypi:authlib":        true,
	"pypi:oauthlib":       true,
	"pypi:requests-oauthlib": true,
	"pypi:cffi":           true,
	"pypi:argon2-cffi":    true,
	"pypi:scrypt":         true,
	"pypi:ed25519":        true,
	"pypi:fastecdsa":      true,
	"pypi:secp256k1":      true,
	"pypi:coincurve":      true,
	"pypi:ecdsa":          true,
	"pypi:rsa":            true,
	"pypi:paramiko":       true,
	"pypi:asyncssh":       true,
	"pypi:fabric":         true,
	"pypi:pynacl":         true,
	"pypi:nacl":           true,
	"pypi:pyspnego":       true,
	"pypi:gssapi":         true,
	"pypi:saml2":          true,
	"pypi:python3-saml":   true,
	"pypi:certifi":        true,
	"pypi:josepy":         true,
	"pypi:acme":           true,
	"pypi:webencodings":   true,
	"pypi:ssh-python":     true,

	// ---- npm ----
	"npm:node-forge":           true,
	"npm:crypto-js":            true,
	"npm:bcrypt":                true,
	"npm:bcryptjs":              true,
	"npm:md5":                   true,
	"npm:sha1":                  true,
	"npm:sha":                   true,
	"npm:hash.js":               true,
	"npm:jsonwebtoken":          true,
	"npm:jose":                  true,
	"npm:node-jose":             true,
	"npm:jwk-to-pem":            true,
	"npm:jsrsasign":             true,
	"npm:tweetnacl":             true,
	"npm:elliptic":              true,
	"npm:secp256k1":             true,
	"npm:noble-secp256k1":       true,
	"npm:@noble/curves":         true,
	"npm:@noble/secp256k1":      true,
	"npm:@noble/hashes":         true,
	"npm:@noble/ed25519":        true,
	"npm:asn1.js":               true,
	"npm:pkijs":                 true,
	"npm:node-rsa":              true,
	"npm:ssh2":                  true,
	"npm:ssh2-streams":          true,
	"npm:openpgp":               true,
	"npm:tls":                   true,
	"npm:passport-saml":         true,
	"npm:xml-crypto":            true,
	"npm:xmldsigjs":             true,
	"npm:webcrypto-core":        true,
	"npm:@peculiar/webcrypto":   true,

	// ---- Go ----
	"go:golang.org/x/crypto":                       true,
	"go:github.com/btcsuite/btcd/btcec":            true,
	"go:github.com/btcsuite/btcd/btcec/v2":         true,
	"go:github.com/decred/dcrd/dcrec/secp256k1":    true,
	"go:github.com/decred/dcrd/dcrec/secp256k1/v4": true,
	"go:github.com/lestrrat-go/jwx":                true,
	"go:github.com/lestrrat-go/jwx/v2":             true,
	"go:github.com/golang-jwt/jwt":                 true,
	"go:github.com/golang-jwt/jwt/v4":              true,
	"go:github.com/golang-jwt/jwt/v5":              true,
	"go:github.com/dgrijalva/jwt-go":               true,
	"go:github.com/cloudflare/circl":               true,
	"go:github.com/aead/chacha20":                  true,
	"go:github.com/miekg/pkcs11":                   true,
	"go:github.com/google/tink/go":                 true,
	"go:gopkg.in/square/go-jose.v2":                true,
	"go:github.com/go-jose/go-jose/v3":             true,
	"go:github.com/go-jose/go-jose/v4":             true,
	"go:filippo.io/age":                            true,
	"go:filippo.io/edwards25519":                   true,

	// ---- Maven (Java) ----
	"maven:org.bouncycastle:bcprov-jdk15on":               true,
	"maven:org.bouncycastle:bcprov-jdk18on":               true,
	"maven:org.bouncycastle:bcprov-jdk16":                 true,
	"maven:org.bouncycastle:bcpkix-jdk15on":               true,
	"maven:org.bouncycastle:bcpkix-jdk18on":               true,
	"maven:org.bouncycastle:bcpg-jdk15on":                 true,
	"maven:org.bouncycastle:bcpg-jdk18on":                 true,
	"maven:org.bouncycastle:bctls-jdk15on":                true,
	"maven:org.bouncycastle:bctls-jdk18on":                true,
	"maven:org.bouncycastle:bcutil-jdk15on":               true,
	"maven:org.bouncycastle:bcutil-jdk18on":               true,
	"maven:org.bouncycastle:bcmail-jdk15on":               true,
	"maven:org.bouncycastle:bcmail-jdk18on":               true,
	"maven:org.bouncycastle:bc-fips":                      true,
	"maven:org.mindrot:jbcrypt":                           true,
	"maven:com.password4j:password4j":                     true,
	"maven:com.nimbusds:nimbus-jose-jwt":                  true,
	"maven:org.springframework.security:spring-security-crypto": true,
	"maven:com.amazonaws:aws-encryption-sdk-java":         true,
	"maven:io.jsonwebtoken:jjwt-api":                      true,
	"maven:io.jsonwebtoken:jjwt-impl":                     true,
	"maven:com.auth0:java-jwt":                            true,
	"maven:com.auth0:jwks-rsa":                            true,
	"maven:org.jasig.cas:cas-server-core":                 true,
	"maven:com.googlecode.json-simple:json-simple":        true,
	"maven:net.shibboleth.tool:xmlsectool":                true,

	// ---- Cargo (Rust) ----
	"cargo:openssl":              true,
	"cargo:openssl-sys":          true,
	"cargo:rustls":               true,
	"cargo:rustls-webpki":        true,
	"cargo:rustls-pemfile":       true,
	"cargo:rustls-native-certs":  true,
	"cargo:ring":                 true,
	"cargo:rsa":                  true,
	"cargo:ed25519":              true,
	"cargo:ed25519-dalek":        true,
	"cargo:secp256k1":            true,
	"cargo:k256":                 true,
	"cargo:p256":                 true,
	"cargo:p384":                 true,
	"cargo:p521":                 true,
	"cargo:ecdsa":                true,
	"cargo:curve25519-dalek":     true,
	"cargo:x25519-dalek":         true,
	"cargo:md5":                  true,
	"cargo:md-5":                 true,
	"cargo:sha1":                 true,
	"cargo:sha-1":                true,
	"cargo:sha2":                 true,
	"cargo:sha3":                 true,
	"cargo:blake2":               true,
	"cargo:blake3":               true,
	"cargo:digest":               true,
	"cargo:hmac":                 true,
	"cargo:hkdf":                 true,
	"cargo:aes":                  true,
	"cargo:aes-gcm":              true,
	"cargo:aes-gcm-siv":          true,
	"cargo:chacha20":             true,
	"cargo:chacha20poly1305":     true,
	"cargo:salsa20":              true,
	"cargo:argon2":               true,
	"cargo:scrypt":               true,
	"cargo:pbkdf2":               true,
	"cargo:bcrypt":               true,
	"cargo:rc4":                  true,
	"cargo:des":                  true,
	"cargo:webpki":               true,
	"cargo:webpki-roots":         true,
	"cargo:native-tls":           true,
	"cargo:boring":               true,
	"cargo:boring-sys":           true,
	"cargo:pem":                  true,
	"cargo:der":                  true,
	"cargo:pkcs1":                true,
	"cargo:pkcs7":                true,
	"cargo:pkcs8":                true,
	"cargo:spki":                 true,
	"cargo:signature":            true,
	"cargo:jsonwebtoken":         true,
	"cargo:tiny-keccak":          true,
	"cargo:russh":                true,
	"cargo:thrussh":              true,

	// ---- RubyGems ----
	"rubygems:bcrypt":      true,
	"rubygems:bcrypt-ruby": true,
	"rubygems:scrypt":      true,
	"rubygems:argon2":      true,
	"rubygems:rbnacl":      true,
	"rubygems:rbnacl-libsodium": true,
	"rubygems:openssl":     true,
	"rubygems:jwt":         true,
	"rubygems:json-jwt":    true,
	"rubygems:ed25519":     true,
	"rubygems:secp256k1":   true,
	"rubygems:eth":         true,
	"rubygems:net-ssh":     true,
	"rubygems:net-ssh-multi": true,
	"rubygems:ruby-saml":   true,
	"rubygems:openid_connect": true,
	"rubygems:doorkeeper":  true,
	"rubygems:omniauth-oauth2": true,
	"rubygems:rack-jwt":    true,

	// ---- Composer (PHP) ----
	"composer:phpseclib/phpseclib":         true,
	"composer:phpseclib/phpseclib2_compat": true,
	"composer:phpseclib/bcmath_compat":     true,
	"composer:paragonie/halite":            true,
	"composer:paragonie/sodium_compat":     true,
	"composer:paragonie/paseto":            true,
	"composer:paragonie/random_compat":     true,
	"composer:paragonie/constant_time_encoding": true,
	"composer:defuse/php-encryption":       true,
	"composer:mdanter/ecc":                 true,
	"composer:web3p/ethereum-tx":           true,
	"composer:firebase/php-jwt":            true,
	"composer:lcobucci/jwt":                true,
	"composer:web-token/jwt-framework":     true,
	"composer:web-token/jwt-key-mgmt":      true,
	"composer:web-token/jwt-signature":     true,
	"composer:spomky-labs/jose":            true,
	"composer:spomky-labs/php-jose":        true,
	"composer:auth0/auth0-php":             true,
	"composer:kreait/firebase-php":         true,
	"composer:simplesamlphp/saml2":         true,
	"composer:simplesamlphp/simplesamlphp": true,
	"composer:robrichards/xmlseclibs":      true,
	"composer:onelogin/php-saml":           true,
	"composer:hybridauth/hybridauth":       true,

	// ---- NuGet (.NET) ----
	"nuget:bcrypt.net-next":             true,
	"nuget:bcrypt.net":                  true,
	"nuget:portable.bouncycastle":       true,
	"nuget:bouncycastle.netcore":        true,
	"nuget:bouncycastle":                true,
	"nuget:bouncycastle.cryptography":   true,
	"nuget:bouncycastle.crypto":         true,
	"nuget:system.identitymodel.tokens.jwt":     true,
	"nuget:microsoft.identitymodel.tokens":      true,
	"nuget:microsoft.identitymodel.jsonwebtokens": true,
	"nuget:identitymodel":               true,
	"nuget:microsoft.aspnetcore.authentication.jwtbearer": true,
	"nuget:konscious.security.cryptography.argon2": true,
	"nuget:nsec.cryptography":           true,
	"nuget:libsodium":                   true,
	"nuget:libsodium-net":               true,
	"nuget:sodium.core":                 true,
	"nuget:nbitcoin":                    true,
	"nuget:nbitcoin.secp256k1":          true,
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
