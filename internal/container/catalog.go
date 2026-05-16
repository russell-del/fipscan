package container

import "strings"

// CatalogEntry describes one container-level package whose FIPS posture
// is worth surfacing in a scan report. Match is the canonical (lowercased)
// package name from the system package database.
type CatalogEntry struct {
	Name        string
	Database    string // "dpkg" | "apk" | "" (any)
	RuleID      string
	Severity    string
	Reason      string
	Remediation string
	Reference   string
}

var containerCatalog = []CatalogEntry{
	// ---- OpenSSL / libcrypto ----
	{
		Name: "openssl", Database: "apk",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Default Alpine OpenSSL is not built with the FIPS provider activated.",
		Remediation: "Use a FIPS-enabled base image (Chainguard FIPS, Wolfi-FIPS, RHEL UBI FIPS, Iron Bank) or rebuild OpenSSL with `enable-fips` and ship the validated fipsmodule.cnf.",
		Reference:   "NIST CMVP cert. #4282 (OpenSSL FIPS Provider 3.0.8)",
	},
	{
		Name: "libssl3", Database: "apk",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Alpine libssl3 (OpenSSL 3.x) ships without the FIPS provider activated.",
		Remediation: "Use a FIPS-enabled base image (Chainguard FIPS, Wolfi-FIPS) or rebuild OpenSSL with `enable-fips`.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libcrypto3", Database: "apk",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Alpine libcrypto3 (OpenSSL 3.x) ships without the FIPS provider activated.",
		Remediation: "Use a FIPS-enabled base image (Chainguard FIPS, Wolfi-FIPS) or rebuild OpenSSL with `enable-fips`.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libssl1.1", Database: "apk",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "OpenSSL 1.1.x is EOL (Sep 2023) and is not FIPS 140-3 validated.",
		Remediation: "Upgrade base image to Alpine 3.17+ shipping OpenSSL 3.0.8+ with the FIPS provider.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libcrypto1.1", Database: "apk",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "OpenSSL 1.1.x is EOL (Sep 2023) and is not FIPS 140-3 validated.",
		Remediation: "Upgrade base image to Alpine 3.17+ shipping OpenSSL 3.0.8+ with the FIPS provider.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libssl3", Database: "dpkg",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Default Debian/Ubuntu libssl3 ships without the FIPS provider activated.",
		Remediation: "Use Ubuntu Pro FIPS, RHEL UBI FIPS, or rebuild OpenSSL with `enable-fips`.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libssl1.1", Database: "dpkg",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "OpenSSL 1.1.x is EOL (Sep 2023) and is not FIPS 140-3 validated. The 1.0.2 FIPS module is end-of-validation.",
		Remediation: "Upgrade base image to one shipping OpenSSL 3.0.8+ with the FIPS provider.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "openssl-libs", Database: "dpkg",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "openssl-libs present; verify the FIPS provider is enabled at runtime.",
		Remediation: "Confirm /etc/system-fips is present and the FIPS provider is loaded.",
		Reference:   "NIST CMVP cert. #4282",
	},

	// ---- libgcrypt: not FIPS validated as v1.10 ----
	{
		Name: "libgcrypt", Database: "apk",
		RuleID: "FIPS-CONT-LIBGCRYPT-001", Severity: "MEDIUM",
		Reason:      "libgcrypt is not currently FIPS 140-3 validated. Applications linking it for security purposes will not pass FIPS audit.",
		Remediation: "Replace consumers with OpenSSL / nss / wolfSSL FIPS builds.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libgcrypt20", Database: "dpkg",
		RuleID: "FIPS-CONT-LIBGCRYPT-001", Severity: "MEDIUM",
		Reason:      "libgcrypt is not currently FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL / nss / wolfSSL FIPS builds.",
		Reference:   "NIST CMVP",
	},

	// ---- GnuTLS: not in current CMVP ----
	{
		Name: "gnutls", Database: "apk",
		RuleID: "FIPS-CONT-GNUTLS-001", Severity: "MEDIUM",
		Reason:      "GnuTLS is not currently FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or NSS FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libgnutls30", Database: "dpkg",
		RuleID: "FIPS-CONT-GNUTLS-001", Severity: "MEDIUM",
		Reason:      "GnuTLS is not currently FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or NSS FIPS.",
		Reference:   "NIST CMVP",
	},

	// ---- mbedtls / libsodium / wolfssl ----
	{
		Name: "mbedtls", Database: "apk",
		RuleID: "FIPS-CONT-MBEDTLS-001", Severity: "MEDIUM",
		Reason:      "mbedTLS is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or wolfSSL FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libsodium", Database: "apk",
		RuleID: "FIPS-CONT-SODIUM-001", Severity: "MEDIUM",
		Reason:      "libsodium is not FIPS 140-3 validated. Its primitives (XSalsa20, Ed25519 implementation, Argon2) include some that are not on the FIPS approved list.",
		Remediation: "Replace consumers with OpenSSL FIPS for FIPS-mandated operations.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libsodium23", Database: "dpkg",
		RuleID: "FIPS-CONT-SODIUM-001", Severity: "MEDIUM",
		Reason:      "libsodium is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS for FIPS-mandated operations.",
		Reference:   "NIST CMVP",
	},

	// ---- RPM (RHEL / Fedora / Rocky / Alma) ------------------------------
	{
		Name: "openssl-libs", Database: "rpm",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "openssl-libs on RHEL/Fedora; FIPS provider activation depends on /etc/system-fips and crypto-policies.",
		Remediation: "Verify /etc/system-fips is present and `update-crypto-policies --set FIPS` was run during image build.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "openssl", Database: "rpm",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "openssl CLI on RHEL/Fedora; FIPS provider activation depends on system-fips marker and crypto-policies.",
		Remediation: "Verify /etc/system-fips and crypto-policies are FIPS-configured.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "openssl11-libs", Database: "rpm",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "openssl11-libs (OpenSSL 1.1.x) is EOL (Sep 2023) and not FIPS 140-3 validated.",
		Remediation: "Upgrade to openssl 3.0.8+ with the FIPS provider on RHEL 9 / UBI 9 FIPS.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libgcrypt", Database: "rpm",
		RuleID: "FIPS-CONT-LIBGCRYPT-001", Severity: "MEDIUM",
		Reason:      "libgcrypt on RHEL/Fedora is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL / NSS FIPS builds.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "gnutls", Database: "rpm",
		RuleID: "FIPS-CONT-GNUTLS-001", Severity: "MEDIUM",
		Reason:      "GnuTLS is not currently FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or NSS FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "nss", Database: "rpm",
		RuleID: "FIPS-CONT-NSS-001", Severity: "LOW",
		Reason:      "NSS is present; an NSS FIPS submodule exists (cert #3949). Verify build configuration enables FIPS.",
		Remediation: "Confirm NSS was built with FIPS mode and the validated softokn module is loaded.",
		Reference:   "NIST CMVP cert. #3949",
	},
	{
		Name: "openssl-fips-provider", Database: "rpm",
		RuleID: "FIPS-CONT-OPENSSL-FIPS-PROVIDER-001", Severity: "LOW",
		Reason:      "openssl-fips-provider is installed. This is Red Hat's FIPS 140-3 validated OpenSSL 3.0.7 module — a positive FIPS-readiness signal.",
		Remediation: "Confirm /etc/system-fips is present and crypto-policies are set to FIPS so the validated provider is actually loaded.",
		Reference:   "NIST CMVP cert. #4746",
	},
	{
		Name: "openssl-fips-provider-so", Database: "rpm",
		RuleID: "FIPS-CONT-OPENSSL-FIPS-PROVIDER-001", Severity: "LOW",
		Reason:      "openssl-fips-provider-so is installed (the FIPS provider shared object).",
		Remediation: "Confirm /etc/system-fips is present and crypto-policies are set to FIPS.",
		Reference:   "NIST CMVP cert. #4746",
	},

	// ---- ELF DT_NEEDED (distroless / no package DB) ----------------------
	// Match against the soname referenced by NEEDED entries in installed
	// binaries. Database key is "elf".
	{
		Name: "libcrypto.so.3", Database: "elf",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Binaries link libcrypto.so.3 (OpenSSL 3.x). FIPS posture depends on whether the bundled OpenSSL has the FIPS provider activated.",
		Remediation: "Confirm /etc/system-fips marker and that the OpenSSL FIPS provider is enabled at runtime.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libssl.so.3", Database: "elf",
		RuleID: "FIPS-CONT-OPENSSL-001", Severity: "MEDIUM",
		Reason:      "Binaries link libssl.so.3 (OpenSSL 3.x). FIPS posture depends on whether the bundled OpenSSL has the FIPS provider activated.",
		Remediation: "Confirm /etc/system-fips marker and FIPS provider activation.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libcrypto.so.1.1", Database: "elf",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "Binaries link libcrypto.so.1.1 (OpenSSL 1.1.x), which is EOL (Sep 2023) and not FIPS 140-3 validated.",
		Remediation: "Rebuild against an OpenSSL 3.0.8+ FIPS-validated base image.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libssl.so.1.1", Database: "elf",
		RuleID: "FIPS-CONT-OPENSSL-002", Severity: "HIGH",
		Reason:      "Binaries link libssl.so.1.1 (OpenSSL 1.1.x), which is EOL.",
		Remediation: "Rebuild against an OpenSSL 3.0.8+ FIPS-validated base image.",
		Reference:   "NIST CMVP cert. #4282",
	},
	{
		Name: "libgcrypt.so.20", Database: "elf",
		RuleID: "FIPS-CONT-LIBGCRYPT-001", Severity: "MEDIUM",
		Reason:      "Binaries link libgcrypt, which is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or NSS FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libgnutls.so.30", Database: "elf",
		RuleID: "FIPS-CONT-GNUTLS-001", Severity: "MEDIUM",
		Reason:      "Binaries link GnuTLS, which is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or NSS FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libsodium.so.23", Database: "elf",
		RuleID: "FIPS-CONT-SODIUM-001", Severity: "MEDIUM",
		Reason:      "Binaries link libsodium, which is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS.",
		Reference:   "NIST CMVP",
	},
	{
		Name: "libmbedcrypto.so.7", Database: "elf",
		RuleID: "FIPS-CONT-MBEDTLS-001", Severity: "MEDIUM",
		Reason:      "Binaries link mbedTLS, which is not FIPS 140-3 validated.",
		Remediation: "Replace consumers with OpenSSL FIPS or wolfSSL FIPS.",
		Reference:   "NIST CMVP",
	},
}

// catalogIndex enables O(1) lookup by (database, lowercased-name). Note
// some entries have Database="" for any-distro matches.
var catalogIndex map[string]CatalogEntry

func init() {
	catalogIndex = make(map[string]CatalogEntry, len(containerCatalog))
	for _, e := range containerCatalog {
		catalogIndex[key(e.Database, e.Name)] = e
	}
}

func key(db, name string) string {
	return strings.ToLower(db) + "|" + strings.ToLower(name)
}

// Lookup returns the catalog entry for a given installed package, if any.
func Lookup(pkg Package) *CatalogEntry {
	if e, ok := catalogIndex[key(pkg.Database, pkg.Name)]; ok {
		return &e
	}
	if e, ok := catalogIndex[key("", pkg.Name)]; ok {
		return &e
	}
	return nil
}

// ParseOsRelease pulls ID, VERSION_ID, and PRETTY_NAME out of an
// /etc/os-release file. Returns zero values for missing fields.
func ParseOsRelease(data []byte) (id, version, pretty string) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			version = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	return
}
