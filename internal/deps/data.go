package deps

// catalog is the curated set of packages whose presence is FIPS-relevant.
// This is the actual product moat — extend it from real customer findings,
// CMVP/CAVP browsing, and tracking deprecation milestones in NIST SP 800-131A.
var catalog = []CatalogEntry{
	// ---- PyPI ----------------------------------------------------------------
	{
		Ecosystem: "pypi", Name: "pycrypto",
		RuleID: "FIPS-DEP-PYPI-001", Severity: "HIGH",
		Reason:      "pycrypto is abandoned (no release since 2014) and contains known vulnerabilities.",
		Remediation: "Replace with `cryptography` (pyca) or `pycryptodome`.",
		Reference:   "https://github.com/dlitz/pycrypto",
	},
	{
		Ecosystem: "pypi", Name: "md5",
		RuleID: "FIPS-DEP-PYPI-002", Severity: "HIGH",
		Reason:      "The standalone `md5` PyPI package wraps MD5, which is not FIPS 140-3 approved.",
		Remediation: "Use hashlib.sha256 from the standard library.",
		Reference:   "FIPS 180-4",
	},
	{
		Ecosystem: "pypi", Name: "bcrypt",
		RuleID: "FIPS-DEP-PYPI-003", Severity: "HIGH",
		Reason:      "bcrypt is built on Blowfish, which is not on the FIPS 140-3 approved algorithm list.",
		Remediation: "Use PBKDF2 (hashlib.pbkdf2_hmac with SHA-256/SHA-512) for password hashing.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "pypi", Name: "passlib",
		RuleID: "FIPS-DEP-PYPI-004", Severity: "MEDIUM",
		Reason:      "passlib supports many non-FIPS hashes (bcrypt, scrypt, argon2). Only PBKDF2-HMAC schemes are FIPS-approved.",
		Remediation: "If you use passlib, restrict CryptContext to pbkdf2_sha256 or pbkdf2_sha512.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "pypi", Name: "m2crypto",
		RuleID: "FIPS-DEP-PYPI-005", Severity: "MEDIUM",
		Reason:      "M2Crypto binds to system OpenSSL; FIPS posture depends on whether the underlying OpenSSL is built with the FIPS provider enabled.",
		Remediation: "Verify the runtime image has OpenSSL 3.0+ with the FIPS provider, or migrate to `cryptography` built against a FIPS provider.",
		Reference:   "NIST CMVP",
	},
	{
		Ecosystem: "pypi", Name: "cryptography",
		RuleID: "FIPS-DEP-PYPI-006", Severity: "MEDIUM",
		Reason:      "PyPI wheels of `cryptography` ship a bundled non-FIPS OpenSSL. The package is fine; the build matters.",
		Remediation: "For FIPS deployments, build `cryptography` from source against a FIPS-validated OpenSSL 3.x with the FIPS provider activated, or install via a distro package linked to FIPS-validated OpenSSL.",
		Reference:   "https://cryptography.io/en/latest/installation/",
	},
	{
		Ecosystem: "pypi", Name: "pycryptodome",
		RuleID: "FIPS-DEP-PYPI-007", Severity: "MEDIUM",
		Reason:      "pycryptodome is a pure-Python+C crypto library that is NOT a FIPS-validated cryptographic module. It exposes many non-approved primitives (DES, 3DES, RC4, Blowfish, ChaCha20).",
		Remediation: "If FIPS validation is required, replace pycryptodome usage with `cryptography` built against a FIPS-validated OpenSSL.",
		Reference:   "NIST CMVP",
	},

	// ---- npm -----------------------------------------------------------------
	{
		Ecosystem: "npm", Name: "md5",
		RuleID: "FIPS-DEP-NPM-001", Severity: "HIGH",
		Reason:      "The `md5` npm package wraps MD5, which is not FIPS 140-3 approved.",
		Remediation: "Use Node's built-in `crypto.createHash('sha256')`.",
		Reference:   "FIPS 180-4",
	},
	{
		Ecosystem: "npm", Name: "sha1",
		RuleID: "FIPS-DEP-NPM-002", Severity: "MEDIUM",
		Reason:      "The `sha1` npm package wraps SHA-1, which is disallowed for digital signatures.",
		Remediation: "Use Node's built-in `crypto.createHash('sha256')`.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Ecosystem: "npm", Name: "crypto-js",
		RuleID: "FIPS-DEP-NPM-003", Severity: "HIGH",
		Reason:      "crypto-js is pure-JavaScript and is not a FIPS-validated cryptographic module. It defaults to several non-approved algorithms (MD5, SHA-1, RC4).",
		Remediation: "Use Node's built-in `crypto` module on a runtime backed by a FIPS-validated OpenSSL.",
		Reference:   "NIST CMVP",
	},
	{
		Ecosystem: "npm", Name: "bcrypt",
		RuleID: "FIPS-DEP-NPM-004", Severity: "HIGH",
		Reason:      "bcrypt is built on Blowfish, which is not FIPS 140-3 approved.",
		Remediation: "Use PBKDF2 via Node's `crypto.pbkdf2` with SHA-256/SHA-512.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "npm", Name: "bcryptjs",
		RuleID: "FIPS-DEP-NPM-004", Severity: "HIGH",
		Reason:      "bcryptjs implements bcrypt (Blowfish-based), which is not FIPS 140-3 approved.",
		Remediation: "Use PBKDF2 via Node's `crypto.pbkdf2` with SHA-256/SHA-512.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "npm", Name: "node-forge",
		RuleID: "FIPS-DEP-NPM-005", Severity: "MEDIUM",
		Reason:      "node-forge is pure-JavaScript and is not FIPS-validated. It includes implementations of non-approved algorithms.",
		Remediation: "Use Node's built-in `crypto` module on a FIPS-validated OpenSSL runtime.",
		Reference:   "NIST CMVP",
	},

	// ---- Go modules ----------------------------------------------------------
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/blowfish",
		RuleID: "FIPS-DEP-GO-001", Severity: "HIGH",
		Reason:      "Blowfish is not on the FIPS 140-3 approved cipher list.",
		Remediation: "Use crypto/aes.",
		Reference:   "FIPS 197",
	},
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/cast5",
		RuleID: "FIPS-DEP-GO-002", Severity: "HIGH",
		Reason:      "CAST5 is not FIPS 140-3 approved.",
		Remediation: "Use crypto/aes.",
		Reference:   "FIPS 197",
	},
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/twofish",
		RuleID: "FIPS-DEP-GO-003", Severity: "HIGH",
		Reason:      "Twofish is not FIPS 140-3 approved.",
		Remediation: "Use crypto/aes.",
		Reference:   "FIPS 197",
	},
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/xtea",
		RuleID: "FIPS-DEP-GO-004", Severity: "HIGH",
		Reason:      "XTEA is not FIPS 140-3 approved.",
		Remediation: "Use crypto/aes.",
		Reference:   "FIPS 197",
	},
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/md4",
		RuleID: "FIPS-DEP-GO-005", Severity: "HIGH",
		Reason:      "MD4 is not FIPS 140-3 approved.",
		Remediation: "Use crypto/sha256 or crypto/sha512.",
		Reference:   "FIPS 180-4",
	},
	{
		Ecosystem: "go", Name: "golang.org/x/crypto/bcrypt",
		RuleID: "FIPS-DEP-GO-006", Severity: "HIGH",
		Reason:      "bcrypt is built on Blowfish, which is not FIPS 140-3 approved.",
		Remediation: "Use golang.org/x/crypto/pbkdf2 with SHA-256/SHA-512.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "go", Name: "github.com/btcsuite/btcd/btcec",
		RuleID: "FIPS-DEP-GO-007", Severity: "HIGH",
		Reason:      "btcec implements secp256k1, which is not on the FIPS 186-5 approved curve list.",
		Remediation: "Use crypto/ecdsa with elliptic.P256/P384/P521.",
		Reference:   "FIPS 186-5",
	},
	{
		Ecosystem: "go", Name: "github.com/btcsuite/btcd/btcec/v2",
		RuleID: "FIPS-DEP-GO-007", Severity: "HIGH",
		Reason:      "btcec implements secp256k1, which is not on the FIPS 186-5 approved curve list.",
		Remediation: "Use crypto/ecdsa with elliptic.P256/P384/P521.",
		Reference:   "FIPS 186-5",
	},

	// ---- Maven (Java) --------------------------------------------------------
	{
		Ecosystem: "maven", Name: "org.bouncycastle:bcprov-jdk15on",
		RuleID: "FIPS-DEP-MVN-001", Severity: "MEDIUM",
		Reason:      "Standard BouncyCastle (bcprov-*) is NOT a FIPS-validated module. The FIPS-validated variant is `bc-fips`.",
		Remediation: "Replace with `org.bouncycastle:bc-fips` (BC-FJA, the FIPS-validated build).",
		Reference:   "NIST CMVP cert. #4616",
	},
	{
		Ecosystem: "maven", Name: "org.bouncycastle:bcprov-jdk18on",
		RuleID: "FIPS-DEP-MVN-001", Severity: "MEDIUM",
		Reason:      "Standard BouncyCastle (bcprov-*) is NOT a FIPS-validated module.",
		Remediation: "Replace with `org.bouncycastle:bc-fips` (BC-FJA, the FIPS-validated build).",
		Reference:   "NIST CMVP cert. #4616",
	},
	{
		Ecosystem: "maven", Name: "org.bouncycastle:bcpkix-jdk15on",
		RuleID: "FIPS-DEP-MVN-002", Severity: "MEDIUM",
		Reason:      "Standard BouncyCastle PKIX (bcpkix-*) is NOT a FIPS-validated module.",
		Remediation: "Replace with `org.bouncycastle:bcpkix-fips`.",
		Reference:   "NIST CMVP cert. #4616",
	},
	{
		Ecosystem: "maven", Name: "org.bouncycastle:bcpkix-jdk18on",
		RuleID: "FIPS-DEP-MVN-002", Severity: "MEDIUM",
		Reason:      "Standard BouncyCastle PKIX (bcpkix-*) is NOT a FIPS-validated module.",
		Remediation: "Replace with `org.bouncycastle:bcpkix-fips`.",
		Reference:   "NIST CMVP cert. #4616",
	},
	{
		Ecosystem: "maven", Name: "org.mindrot:jbcrypt",
		RuleID: "FIPS-DEP-MVN-003", Severity: "HIGH",
		Reason:      "jBCrypt implements bcrypt (Blowfish-based), which is not FIPS 140-3 approved.",
		Remediation: "Use PBKDF2 (javax.crypto.spec.PBEKeySpec with SHA-256/SHA-512).",
		Reference:   "NIST SP 800-132",
	},

	// ---- NuGet (.NET) --------------------------------------------------------
	{
		Ecosystem: "nuget", Name: "BCrypt.Net-Next",
		RuleID: "FIPS-DEP-NUGET-001", Severity: "HIGH",
		Reason:      "BCrypt.Net-Next implements bcrypt, which is not FIPS 140-3 approved.",
		Remediation: "Use Rfc2898DeriveBytes (PBKDF2) with SHA-256/SHA-512.",
		Reference:   "NIST SP 800-132",
	},
	{
		Ecosystem: "nuget", Name: "Portable.BouncyCastle",
		RuleID: "FIPS-DEP-NUGET-002", Severity: "MEDIUM",
		Reason:      "Portable.BouncyCastle is NOT a FIPS-validated module.",
		Remediation: "Use System.Security.Cryptography (CNG) on a Windows host with FIPS mode, or `BouncyCastle.NetCore.FIPS`.",
		Reference:   "NIST CMVP",
	},
	{
		Ecosystem: "nuget", Name: "BouncyCastle.NetCore",
		RuleID: "FIPS-DEP-NUGET-002", Severity: "MEDIUM",
		Reason:      "BouncyCastle.NetCore is NOT a FIPS-validated module. The .NET FIPS variant is `BouncyCastle.NetCore.FIPS`.",
		Remediation: "Replace with `BouncyCastle.NetCore.FIPS` or use System.Security.Cryptography (CNG) under FIPS mode.",
		Reference:   "NIST CMVP",
	},
}
