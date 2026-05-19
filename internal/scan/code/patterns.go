package code

import "regexp"

// Pattern describes one rule used to flag non-FIPS-approved cryptography.
// Languages is the set of file extensions the pattern applies to.
type Pattern struct {
	Rule        string
	Algorithm   string
	Severity    string
	Languages   []string
	Regex       *regexp.Regexp
	Remediation string
	Reference   string
}

// Patterns is the v0.1 detection set: MD5, SHA-1, DES, 3DES, RC4
// across Python, Go, Java, JavaScript/TypeScript, and C#.
//
// Severity guide:
//
//	HIGH   = algorithm is disallowed under FIPS 140-3 / SP 800-131A Rev. 2
//	MEDIUM = algorithm is restricted (e.g. SHA-1 disallowed for digital
//	         signatures but permitted in legacy verification contexts)
var Patterns = []Pattern{
	// ---- MD5 (FIPS-HASH-001) ---------------------------------------------
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`\bhashlib\.md5\s*\(|from\s+hashlib\s+import\s+[^#\n]*\bmd5\b|from\s+Crypto\.Hash\s+import\s+MD5\b|\bMD5\.new\s*\(|^\s*import\s+md5\b`),
		Remediation: "Replace MD5 with SHA-256 (hashlib.sha256). MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`"crypto/md5"|\bmd5\.New\s*\(|\bmd5\.Sum\s*\(`),
		Remediation: "Replace crypto/md5 with crypto/sha256. MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`MessageDigest\.getInstance\s*\(\s*"MD5"`),
		Remediation: `Replace MessageDigest.getInstance("MD5") with "SHA-256". MD5 is not FIPS 140-3 approved.`,
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".js", ".ts", ".mjs", ".cjs"},
		Regex: regexp.MustCompile(
			`(?i)createHash\s*\(\s*['"` + "`" + `]md5['"` + "`" + `]|require\s*\(\s*['"]md5['"]\s*\)|from\s+['"]md5['"]`),
		Remediation: "Replace MD5 with SHA-256: crypto.createHash('sha256'). MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".cs"},
		Regex: regexp.MustCompile(
			`\bMD5\.Create\s*\(\s*\)|\bMD5CryptoServiceProvider\b|new\s+HMACMD5\s*\(`),
		Remediation: "Replace MD5 with SHA256.Create(). MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},

	// ---- SHA-1 (FIPS-HASH-002) -------------------------------------------
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`\bhashlib\.sha1\s*\(|from\s+hashlib\s+import\s+[^#\n]*\bsha1\b|from\s+Crypto\.Hash\s+import\s+SHA1?\b|^\s*import\s+sha1?\b`),
		Remediation: "SHA-1 is disallowed for digital signatures (NIST SP 800-131A Rev. 2). Use SHA-256 or SHA-3.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`"crypto/sha1"|\bsha1\.New\s*\(|\bsha1\.Sum\s*\(`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use crypto/sha256 or crypto/sha512.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`MessageDigest\.getInstance\s*\(\s*"SHA-?1"`),
		Remediation: `Replace "SHA-1" / "SHA1" with "SHA-256". SHA-1 is disallowed for signatures.`,
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".js", ".ts", ".mjs", ".cjs"},
		Regex: regexp.MustCompile(
			`(?i)createHash\s*\(\s*['"` + "`" + `]sha-?1['"` + "`" + `]`),
		Remediation: "Replace 'sha1' with 'sha256' in crypto.createHash().",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".cs"},
		Regex: regexp.MustCompile(
			`\bSHA1\.Create\s*\(\s*\)|\bSHA1CryptoServiceProvider\b|\bSHA1Managed\b`),
		Remediation: "Replace SHA1 with SHA256.Create(). SHA-1 is disallowed for signatures.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},

	// ---- DES (FIPS-CIPHER-001) -------------------------------------------
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`from\s+Crypto\.Cipher\s+import\s+DES\b|\bDES\.new\s*\(`),
		Remediation: "DES is not FIPS 140-3 approved. Use AES (Crypto.Cipher.AES) with 128/192/256-bit keys.",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`"crypto/des"|\bdes\.NewCipher\s*\(`),
		Remediation: "DES is not FIPS 140-3 approved. Use crypto/aes.",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`Cipher\.getInstance\s*\(\s*"DES(/|")`),
		Remediation: "DES is not FIPS 140-3 approved. Use AES/GCM/NoPadding.",
		Reference:   "FIPS 197",
	},

	// ---- 3DES / TDEA (FIPS-CIPHER-002) — disallowed after 2023 -----------
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`from\s+Crypto\.Cipher\s+import\s+DES3\b|\bDES3\.new\s*\(`),
		Remediation: "3DES (TDEA) was disallowed after 2023 (NIST SP 800-131A Rev. 2). Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`\bdes\.NewTripleDESCipher\s*\(`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use crypto/aes.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`Cipher\.getInstance\s*\(\s*"(DESede|TripleDES)`),
		Remediation: "DESede / 3DES is disallowed after 2023. Use AES/GCM/NoPadding.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},

	// ---- RC4 / ARC4 (FIPS-CIPHER-003) ------------------------------------
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`from\s+Crypto\.Cipher\s+import\s+ARC4\b|\bARC4\.new\s*\(`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`"crypto/rc4"|\brc4\.NewCipher\s*\(`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use crypto/aes.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`Cipher\.getInstance\s*\(\s*"(RC4|ARCFOUR)`),
		Remediation: "RC4 / ARCFOUR is not FIPS 140-3 approved. Use AES/GCM/NoPadding.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},

	// ---- RSA <2048 (FIPS-KEY-001) ----------------------------------------
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`RSA\.generate\s*\(\s*(512|1024|2047)\b|key_size\s*=\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits per FIPS 186-5 / SP 800-131A Rev. 2.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`rsa\.GenerateKey\s*\([^,]+,\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits. Use rsa.GenerateKey(rand.Reader, 2048) or larger.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`\.initialize\s*\(\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits. Call kpg.initialize(2048) or larger.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".js", ".ts", ".mjs", ".cjs"},
		Regex: regexp.MustCompile(
			`modulusLength\s*:\s*(512|1024|2047)\b`),
		Remediation: "RSA modulusLength must be at least 2048.",
		Reference:   "FIPS 186-5",
	},

	// ---- DSA (FIPS-KEY-002) — disallowed (NIST SP 800-131A Rev. 2) -------
	{
		Rule: "FIPS-KEY-002", Algorithm: "DSA", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`from\s+Crypto\.PublicKey\s+import\s+DSA\b|\bDSA\.generate\s*\(`),
		Remediation: "DSA signature generation is disallowed (NIST SP 800-131A Rev. 2). Use RSA, ECDSA (P-256/P-384), or EdDSA.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-002", Algorithm: "DSA", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`"crypto/dsa"|\bdsa\.GenerateKey\s*\(`),
		Remediation: "DSA signature generation is disallowed. Use crypto/rsa, crypto/ecdsa, or crypto/ed25519.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-002", Algorithm: "DSA", Severity: "HIGH",
		Languages: []string{".java", ".kt", ".kts", ".scala"},
		Regex: regexp.MustCompile(
			`KeyPairGenerator\.getInstance\s*\(\s*"DSA"`),
		Remediation: "DSA signature generation is disallowed. Use RSA, ECDSA, or EdDSA.",
		Reference:   "FIPS 186-5",
	},

	// ---- secp256k1 (FIPS-CURVE-001) — non-NIST elliptic curve ------------
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".py"},
		Regex: regexp.MustCompile(
			`(?i)\bSECP256K1\s*\(\s*\)|ec\.SECP256K1\b`),
		Remediation: "secp256k1 is not on the FIPS 186-5 approved curve list. Use NIST P-256/P-384/P-521 (secp256r1/secp384r1/secp521r1).",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".go"},
		Regex: regexp.MustCompile(
			`(?i)\bsecp256k1\b`),
		Remediation: "secp256k1 is not FIPS 186-5 approved. Use elliptic.P256/P384/P521.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".js", ".ts", ".mjs", ".cjs"},
		Regex: regexp.MustCompile(
			`(?i)['"` + "`" + `]secp256k1['"` + "`" + `]`),
		Remediation: "secp256k1 is not FIPS 186-5 approved. Use 'P-256', 'P-384', or 'P-521'.",
		Reference:   "FIPS 186-5",
	},

	// ========================================================================
	// Ruby (.rb)
	// ========================================================================
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`\bDigest::MD5\b|require\s+['"]digest/md5['"]|OpenSSL::Digest\.new\s*\(\s*['"]MD5['"]\s*\)|OpenSSL::Digest::MD5\b`),
		Remediation: "Replace Digest::MD5 with Digest::SHA256. MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`\bDigest::SHA1\b|require\s+['"]digest/sha1['"]|OpenSSL::Digest\.new\s*\(\s*['"]SHA1['"]\s*\)|OpenSSL::Digest::SHA1\b`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use Digest::SHA256.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::Cipher\.new\s*\(\s*['"]DES(?:-[A-Z0-9-]+)?['"]\s*\)|OpenSSL::Cipher::DES\b`),
		Remediation: "DES is not FIPS 140-3 approved. Use OpenSSL::Cipher.new('AES-256-GCM').",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::Cipher\.new\s*\(\s*['"](?:DES-EDE3|3DES|TripleDES)`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::Cipher\.new\s*\(\s*['"]RC4['"]\s*\)|OpenSSL::Cipher::RC4\b`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::PKey::RSA\.(?:new|generate)\s*\(\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits. Use OpenSSL::PKey::RSA.new(2048) or larger.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-KEY-002", Algorithm: "DSA", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::PKey::DSA\b`),
		Remediation: "DSA signature generation is disallowed. Use OpenSSL::PKey::RSA or OpenSSL::PKey::EC.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".rb"},
		Regex: regexp.MustCompile(
			`OpenSSL::PKey::EC\.(?:new|generate)\s*\(\s*['"]secp256k1['"]\s*\)`),
		Remediation: "secp256k1 is not FIPS 186-5 approved. Use 'prime256v1' (P-256), 'secp384r1', or 'secp521r1'.",
		Reference:   "FIPS 186-5",
	},

	// ========================================================================
	// PHP (.php) — flags ext/standard md5/sha1, ext/mcrypt, and openssl_*
	// ========================================================================
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".php"},
		Regex: regexp.MustCompile(
			`\bmd5\s*\(|\bmd5_file\s*\(|\bhash\s*\(\s*['"]md5['"]|\bhash_init\s*\(\s*['"]md5['"]|\bhash_hmac\s*\(\s*['"]md5['"]`),
		Remediation: "Replace md5() with hash('sha256', ...). MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".php"},
		Regex: regexp.MustCompile(
			`\bsha1\s*\(|\bsha1_file\s*\(|\bhash\s*\(\s*['"]sha1['"]|\bhash_init\s*\(\s*['"]sha1['"]`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use hash('sha256', ...).",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".php"},
		Regex: regexp.MustCompile(
			`\bMCRYPT_DES\b|mcrypt_module_open\s*\(\s*['"]des['"]|openssl_(?:encrypt|decrypt)\s*\([^,]+,\s*['"]des-`),
		Remediation: "DES is not FIPS 140-3 approved. Use openssl_encrypt(..., 'aes-256-gcm', ...).",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".php"},
		Regex: regexp.MustCompile(
			`\bMCRYPT_3DES\b|\bMCRYPT_TRIPLEDES\b|openssl_(?:encrypt|decrypt)\s*\([^,]+,\s*['"]des-ede3`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".php"},
		Regex: regexp.MustCompile(
			`\bMCRYPT_ARCFOUR\b|openssl_(?:encrypt|decrypt)\s*\([^,]+,\s*['"]rc4`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},

	// ========================================================================
	// Rust (.rs)
	// ========================================================================
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`\bmd5::compute\b|use\s+md5(?:\b|::)|use\s+md_5::Md5\b|\bMd5::new\s*\(`),
		Remediation: "Replace the md5 / md-5 crate with sha2::Sha256. MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`use\s+sha1(?:\b|::)|use\s+sha_1::Sha1\b|\bSha1::new\s*\(`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use sha2::Sha256.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`use\s+des::Des\b|\bDes::new\b`),
		Remediation: "DES is not FIPS 140-3 approved. Use aes::Aes256 or aes-gcm.",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`use\s+des::TdesEde[23]\b|\bTdesEde[23]::new\b`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`use\s+rc4(?:\b|::)|\bRc4::new\b`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`RsaPrivateKey::new\s*\([^,]+,\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".rs"},
		Regex: regexp.MustCompile(
			`use\s+k256(?:\b|::)|use\s+secp256k1(?:\b|::)|extern\s+crate\s+secp256k1\b`),
		Remediation: "secp256k1 is not FIPS 186-5 approved. Use p256 or p384 crate.",
		Reference:   "FIPS 186-5",
	},

	// ========================================================================
	// C / C++ — OpenSSL legacy API (MD5_*, EVP_md5) and modern (EVP_MD_fetch)
	// ========================================================================
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bMD5_Init\b|\bMD5_Update\b|\bMD5_Final\b|\bEVP_md5\s*\(|EVP_MD_fetch\s*\([^,]*,\s*"MD5"`),
		Remediation: "Replace MD5_* / EVP_md5 with EVP_sha256. MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bSHA1_Init\b|\bSHA1_Update\b|\bSHA1_Final\b|\bEVP_sha1\s*\(|EVP_MD_fetch\s*\([^,]*,\s*"SHA-?1"`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use EVP_sha256.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bDES_set_key(?:_unchecked|_checked)?\b|\bDES_ecb_encrypt\b|\bDES_ncbc_encrypt\b|\bEVP_des_(?:ecb|cbc|cfb\d*|ofb)\s*\(`),
		Remediation: "DES is not FIPS 140-3 approved. Use EVP_aes_256_gcm.",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bDES_ede3_\w+\b|\bEVP_des_ede3(?:_\w+)?\s*\(|EVP_CIPHER_fetch\s*\([^,]*,\s*"DES-EDE3`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use EVP_aes_256_gcm.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bRC4_set_key\b|\bEVP_rc4\s*\(`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use EVP_aes_256_gcm.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-KEY-001", Algorithm: "RSA <2048", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`RSA_generate_key(?:_ex)?\s*\([^,]*,\s*(512|1024|2047)\b|EVP_PKEY_CTX_set_rsa_keygen_bits\s*\([^,]+,\s*(512|1024|2047)\b`),
		Remediation: "RSA keys must be at least 2048 bits.",
		Reference:   "FIPS 186-5",
	},
	{
		Rule: "FIPS-CURVE-001", Algorithm: "secp256k1", Severity: "HIGH",
		Languages: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
		Regex: regexp.MustCompile(
			`\bNID_secp256k1\b|"secp256k1"`),
		Remediation: "secp256k1 is not FIPS 186-5 approved. Use NID_X9_62_prime256v1, NID_secp384r1, or NID_secp521r1.",
		Reference:   "FIPS 186-5",
	},

	// ========================================================================
	// Swift (.swift) — CommonCrypto + CryptoKit's Insecure namespace
	// ========================================================================
	{
		Rule: "FIPS-HASH-001", Algorithm: "MD5", Severity: "HIGH",
		Languages: []string{".swift"},
		Regex: regexp.MustCompile(
			`\bCC_MD5\s*\(|\bInsecure\.MD5\b`),
		Remediation: "Replace CC_MD5 / Insecure.MD5 with SHA256 (CryptoKit). MD5 is not FIPS 140-3 approved.",
		Reference:   "FIPS 180-4",
	},
	{
		Rule: "FIPS-HASH-002", Algorithm: "SHA-1", Severity: "MEDIUM",
		Languages: []string{".swift"},
		Regex: regexp.MustCompile(
			`\bCC_SHA1\s*\(|\bInsecure\.SHA1\b`),
		Remediation: "SHA-1 is disallowed for digital signatures. Use SHA256 (CryptoKit).",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-001", Algorithm: "DES", Severity: "HIGH",
		Languages: []string{".swift"},
		Regex: regexp.MustCompile(
			`\bkCCAlgorithmDES\b`),
		Remediation: "DES is not FIPS 140-3 approved. Use kCCAlgorithmAES or AES.GCM (CryptoKit).",
		Reference:   "FIPS 197",
	},
	{
		Rule: "FIPS-CIPHER-002", Algorithm: "3DES (TDEA)", Severity: "HIGH",
		Languages: []string{".swift"},
		Regex: regexp.MustCompile(
			`\bkCCAlgorithm3DES\b`),
		Remediation: "3DES (TDEA) was disallowed after 2023. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
	{
		Rule: "FIPS-CIPHER-003", Algorithm: "RC4 (ARC4)", Severity: "HIGH",
		Languages: []string{".swift"},
		Regex: regexp.MustCompile(
			`\bkCCAlgorithmRC4\b`),
		Remediation: "RC4 is not FIPS 140-3 approved. Use AES.",
		Reference:   "NIST SP 800-131A Rev. 2",
	},
}
