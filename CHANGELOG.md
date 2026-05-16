# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — initial public release

### Scanner

- **Source code scanning** across 12 languages: Python, Go, Java, Kotlin,
  Scala, JavaScript, TypeScript, C#, Ruby, PHP, Rust, C/C++, Swift.
  ~64 patterns covering MD5, SHA-1, DES, 3DES, RC4, RSA < 2048, DSA,
  secp256k1.
- **Dependency manifest scanning** for 7 formats: `requirements.txt`,
  `Pipfile.lock`, `pyproject.toml` (PEP 621 + Poetry), `go.mod`,
  `package-lock.json` (v1/v2/v3), `pom.xml`, `*.csproj`. Curated catalog
  of ~30 FIPS-relevant packages across PyPI / npm / Go / Maven / NuGet.
- **Container image scanning** via a stdlib-only OCI / Docker v2 client.
  Anonymous + Basic-auth registries. Streaming layer extraction
  (path-traversal-safe). Parses dpkg, apk, **and RPM** databases (the
  RPM parser uses a HEADERIMMUTABLE-sentinel scan over `rpmdb.sqlite`,
  avoiding a SQLite dependency). ELF `DT_NEEDED` inspection for
  distroless images. Identifies base OS and FIPS posture.
- **Outputs**: terminal, JSON, **SARIF 2.1.0** (GitHub Code Scanning
  ingestible).
- **`-exclude`** flag on code + deps scanners.
- **`-platform`** flag for multi-arch image manifests.
- **`-fail-on`** flag for CI gating.

### Server

- `fipscan server` subcommand: long-running watchlist, scheduled
  re-scans, embedded HTML dashboard, JSON API.
- File-backed JSON persistence under `-data`. Atomic writes.
- HTTP Basic auth with **PBKDF2-HMAC-SHA256** (NIST SP 800-132,
  600k iterations). `fipscan hash-password` subcommand. **bcrypt /
  scrypt / argon2 deliberately not used** — they are not FIPS-approved
  and would be flagged by the tool itself.
- Refuses to bind to a non-loopback address without authentication.
- **Webhook alerts** on new findings (Slack/Teams compatible payload
  plus structured JSON). Per-destination severity threshold. Diff
  against previous scan suppresses spam on identical re-scans. Test-fire
  endpoint for verifying receiver wiring.
- `-public-url` flag embeds clickable scan-detail links in alerts.

### Build & supply chain

- **Go 1.26 FIPS 140-3 cryptographic module** (`GOFIPS140=v1.0.0`).
  `fipscan -version` reports `fips140-module: v1.0.0 (enabled=true)` at
  runtime.
- **Zero third-party Go dependencies**.
- Reproducible builds (`-trimpath -buildvcs=false -ldflags="-s -w"`,
  `SOURCE_DATE_EPOCH` honored). Verified: two invocations produce
  byte-identical SHA-256.
- CycloneDX 1.5 SBOM generated per release.
- **Distroless multi-arch Docker image** at
  `ghcr.io/rbuilta/fipscan` (linux/amd64, linux/arm64).
- Cross-platform binaries: linux/amd64, linux/arm64, darwin/amd64,
  darwin/arm64, windows/amd64.
- Cosign keyless signatures via GitHub Actions OIDC for every artifact.
- **Dogfooded**: `make dogfood` runs `fipscan` against its own source
  tree and produces zero findings.

[1.0.0]: https://github.com/rbuilta/fipscan/releases/tag/v1.0.0
