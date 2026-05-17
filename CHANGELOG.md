# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [1.2.0] — More lockfile formats + Rust ecosystem

### Added

- **`uv.lock`** parser (PEP 723 + astral-sh/uv lockfile format).
- **`poetry.lock`** parser (Poetry classic lockfile).
- **`Cargo.lock`** parser (Rust crates.io lockfile).
- **`yarn.lock`** parser (Yarn classic / berry custom format).
- **Cargo / Rust ecosystem** in the FIPS-relevance catalog. 8 entries:
  `md5`, `md-5`, `sha1`, `sha-1`, `bcrypt`, `secp256k1`, `k256`,
  `rc4`, `des`.

The three TOML-based lockfiles (uv.lock, poetry.lock, Cargo.lock) all
serialise their resolved dependency set as `[[package]]` arrays-of-
tables — `parsePackageArrayTOML` handles all three with one
implementation; the parser functions are thin wrappers that exist only
so the scanner can register each filename with its own ecosystem
("pypi" vs "cargo").

### Tested

- Local fixtures: 125 → **146** findings (+21 from the four new
  manifest fixtures).
- `mitmproxy/mitmproxy` (real uv.lock): now surfaces `bcrypt 5.0.0` and
  `cryptography 46.0.4` from the lockfile, in addition to the
  pyproject.toml manifest declarations.
- `BurntSushi/ripgrep` (real Cargo.lock): 0 findings, fetch+parse
  worked end-to-end.

## [1.1.0] — GitLab + Bitbucket Cloud support

### Added

- **`source.Fetcher` interface** + factory `source.Choose(platform,
  config)`. Three implementations: `GitHubFetcher`, `GitLabFetcher`,
  `BitbucketFetcher`. All share the same hardened tarball-extract path
  (path-traversal rejection, size caps, link-skip).
- **GitLab** support (`-repo-platform=gitlab`). Cloud (gitlab.com) and
  self-hosted (set `FIPSCAN_GITLAB_HOST`). Auth via PAT in the
  `PRIVATE-TOKEN` header. Handles nested groups
  ("group/subgroup/project") by URL-encoding the spec.
- **Bitbucket Cloud** support (`-repo-platform=bitbucket`). Auth via
  HTTP Basic with username + app-password. (Bitbucket Data Center is a
  follow-up.)
- New CLI flags: `-repo-platform`, `-gitlab-token`,
  `-bitbucket-username`, `-bitbucket-password`. Env-var equivalents
  (`GITLAB_TOKEN`, `BITBUCKET_USERNAME`, `BITBUCKET_APP_PASSWORD`).
- Server watchlist: `Target.RepoHost` field. Add-target form has a
  platform dropdown. Dashboard surfaces the platform as a small badge
  next to the repo type pill. Scheduler dispatches to the correct
  fetcher per target.

### Changed

- `Fetcher.FetchRepo` is now `(spec, ref) → (dir, err)` — `spec` is the
  platform-conventional `owner/repo` or `group/project` string. Each
  fetcher parses what's appropriate for its API.
- `internal/source/github.go` shrank from 149 → ~50 LOC; common tarball
  extraction lives in `internal/source/source.go`.

### Tested against real public repos

- GitHub: `paramiko/paramiko` → 12 findings (regression baseline)
- GitLab: `gitlab-org/cli` → 2 SHA-1 findings
- Bitbucket Cloud: `atlassian/atlassian-event` → 0 findings

## [1.0.2] — SIEM-friendly audit log

### Added

- `internal/audit/` — new package emitting security-relevant events as
  ECS 8.x-compatible JSON lines. Natively parsed by Elastic, Splunk,
  Datadog, Sumo, Wazuh, Loki, etc.
- 10 event types: `server.started`, `server.stopped`,
  `auth.login_failure`, `target.added`, `target.deleted`,
  `target.scan_requested`, `scan.started`, `scan.completed`,
  `scan.failed`, `alert.configured`, `alert.unconfigured`,
  `alert.delivered`, `alert.delivery_failed`.
- `-audit-log <path>` flag and `FIPSCAN_AUDIT_LOG` env var. File
  opened `0o640` (owner rw, group r — typical for SIEM agent
  ingestion). Atomic per-line writes via `O_APPEND` semantics.
- Docker image enables audit by default at
  `/var/lib/fipscan/audit.log` so the log lives in the persisted
  volume.
- Each event carries: `@timestamp`, `event.{id,kind,category,type,action,outcome}`,
  `service.{name,version,type}`, `host.hostname`, and where relevant
  `source.ip`, `user.name`, plus a namespaced `fipscan.*` block with
  product-specific detail (target, scan, findings, alert).
- Source IP attribution uses `RemoteAddr` only — `X-Forwarded-For` is
  deliberately NOT trusted (would let any client spoof audit-log IPs).

## [1.0.1] — runtime FIPS-mode enforcement

### Changed

- Every subcommand (`scan`, `server`, `hash-password`) now refuses to
  start unless the FIPS 140-3 cryptographic module is linked AND
  `crypto/fips140.Enabled()` returns `true` at runtime. Fail-closed,
  exit 2, with remediation text. `-version` remains exempt so it stays
  usable for diagnosis.
- `make build` now defaults to `GOFIPS140=v1.0.0`. There is no longer
  a non-FIPS build path — every fipscan binary is a FIPS binary.

### Added

- `/api/v1/healthz` now reports `fips140_module` (module version) and
  `fips140_mode_enabled` (runtime state).
- Dashboard footer shows a FIPS-state badge on every page (green when
  active, amber if module is linked but disabled, red if no module).

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
