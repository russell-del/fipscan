# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [1.8.0] — OSV importer (catalog grows from ~80 → 290+)

### Added

- **`internal/osv/`** — minimal OSV (osv.dev) schema, downloader, and
  filter. Stream-extracts the per-ecosystem ZIP bundles published at
  `osv-vulnerabilities.storage.googleapis.com`. Stdlib only.
- **`cmd/fipscan-osv-import`** — codegen tool that downloads all 8
  supported OSV ecosystems (PyPI, npm, Go, Maven, crates.io,
  RubyGems, Packagist, NuGet), filters to crypto-relevant CVEs, and
  emits Go source for `internal/deps/osv_entries.go` (committed to
  the repo — single-binary distribution, no runtime catalog file).
- **`make update-catalog`** — one-line catalog refresh. Run before a
  release to pull in new CVEs.
- **Per-affected-package filtering** — when a CVE is crypto-relevant
  via keyword match (not package allowlist hit), we emit catalog
  entries only for packages on the known-crypto allowlist. Stops a
  CVE that mentions "TLS" once from polluting the catalog with
  entries for every unrelated package in its affected list.
- **Word-boundary keyword matching** — surrounding-space lookups so
  ` tls ` matches but `tlsx` doesn't.

### Catalog growth

| Source | Entries |
|---|---|
| Hand-curated (`data.go`) | 52 |
| **OSV-imported** (`osv_entries.go`) | **214** |
| Total dep catalog | **266** |
| Container catalog | 31 (unchanged) |
| Code pattern matrix | 61 (unchanged) |

OSV breakdown: PyPI 70 · npm 58 · Maven 46 · Go 33 · RubyGems 5 ·
NuGet 2. Real CVEs: ChaCha20-Poly1305 Terrapin attack
(GHSA-45x7-px36-x8w8) on `golang.org/x/crypto`, multiple recent
`cryptography` issues including CVE windows that affect 46.0.x.

### Tuning history

| Attempt | Filter | Entries | Notes |
|---|---|---|---|
| 1 | Broad keywords ("key", "encrypt", "random", "verification") | 26,779 | Way too many false positives — XSS, DoS, unaligned-read CVEs leaked in |
| 2 | **Tight keywords + word boundaries + per-affected-package filter** | **214** | Real crypto CVEs only. False negatives recoverable by adding to the allowlist. |

### Real-world impact

`mitmproxy/mitmproxy` jumped 6 → 16 findings: the OSV import surfaces
several CVEs against the `cryptography 46.0.4` they currently ship —
the kind of "your tool just told me about a CVE I didn't know about"
moment that justifies a paid product.

## [1.7.0] — Gradle Version Catalogs + pyproject.toml `[project.optional-dependencies]`

### Added

- **`gradle/libs.versions.toml`** parser. Resolves both the `[versions]`
  table (including Gradle's rich-version forms — `{ strictly = "X" }`,
  `{ require = "X" }`, `{ prefer = "X" }`) and the `[libraries]` table
  in every common shape:
  - `alias = { module = "g:a", version.ref = "name" }`
  - `alias = { module = "g:a", version = "x" }`
  - `alias = { group = "g", name = "a", version = "x" }`
  - `alias = "g:a:v"` (shorthand string form)
  - Single OR double quotes accepted throughout
  - `[plugins]` deliberately skipped — plugin coordinates aren't
    runtime/test deps
- **`[project.optional-dependencies]` block** in `pyproject.toml`.
  Single-line (`test = ["pytest"]`) and multi-line array forms both
  handled. Optional groups get installed when users do
  `pip install pkg[extras]`, so they're flagged at the same severity
  as main `dependencies`.
- **Two new Maven catalog entries** for `org.bouncycastle:bcpg-jdk15on`
  and `bcpg-jdk18on` (the OpenPGP variant — not FIPS-validated).
- `libs.versions.toml` priority **20** in the dedup table — for
  projects that use Version Catalogs, the catalog is the
  authoritative source (build.gradle.kts only contains aliases).
- `internal/deps/version_catalog_test.go` — 2 sub-tests covering all
  library forms + the unresolvable-version.ref fail-safe.

### Verified end-to-end on the real world

- **`bisq-network/bisq`** (multi-module Java/Gradle DEX) now surfaces
  `org.bouncycastle:bcpg-jdk18on 1.84` from
  `gradle/libs.versions.toml:64`. v1.6.0 returned 0 deps findings on
  this repo — the version-catalog parser was the missing piece.
- Fixtures (`-no-dedup`): 161 → **165** (+3 from gradle catalog
  fixture, +1 from pyproject optional-dependencies pycrypto).
- Default-deduped total unchanged at **133** (every new finding is a
  cross-format dup, correctly collapsed).

### Tests

`internal/deps` now has **6 test files / 13 sub-tests** covering
version parsing, constraints, dedup, Gradle DSL, Gradle Version
Catalog, and parser unresolvable-ref edge cases.

## [1.6.0] — Gradle (Groovy DSL + Kotlin DSL)

### Added

- **`build.gradle`** + **`build.gradle.kts`** parsers — closes the
  JVM ecosystem hole. Captures dep declarations from every standard
  configuration (`implementation`, `api`, `compileOnly`, `runtimeOnly`,
  `testImplementation`, `kapt`, `annotationProcessor`, etc.) using
  short notation:

  ```groovy
  implementation 'org.bouncycastle:bcprov-jdk18on:1.77'
  api "org.bouncycastle:bcpkix-jdk18on:1.77"
  ```

  ```kotlin
  implementation("org.bouncycastle:bcprov-jdk18on:1.77")
  implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.1"))
  ```

  Gradle deps share the `maven` ecosystem with `pom.xml` — same
  catalog entries fire (`bcprov-*`, `bcpkix-*`, `jbcrypt`).

- Two-pass regex (config-keyword line filter + coord extraction)
  handles wrapper forms like `platform(...)` and `enforcedPlatform(...)`.
- Gradle filenames added to the dedup priority table so they collapse
  cleanly with `pom.xml` when a project ships both (rare).
- `internal/deps/gradle_test.go` — Groovy DSL + Kotlin DSL coverage,
  with assertions that project / file / commented-out deps are
  correctly skipped.

### Not yet supported

- **Map notation** (`implementation group: 'x', name: 'y', version: 'z'`)
  — uncommon, will add when a customer reports it.
- **Gradle Version Catalogs** (`gradle/libs.versions.toml`) — modern
  multi-module projects increasingly use these. Separate parser, future
  release.
- **Variable substitution** (`implementation "$springVer:..."`) — can't
  resolve without a Groovy/Kotlin interpreter.

### Tested

- Fixtures (`-no-dedup`): 156 → **161** (+5 from Gradle fixtures).
  Default-deduped total stays at 133 because the Gradle deps overlap
  exactly with `pom.xml` in the fixture set.
- Unit tests: `TestParseGradle` + `TestParseGradleKotlinDSL` pass.
- Real Gradle projects (square/okhttp, mockito/mockito) scan clean
  end-to-end. apache/kafka surfaces a `pycrypto` from a docker test
  requirements.txt — an amusing cross-language find from a Java
  project's docker dir.

### Coverage so far — **14 manifest formats across 8 ecosystems**

| Ecosystem | Formats |
|---|---|
| Python (PyPI) | `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `uv.lock` |
| Node (npm) | `package-lock.json`, `yarn.lock` |
| Go | `go.mod` |
| Java/Maven | `pom.xml`, **`build.gradle`**, **`build.gradle.kts`** |
| .NET/NuGet | `*.csproj` |
| Rust/Cargo | `Cargo.lock` |
| Ruby/RubyGems | `Gemfile.lock` |
| PHP/Composer | `composer.lock` |

## [1.5.0] — Cross-manifest dedup

### Added

- **`internal/deps/dedup.go`** with `Dedup([]Finding) []Finding`. When
  the same package fires the same rule from multiple manifests in one
  project, only the finding from the highest-priority manifest is
  kept. Lockfiles (uv.lock, poetry.lock, Pipfile.lock, yarn.lock,
  package-lock.json) outrank declarative manifests (pyproject.toml,
  requirements.txt) because they carry the resolved version.
- `internal/deps/dedup_test.go` — 5 sub-tests covering: lockfile
  precedence, range-split entries (different rules, both kept),
  different packages with same rule (both kept), code findings (pass
  through), order preservation.
- **CLI `-no-dedup`** flag for users who want the raw output.
- Server scheduler dedupes unconditionally — dashboard noise drops
  for any Python or Node project that ships both a manifest and a
  lockfile.

### Tested

| Test | Before | After |
|---|---|---|
| Local fixtures | 156 | **133** (23 duplicates collapsed) |
| Same scan with `-no-dedup` | 156 | 156 (baseline preserved) |
| `bcrypt` across requirements/Pipfile/pyproject/uv.lock fixtures | 4 findings | **1** (kept the uv.lock entry) |
| `mitmproxy/mitmproxy` real-world | 6 (2 bcrypt + 2 cryptography + 2 code) | **4** (1 bcrypt + 1 cryptography + 2 code) |
| `make dogfood` | clean | clean |
| `go test ./internal/deps/` | 3 tests | **8 tests** (5 new) |

## [1.4.0] — Version-range matching in the catalog (+ first unit tests)

### Added

- **`internal/deps/version.go`** — a pragmatic SemVer-ish version
  parser and constraint set. Accepts the common operators (`<`, `<=`,
  `>`, `>=`, `==`, `!=`) and intersections (`>=1.0,<2.0`). Truncates
  to major.minor.patch — distro release suffixes (`-r1`, `-11.el9`),
  SemVer pre-release (`-rc.1`), and build metadata (`+abi.7`) are
  ignored so the catalog can match real-world version strings without
  per-ecosystem parsers.
- **`CatalogEntry.AffectedVersions` field** — optional constraint that
  narrows an entry to a version range. Empty means "applies to all
  versions" (backward compatible — existing entries unchanged).
- **Multiple entries per (ecosystem, name) are now supported.** The
  same package can carry different severities for different version
  windows.
- **`internal/deps/version_test.go`** — first real unit-test file in
  the codebase. `ParseVersion`, `Compare`, and `Constraint` covered
  with table-driven tests. Run via `go test ./...`.

### Demonstrated with two real CVE boundaries

- **`cryptography <39.0.1`** → HIGH (`FIPS-DEP-PYPI-006-CVE`,
  CVE-2023-23931 memory corruption). **`>=39.0.1`** → MEDIUM
  (bundled-OpenSSL FIPS posture only).
- **`node-forge <1.3.0`** → HIGH (`FIPS-DEP-NPM-005-CVE`,
  CVE-2022-24771 / 24772 / 24773 RSA PKCS#1 v1.5 signature bypass).
  **`>=1.3.0`** → MEDIUM (non-FIPS posture only).

### Changed

- `Lookup` signature changed from `(ecosystem, name) → *CatalogEntry`
  to `(ecosystem, name, version) → []CatalogEntry`. Scanner loops over
  matches so a package can emit multiple findings if multiple entries
  apply.

### Tested

- Local fixtures: 155 → **156** (`testdata/manifests/legacy/requirements.txt`
  added with `cryptography==30.0.0` — fires the HIGH CVE entry).
- Real-world: `mitmproxy/mitmproxy` `cryptography 46.0.4` now correctly
  fires only the MEDIUM posture entry (not both).
- Range mechanism verified: `node-forge 1.3.1` in two existing fixtures
  → MEDIUM only (not both HIGH and MEDIUM).

## [1.3.0] — Ruby (Gemfile.lock) + PHP (composer.lock) ecosystems

### Added

- **`Gemfile.lock`** parser (Bundler lockfile, Ruby). Captures gems at
  exactly 4-space indent inside any `specs:` block; transitive deps
  (6+ spaces) are skipped via the regex anchor.
- **`composer.lock`** parser (Composer lockfile, PHP). JSON; reads
  both the `packages` and `packages-dev` arrays.
- **RubyGems ecosystem** in the FIPS catalog. 6 entries: `bcrypt`,
  `bcrypt-ruby`, `scrypt`, `argon2`, `rbnacl`, `eth`.
- **Composer ecosystem** in the FIPS catalog. 4 entries:
  `phpseclib/phpseclib`, `paragonie/halite`, `mdanter/ecc`,
  `web3p/ethereum-tx`.

### Tested

- Local fixtures: 146 → **155** findings (+9 across the two new
  manifest fixtures).
- `mastodon/mastodon` (real Rails Gemfile.lock): surfaces
  `bcrypt 3.1.22`.
- `phpmyadmin/phpmyadmin` (real composer.lock): 36 code findings
  (PHP source patterns firing), 0 composer-package findings — their
  composer.lock simply doesn't ship any of the cataloged packages
  (most PHP projects use the built-in `openssl_*` functions, which
  the code scanner already detects).

### Coverage so far — 13 dependency manifest formats across 7 ecosystems

| Ecosystem | Formats |
|---|---|
| Python (PyPI) | `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `uv.lock` |
| Node (npm) | `package-lock.json`, `yarn.lock` |
| Go | `go.mod` |
| Java/Maven | `pom.xml` |
| .NET/NuGet | `*.csproj` |
| Rust/Cargo | `Cargo.lock` |
| Ruby/RubyGems | `Gemfile.lock` |
| PHP/Composer | `composer.lock` |

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
