# fipscan

FIPS 140-3 readiness scanner for source code, dependency manifests, and container images.
Single Go binary, zero third-party dependencies, ships with its own FIPS 140-3 cryptographic module.

```text
$ fipscan -image alpine:3.19
[MEDIUM] libcrypto3 3.1.8-r1            — FIPS-CONT-OPENSSL-001
[MEDIUM] ELF-NEEDED: libcrypto.so.3      — FIPS-CONT-OPENSSL-001
[MEDIUM] base image: Alpine Linux v3.19  — FIPS-CONT-POSTURE-001
```

- **CLI** — scan a directory, a GitHub/GitLab/Bitbucket repo, or any OCI container image
- **Server** — self-hosted dashboard with a watchlist, scheduled re-scans, alerts, and an audit log
- **GitHub Action** — drop into a workflow, fail PRs on new HIGH findings, upload SARIF to Code Scanning

---

## 60-second quick start

```sh
# scan a container image
docker run --rm ghcr.io/russell-del/fipscan:latest -image alpine:3.19

# scan a public GitHub repo
docker run --rm ghcr.io/russell-del/fipscan:latest -repo paramiko/paramiko

# scan the current directory
docker run --rm -v "$PWD:/src" -w /src ghcr.io/russell-del/fipscan:latest -path .
```

---

## What it scans

| Surface | How |
|---|---|
| **Source code**, 13 languages | Python · Go · Java · Kotlin · Scala · JavaScript · TypeScript · C# · Ruby · PHP · Rust · C/C++ · Swift. Regex pattern catalog for MD5, SHA-1, DES, 3DES, RC4, RSA < 2048, DSA, secp256k1, etc. |
| **Dependency manifests**, 14+ formats | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` (PEP 621 + Poetry), `uv.lock`, `poetry.lock`, `go.mod`, `package-lock.json`, `yarn.lock`, `pom.xml`, `build.gradle(.kts)`, `libs.versions.toml`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `*.csproj`. Curated FIPS-relevance catalog + ~450 entries imported from OSV.dev. |
| **Container images** | OCI / Docker v2 distribution client: pulls manifest + layers directly over HTTPS from any registry (Docker Hub, GHCR, GCR, Red Hat, private). No Docker daemon required. Parses dpkg / apk / rpm databases; reads ELF `DT_NEEDED` for distroless images; identifies base OS and FIPS posture (`/etc/system-fips`, crypto-policies). |

Outputs: terminal (with color), JSON, **SARIF 2.1.0** (GitHub Code Scanning), **CSAF 2.0 VEX**.

---

## Install (CLI)

### Docker (recommended)

```sh
docker pull ghcr.io/russell-del/fipscan:latest
```

Multi-arch image (linux/amd64, linux/arm64). Tagged versions: `:v1.12.0`, `:latest`.

### Binary

Linux / macOS / Windows on amd64 + arm64. From the [latest release](https://github.com/russell-del/fipscan/releases/latest):

```sh
# Apple Silicon
curl -L -o fipscan https://github.com/russell-del/fipscan/releases/latest/download/fipscan-1.12.0-darwin-arm64
chmod +x fipscan

# Linux amd64
curl -L -o fipscan https://github.com/russell-del/fipscan/releases/latest/download/fipscan-1.12.0-linux-amd64
chmod +x fipscan
```

On macOS you may need to clear the quarantine bit: `xattr -d com.apple.quarantine ./fipscan`.

### Verify signatures (optional)

Every release artifact is signed with [cosign keyless](https://docs.sigstore.dev/cosign/overview/) (GitHub OIDC) and ships with a CycloneDX SBOM.

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/russell-del/fipscan' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature fipscan-1.12.0-linux-amd64.sig \
  --certificate fipscan-1.12.0-linux-amd64.crt \
  fipscan-1.12.0-linux-amd64
```

---

## Scanning guide

Every scan walks **both** source code and dependency manifests in one pass — you don't choose one or the other. Pick the *source* (local path / remote repo / container image) and `fipscan` does the rest.

> The examples below use the `fipscan` binary directly. If you'd rather run via Docker, prefix any command with `docker run --rm ghcr.io/russell-del/fipscan:latest` (and mount the workspace with `-v "$PWD:/src" -w /src` if you're scanning a local path).

### Scan local code

```sh
# current directory
fipscan -path .

# a specific project
fipscan -path ~/code/my-app

# skip vendored / generated paths (comma-separated, relative to -path)
fipscan -path . -exclude vendor,third_party,testdata

# write JSON for tooling, or SARIF for GitHub Code Scanning
fipscan -path . -format json  > findings.json
fipscan -path . -format sarif > fipscan.sarif

# baseline + diff (CI-friendly): record current state once, then surface only NEW findings
fipscan -path . -baseline-write baseline.json    # first run — capture the current set
fipscan -path . -baseline baseline.json          # subsequent runs — show only what's new
fipscan -path . -baseline baseline.json -show-resolved   # also list what got fixed

# CI gate: exit 1 if any HIGH findings exist
fipscan -path . -fail-on high

# waive a finding inline — drop this comment near the offending line:
#   // fipscan:waive FIPS-HASH-001 reason="legacy data, scheduled for removal in Q3"
fipscan -path . -show-waived   # see what was suppressed
```

Via Docker (mounting the current dir):

```sh
docker run --rm -v "$PWD:/src" -w /src ghcr.io/russell-del/fipscan:latest -path .
```

### Scan a GitHub repository

No `git` binary required — `fipscan` pulls the tarball over the GitHub API.

```sh
# public repo
fipscan -repo paramiko/paramiko

# specific branch / tag / commit SHA
fipscan -repo paramiko/paramiko -ref v3.4.0
fipscan -repo paramiko/paramiko -ref 1a2b3c4d

# private repo — needs a token with `repo` scope
fipscan -repo my-org/private-app -token "$GITHUB_TOKEN"
# or set GITHUB_TOKEN in the env and drop the flag
GITHUB_TOKEN=ghp_xxx fipscan -repo my-org/private-app
```

### Scan a GitLab project

```sh
# public project (note the URL-encoded namespace/name in -repo)
fipscan -repo gitlab-org/cli -repo-platform gitlab

# private project — PAT with `read_api` + `read_repository`
fipscan -repo my-group/my-project -repo-platform gitlab \
        -gitlab-token "$GITLAB_TOKEN"

# self-hosted GitLab not supported yet — open an issue if you need it
```

### Scan a Bitbucket Cloud repository

```sh
fipscan -repo atlassian/atlassian-event -repo-platform bitbucket

# private repo — Bitbucket app password (Repositories: read)
fipscan -repo my-team/my-repo -repo-platform bitbucket \
        -bitbucket-username "$BB_USER" \
        -bitbucket-password "$BB_APP_PASSWORD"
```

### Scan a container image

OCI / Docker v2 distribution client built in. **No Docker daemon required** — fipscan talks to the registry directly over HTTPS.

```sh
# from Docker Hub
fipscan -image alpine:3.19
fipscan -image debian:bookworm-slim
fipscan -image nginx:1.27

# distroless images (no apk/dpkg/rpm — fipscan reads ELF DT_NEEDED)
fipscan -image gcr.io/distroless/python3-debian12

# multi-arch images — pick a specific platform
fipscan -image alpine:3.19 -platform linux/arm64
fipscan -image debian:bookworm-slim -platform linux/arm/v7

# pin by digest for reproducibility
fipscan -image alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b

# images on GHCR / GCR / Red Hat / etc — registry inferred from the reference
fipscan -image ghcr.io/owner/app:v1.0.0
fipscan -image quay.io/prometheus/prometheus:v2.55.0
fipscan -image registry.access.redhat.com/ubi9/ubi-minimal:9.4

# private registry — basic auth
fipscan -image my-registry.example.com/app:v1.2.3 \
        -registry-username svc -registry-password "$REG_TOKEN"
# or via env: FIPSCAN_REGISTRY_USERNAME / FIPSCAN_REGISTRY_PASSWORD
```

### Output formats

| Format | Use for |
|---|---|
| `terminal` *(default)* | Local dev — colored output (auto-disabled when piped or `NO_COLOR` is set) |
| `json` | Scripting / custom tooling. Stable schema; `-baseline` + `-show-resolved` emits a `mode: "diff"` envelope. |
| `sarif` | GitHub Code Scanning — upload with `github/codeql-action/upload-sarif`. |
| `csaf` | CSAF 2.0 VEX export — for sharing vulnerability status with downstream consumers. |

### CI gating

```sh
# fail the build on any HIGH finding
fipscan -path . -fail-on high

# or fail only on NEW high-severity findings vs a tracked baseline
fipscan -path . -baseline baseline.json -fail-on high
```

Exit codes: `0` = no findings at/above the `-fail-on` threshold · `1` = findings present · `2` = tool error.

### Full flag list

```sh
fipscan -h            # scan flags
fipscan server -h     # server flags
fipscan hash-password # read a password from stdin, print a PBKDF2 hash
```

---

## Run your own server

The same binary runs as a self-hosted server with a watchlist, scheduled re-scans, a JSON API, an embedded HTML dashboard, and Slack/Teams/webhook alerts on new findings.

### Option A — Docker, one command

```sh
# 1. generate a password hash (PBKDF2-HMAC-SHA256, 600k iters — NIST SP 800-132)
HASH=$(echo -n 'pick-a-strong-password' | docker run --rm -i ghcr.io/russell-del/fipscan:latest hash-password)

# 2. run the server
docker run -d --name fipscan \
  -p 8080:8080 \
  -e FIPSCAN_AUTH_PASSWORD_HASH="$HASH" \
  -v fipscan-data:/var/lib/fipscan \
  ghcr.io/russell-del/fipscan:latest server -listen 0.0.0.0:8080 -data /var/lib/fipscan

# 3. open the dashboard
open http://localhost:8080
# username: admin   password: pick-a-strong-password
```

### Option B — docker-compose (recommended)

The repo ships a [`docker-compose.yml`](docker-compose.yml). Generate a password hash, drop it in `.env`, then:

```sh
# .env
FIPSCAN_AUTH_PASSWORD_HASH=pbkdf2-sha256$600000$...   # output of `fipscan hash-password`
# optional: GITHUB_TOKEN, FIPSCAN_REGISTRY_USERNAME, FIPSCAN_REGISTRY_PASSWORD
```

```sh
docker compose up -d
docker compose logs -f fipscan
```

### Option C — binary + systemd

```sh
sudo install -m 0755 fipscan /usr/local/bin/fipscan
sudo useradd -r -s /usr/sbin/nologin fipscan
sudo mkdir -p /var/lib/fipscan && sudo chown fipscan:fipscan /var/lib/fipscan

sudo tee /etc/fipscan.env >/dev/null <<EOF
FIPSCAN_AUTH_PASSWORD_HASH=pbkdf2-sha256$600000$...
FIPSCAN_AUDIT_LOG=/var/log/fipscan/audit.jsonl
FIPSCAN_PUBLIC_URL=https://fipscan.example.com
EOF

sudo tee /etc/systemd/system/fipscan.service >/dev/null <<'EOF'
[Unit]
Description=fipscan server
After=network-online.target

[Service]
User=fipscan
Group=fipscan
EnvironmentFile=/etc/fipscan.env
ExecStart=/usr/local/bin/fipscan server -listen 127.0.0.1:8080 -data /var/lib/fipscan
Restart=on-failure
ProtectSystem=strict
ReadWritePaths=/var/lib/fipscan /var/log/fipscan
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload && sudo systemctl enable --now fipscan
```

### Configuration reference

| Flag | Env var | Default | Description |
|---|---|---|---|
| `-listen` | — | `127.0.0.1:8080` | Bind address. **Default is loopback only** — set to `0.0.0.0:8080` to expose. Server refuses to bind a non-loopback address unless `FIPSCAN_AUTH_PASSWORD_HASH` is set. |
| `-data` | — | `./fipscan-data` | Directory for persisted state (watchlist, scan results — JSON files, no DB). |
| `-interval` | — | `24h` | How often the scheduler re-scans each watchlist target. |
| `-auth-user` | — | `admin` | Username for HTTP Basic auth. |
| `-auth-password-hash` | `FIPSCAN_AUTH_PASSWORD_HASH` | — | PBKDF2 password hash. Generate with `fipscan hash-password`. |
| `-public-url` | `FIPSCAN_PUBLIC_URL` | — | Externally visible base URL. Embedded in alert payloads so links resolve. |
| `-audit-log` | `FIPSCAN_AUDIT_LOG` | stderr | Path to JSONL audit log (ECS 8.x — Elastic Common Schema, SIEM-friendly). |
| — | `GITHUB_TOKEN` | — | Token for scanning private GitHub repos. |
| — | `GITLAB_TOKEN` | — | PAT for private GitLab projects. |
| — | `BITBUCKET_USERNAME` / `BITBUCKET_APP_PASSWORD` | — | Credentials for private Bitbucket Cloud repos. |
| — | `FIPSCAN_REGISTRY_USERNAME` / `FIPSCAN_REGISTRY_PASSWORD` | — | Credentials for private OCI registries. |

### Reverse proxy (TLS termination)

The server speaks plain HTTP — put it behind nginx, Caddy, or Traefik for TLS. Caddy example:

```caddy
fipscan.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Set `FIPSCAN_PUBLIC_URL=https://fipscan.example.com` so alert links point at the right hostname.

### Backup

All state is JSON under `-data` (default `./fipscan-data` or `/var/lib/fipscan` in the container). To back up: snapshot that directory. To restore: stop the server, drop the directory back, restart.

### Alerts

Configure webhooks per watchlist target in the dashboard. Slack and Microsoft Teams payload formats are supported out of the box. Alerts fire only on **new** findings (diff against the previous scan), so re-scans of unchanged code don't spam.

### Audit log

When `FIPSCAN_AUDIT_LOG` is set, every state change writes a single JSONL line in [Elastic Common Schema 8.x](https://www.elastic.co/guide/en/ecs/current/index.html) — ingestible by Splunk, Elastic, Datadog, Sumo, etc. Events: server.started/stopped, auth.login_failure, target.added/deleted, scan.started/completed/failed, alert.delivered/delivery_failed.

---

## GitHub Action

Fail PRs on new HIGH findings and upload SARIF to Code Scanning:

```yaml
# .github/workflows/fipscan.yml
name: fipscan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: russell-del/fipscan/actions/scan@v1.12.0
        with:
          path: .
          format: sarif
          fail-on: high
          output: fipscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: fipscan.sarif
```

See [actions/scan/README.md](actions/scan/README.md) for baseline/diff PR comments and image scanning.

---

## FIPS posture

`fipscan` itself is built with Go 1.26's native FIPS 140-3 cryptographic module (`GOFIPS140=v1.0.0`). At runtime:

```sh
$ fipscan -version
fipscan 1.12.0
fips140-module: v1.0.0 (enabled=true)
```

The tool refuses to start if the FIPS module is not enabled. It uses only FIPS-approved algorithms for its own crypto (TLS to registries, PBKDF2 for password storage). **PBKDF2-HMAC-SHA256**, not bcrypt / scrypt / argon2 — those are not FIPS-approved and `fipscan`'s own catalog would flag them.

### Reproducible builds & supply chain

- `CGO_ENABLED=0`, pure Go, static binary (no system libc)
- `-trimpath -buildvcs=false -ldflags="-s -w"`
- **Zero third-party Go dependencies** — audit surface is the Go standard library only
- CycloneDX 1.5 SBOM published with every release
- Reproducible: `make reproducibility-check` verifies two builds produce identical sha256
- Each artifact signed with cosign keyless (GitHub OIDC)

### Dogfooded

```sh
make dogfood   # runs fipscan on its own source; expected: zero findings
```

---

## Status

This is a **FIPS readiness scanner**, not a FIPS certification authority. Findings highlight cryptography that would block a CMVP/CAVP review. Final validation is NIST's job.

The catalog grows from real findings. PRs adding new packages, algorithms, or language patterns are welcome.

## License

[MIT](LICENSE).
