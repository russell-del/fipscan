# fipscan

FIPS 140-3 readiness scanner for source code, dependency manifests, and container images.
Single Go binary, zero third-party dependencies, ships with its own FIPS 140-3
cryptographic module.

```text
$ fipscan -image alpine:3.19
[MEDIUM] libcrypto3 3.1.8-r1            — FIPS-CONT-OPENSSL-001
[MEDIUM] ELF-NEEDED: libcrypto.so.3      — FIPS-CONT-OPENSSL-001
[MEDIUM] base image: Alpine Linux v3.19  — FIPS-CONT-POSTURE-001
```

## What it scans

| Surface | How |
|---|---|
| **Source code**, 12 languages | Python · Go · Java · Kotlin · Scala · JavaScript · TypeScript · C# · Ruby · PHP · Rust · C/C++ · Swift. Regex-based pattern catalog for MD5, SHA-1, DES, 3DES, RC4, RSA < 2048, DSA, secp256k1, etc. |
| **Dependency manifests**, 7 formats | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` (PEP 621 + Poetry), `go.mod`, `package-lock.json`, `pom.xml`, `*.csproj`. Curated FIPS-relevance catalog covering ~30 packages across PyPI / npm / Go / Maven / NuGet. |
| **Container images** | OCI / Docker v2 distribution client: pulls manifest + layers directly over HTTPS from any registry (Docker Hub, GHCR, GCR, Red Hat, private). No Docker daemon required. Parses dpkg / apk / rpm databases; reads ELF `DT_NEEDED` for distroless images; identifies base OS and FIPS posture (`/etc/system-fips`, crypto-policies). |

Outputs: terminal, JSON, **SARIF 2.1.0** (ingested directly by GitHub Code Scanning).

## Install

```sh
# Docker (recommended)
docker run --rm russell-del/fipscan:latest -image alpine:3.19

# Homebrew (macOS / Linux)
brew install russell-del/tap/fipscan

# Direct binary (Linux / macOS / Windows on amd64 + arm64)
curl -L -o fipscan https://github.com/russell-del/fipscan/releases/latest/download/fipscan-$(uname -s | tr A-Z a-z)-$(uname -m)
chmod +x fipscan
```

Each release is signed with [cosign keyless](https://docs.sigstore.dev/cosign/overview/) and
ships with a CycloneDX SBOM. Verify before installing:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/russell-del/fipscan' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature fipscan-linux-amd64.sig \
  --certificate fipscan-linux-amd64.crt \
  fipscan-linux-amd64
```

## CLI usage

```sh
# Source code
fipscan -path ./my-project
fipscan -path ./my-project -format sarif > fipscan.sarif

# GitHub repository (no git binary required — pulls tarball)
fipscan -repo owner/name [-ref main] [-token $GITHUB_TOKEN]

# Container image
fipscan -image debian:bookworm-slim
fipscan -image gcr.io/distroless/python3-debian12 -platform linux/arm64
fipscan -image my-registry.example.com/app:v1.2.3 \
        -registry-username svc -registry-password "$REG_TOKEN"

# CI gating
fipscan -path . -fail-on high   # exit 1 if any HIGH findings exist
```

## Server / dashboard

The same binary runs as a self-hosted server with a watchlist, scheduled re-scans,
embedded HTML dashboard, JSON API, and Slack/Teams/webhook alerts.

```sh
# Generate a password hash (PBKDF2-HMAC-SHA256, 600k iterations — NIST SP 800-132)
echo -n 'my-secret' | fipscan hash-password
# → pbkdf2-sha256$600000$...

# Run the server
docker run -d --name fipscan -p 8080:8080 \
  -e FIPSCAN_AUTH_PASSWORD_HASH='pbkdf2-sha256$600000$...' \
  -v fipscan-data:/var/lib/fipscan \
  russell-del/fipscan:latest

# Open http://localhost:8080
# Username: admin    Password: my-secret
```

Server features:
- Watchlist of repos and container images
- Background scheduler (default: re-scan every 24h)
- Webhook alerts on **new** findings (diff against previous scan — no spam on
  identical re-scans). Slack/Teams compatible payload by default.
- HTTP Basic auth via PBKDF2; refuses to bind to a non-loopback address without
  authentication configured

## FIPS posture

`fipscan` itself is built with Go 1.26's native FIPS 140-3 cryptographic module
(`GOFIPS140=v1.0.0`). At runtime:

```sh
$ fipscan -version
fipscan 1.0.0
fips140-module: v1.0.0 (enabled=true)
```

The tool deliberately uses only FIPS-approved algorithms for its own crypto
(TLS to GitHub / OCI registries, PBKDF2 for password storage). It uses
**PBKDF2-HMAC-SHA256**, not bcrypt / scrypt / argon2 — those are not
FIPS-approved and `fipscan`'s own catalog would flag them.

### Reproducible builds & supply chain

- `CGO_ENABLED=0`, pure-Go, static binary (no system libc dependency)
- `-trimpath -buildvcs=false -ldflags="-s -w"`
- **Zero third-party Go dependencies** — audit surface is the Go standard
  library only
- CycloneDX 1.5 SBOM published with every release
- Reproducible: `make reproducibility-check` verifies two builds produce
  identical sha256

### Dogfooded

```sh
make dogfood    # runs fipscan on its own source; expected: zero findings
```

## Status

This is a **FIPS readiness scanner**, not a FIPS certification authority.
Findings highlight cryptography that would block a CMVP/CAVP review. Final
validation is NIST's job.

The catalog grows from real customer findings. PRs adding new packages,
algorithms, or language patterns are welcome.

## License

[MIT](LICENSE).
