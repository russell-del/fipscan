#!/usr/bin/env bash
# Emit a CycloneDX 1.5 SBOM for fipscan to stdout.
#
# fipscan has zero third-party Go dependencies — the SBOM is intentionally
# small: one primary component (fipscan itself) plus the Go toolchain
# declared as the build tool. If real deps are ever added, list them here.

set -euo pipefail

VERSION="${1:?usage: gen-sbom.sh <fipscan-version> <go-version>}"
GO_VERSION="${2:?usage: gen-sbom.sh <fipscan-version> <go-version>}"

# Reproducible "now" — SOURCE_DATE_EPOCH overrides if set, else fall back
# to commit timestamp, else 1970-01-01.
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  TS_EPOCH="$SOURCE_DATE_EPOCH"
elif command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  TS_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || echo 0)"
else
  TS_EPOCH=0
fi
TS="$(date -u -r "$TS_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$TS_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

cat <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-a000-000000000001",
  "version": 1,
  "metadata": {
    "timestamp": "$TS",
    "tools": [
      { "vendor": "fipscan", "name": "gen-sbom.sh", "version": "1.0" }
    ],
    "component": {
      "type": "application",
      "bom-ref": "pkg:generic/fipscan@$VERSION",
      "name": "fipscan",
      "version": "$VERSION",
      "description": "FIPS 140-3 readiness scanner for source code, dependency manifests, and container images.",
      "licenses": [],
      "purl": "pkg:generic/fipscan@$VERSION"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:generic/go-stdlib@$GO_VERSION",
      "name": "go-stdlib",
      "version": "$GO_VERSION",
      "description": "Go standard library, including the Go Cryptographic Module (FIPS 140-3) when built with GOFIPS140=v1.0.0.",
      "purl": "pkg:generic/go-stdlib@$GO_VERSION",
      "properties": [
        { "name": "fips140:module-version", "value": "v1.0.0" },
        { "name": "fips140:status",         "value": "see https://go.dev/doc/security/fips140" }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:generic/fipscan@$VERSION",
      "dependsOn": ["pkg:generic/go-stdlib@$GO_VERSION"]
    }
  ]
}
JSON
