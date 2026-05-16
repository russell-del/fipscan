# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Email a description and reproduction steps to `security@fipscan.dev` or use
GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
feature on this repository.

You can expect:

| Time | What |
|------|------|
| 48h  | Acknowledgement |
| 7d   | Initial triage with severity assessment |
| 30d  | Patched release (for HIGH / CRITICAL) |

We follow responsible disclosure. Reporters are credited in the release notes
unless they request otherwise.

## Verifying releases

Each release is signed with [cosign keyless](https://docs.sigstore.dev/cosign/overview/)
using GitHub Actions OIDC. Verify before installing:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/rbuilta/fipscan' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature  <artifact>.sig \
  --certificate <artifact>.crt \
  <artifact>
```

A CycloneDX 1.5 SBOM is published alongside each binary.

## FIPS posture

`fipscan` is built with Go 1.26's FIPS 140-3 cryptographic module
(`GOFIPS140=v1.0.0`). It uses only FIPS-approved primitives for its own
cryptography — TLS to GitHub / OCI registries via Go stdlib, password storage
via PBKDF2-HMAC-SHA256 (NIST SP 800-132).
