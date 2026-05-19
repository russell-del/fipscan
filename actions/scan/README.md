# fipscan / Scan Action

GitHub Action wrapping the `fipscan` CLI. Runs in the `ghcr.io/russell-del/fipscan` Docker image — no separate install step, no caching gymnastics.

## Quick start — fail PRs on new HIGH findings

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

## Baseline / diff for PR comments

```yaml
- uses: russell-del/fipscan/actions/scan@v1.12.0
  with:
    path: .
    format: json
    baseline: baseline.json
    show-resolved: 'true'
    output: diff.json

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const diff = require('./diff.json');
      const newCount = diff.summary.total;
      const fixedCount = diff.resolved_summary?.total ?? 0;
      const body = `fipscan: **${newCount}** new finding(s), **${fixedCount}** fixed since baseline.`;
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body
      });
```

## Scan a container image

```yaml
- uses: russell-del/fipscan/actions/scan@v1.12.0
  with:
    image: alpine:3.19
    format: csaf
    output: alpine-scan.csaf.json
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Local path to scan (relative to the workspace) |
| `repo` | — | GitHub repo `owner/name` (overrides `path`) |
| `ref` | — | Git ref when using `repo` |
| `image` | — | Container image reference (overrides `path` and `repo`) |
| `format` | `sarif` | `terminal` / `json` / `sarif` / `csaf` |
| `fail-on` | `high` | Severity threshold for non-zero exit |
| `baseline` | — | Diff against this baseline file |
| `baseline-write` | — | Write a fresh baseline JSON here |
| `show-resolved` | `false` | With `baseline`, also emit resolved findings |
| `exclude` | — | Comma-separated paths to skip |
| `output` | `fipscan-output` | Where to write fipscan's stdout |
| `fipscan-version` | `latest` | Docker tag of fipscan to use |

## Outputs

| Output | Description |
|---|---|
| `output` | Path of the output file fipscan wrote to |
| `exit-code` | fipscan's exit code (0 / 1 / 2) |

## Notes

- The action runs fipscan inside its FIPS-built Docker image, so the binary is the same one published at `ghcr.io/russell-del/fipscan`. No separate binary download.
- The action does NOT upload SARIF to GitHub Code Scanning itself — use `github/codeql-action/upload-sarif@v3` as a follow-up step (see the quick-start example).
- For private OCI registries (when scanning images), set `FIPSCAN_REGISTRY_USERNAME` and `FIPSCAN_REGISTRY_PASSWORD` as workflow secrets and pass through with `env:` on the action step.
