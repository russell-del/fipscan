// fipscan — FIPS 140-3 readiness scanner.
//
// v0.2: scans a local directory tree OR a GitHub repository (fetched via
// the REST tarball API, no `git` binary required) for use of non-FIPS-
// approved cryptographic algorithms across Python, Go, Java, JS/TS, C#.
// Outputs terminal, JSON, or SARIF 2.1.0 (consumable by GitHub Code
// Scanning).
package main

import (
	"crypto/fips140"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rbuilta/fipscan/internal/container"
	"github.com/rbuilta/fipscan/internal/deps"
	"github.com/rbuilta/fipscan/internal/findings"
	"github.com/rbuilta/fipscan/internal/registry"
	"github.com/rbuilta/fipscan/internal/report"
	"github.com/rbuilta/fipscan/internal/scan/code"
	"github.com/rbuilta/fipscan/internal/server"
	"github.com/rbuilta/fipscan/internal/source"
)

const version = "1.2.0"

// knownSubcommands is the dispatch table for `fipscan <subcommand> ...`.
// Back-compat: if the first argument starts with "-" or is absent, the
// scan flow is invoked directly (preserving the v0.6 CLI shape).
var knownSubcommands = map[string]func(args []string){
	"server":        runServer,
	"scan":          runScan, // explicit form of the default
	"hash-password": runHashPassword,
}

func main() {
	if len(os.Args) > 1 {
		if fn, ok := knownSubcommands[os.Args[1]]; ok {
			fn(os.Args[2:])
			return
		}
	}
	runScan(os.Args[1:])
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		path     = fs.String("path", ".", "Local path to scan (directory)")
		repo     = fs.String("repo", "", "Repository to scan, e.g. owner/name (overrides -path). Used with -repo-platform.")
		repoPlat = fs.String("repo-platform", "github", "Platform for -repo: github | gitlab | bitbucket")
		ref      = fs.String("ref", "", "Git ref (branch, tag, or commit SHA) when using -repo (default: repo's default branch)")
		token    = fs.String("token", "", "GitHub token for -repo (or set GITHUB_TOKEN env var). Required for private GitHub repos.")
		glToken  = fs.String("gitlab-token", "", "GitLab PAT for -repo when -repo-platform=gitlab (or GITLAB_TOKEN env). Required for private GitLab projects.")
		bbUser   = fs.String("bitbucket-username", "", "Bitbucket username for -repo when -repo-platform=bitbucket (or BITBUCKET_USERNAME env).")
		bbPass   = fs.String("bitbucket-password", "", "Bitbucket app password (or BITBUCKET_APP_PASSWORD env).")
		image    = fs.String("image", "", "Container image reference to scan, e.g. alpine:3.19 or gcr.io/distroless/python3:nonroot")
		platform = fs.String("platform", "linux/amd64", "Platform for multi-arch images: os/arch[/variant] (e.g. linux/amd64, linux/arm64, linux/arm/v7)")
		regUser  = fs.String("registry-username", "", "Registry username for -image (or set FIPSCAN_REGISTRY_USERNAME)")
		regPass  = fs.String("registry-password", "", "Registry password for -image (or set FIPSCAN_REGISTRY_PASSWORD)")
		exclude  = fs.String("exclude", "", "Comma-separated list of repo-relative paths to skip (e.g. testdata,vendor)")
		format   = fs.String("format", "terminal", "Output format: terminal | json | sarif")
		failOn   = fs.String("fail-on", "high", "Exit non-zero if findings at or above this severity exist: high | medium | low | none")
		showV    = fs.Bool("version", false, "Print version and exit")
	)
	_ = fs.Parse(args)

	if *showV {
		fmt.Println("fipscan", version)
		// Report the linked FIPS 140-3 cryptographic module, if any.
		// Version() returns the module identifier when built with
		// GOFIPS140=v1.0.0; Enabled() reflects whether the module is
		// currently in FIPS mode (GODEBUG=fips140=on at runtime).
		fipsVer := fips140.Version()
		if fipsVer == "" {
			fmt.Println("fips140-module: none (built without GOFIPS140)")
		} else {
			fmt.Printf("fips140-module: %s (enabled=%v)\n", fipsVer, fips140.Enabled())
		}
		return
	}

	requireFIPSMode()

	if *image != "" && (*repo != "" || *path != ".") {
		fmt.Fprintln(os.Stderr, "-image cannot be combined with -repo or -path")
		os.Exit(2)
	}

	var results []findings.Finding
	if *image != "" {
		auth := resolveRegistryAuth(*regUser, *regPass)
		plat, err := registry.ParsePlatform(*platform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "fipscan: scanning image %s (%s) ...\n", *image, plat)
		r, err := container.ScanImage(*image, auth, plat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "image scan error: %v\n", err)
			os.Exit(2)
		}
		results = r
	} else {
		fetcher, err := source.Choose(*repoPlat, source.Config{
			GitHubToken:       firstNonEmpty(*token, os.Getenv("GITHUB_TOKEN")),
			GitLabToken:       firstNonEmpty(*glToken, os.Getenv("GITLAB_TOKEN")),
			BitbucketUsername: firstNonEmpty(*bbUser, os.Getenv("BITBUCKET_USERNAME")),
			BitbucketPassword: firstNonEmpty(*bbPass, os.Getenv("BITBUCKET_APP_PASSWORD")),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		scanRoot, cleanup, err := resolveScanRoot(*path, *repo, *ref, fetcher)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		defer cleanup()

		excludes := parseExclude(*exclude)
		results, err = code.ScanPath(scanRoot, code.Options{ExcludePrefixes: excludes})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			os.Exit(2)
		}
		depResults, err := deps.ScanPath(scanRoot, deps.Options{ExcludePrefixes: excludes})
		if err != nil {
			fmt.Fprintf(os.Stderr, "deps scan error: %v\n", err)
			os.Exit(2)
		}
		results = append(results, depResults...)

		// When fetching from GitHub the scan root is a temp dir whose top-level
		// entry is GitHub's "{owner}-{repo}-{shortsha}/" wrapper. Strip both so
		// findings are reported with paths relative to the repo root.
		if *repo != "" {
			results = relativizePaths(results, scanRoot)
		}
	}

	switch *format {
	case "json":
		if err := report.RenderJSON(os.Stdout, results, version); err != nil {
			fmt.Fprintf(os.Stderr, "render error: %v\n", err)
			os.Exit(2)
		}
	case "sarif":
		if err := report.RenderSARIF(os.Stdout, results, version); err != nil {
			fmt.Fprintf(os.Stderr, "render error: %v\n", err)
			os.Exit(2)
		}
	case "terminal":
		report.RenderTerminal(os.Stdout, results)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}

	if shouldFail(results, *failOn) {
		os.Exit(1)
	}
}

// runHashPassword reads a password from stdin and prints a PBKDF2 hash
// suitable for passing to `fipscan server -auth-password-hash` or for
// setting in the FIPSCAN_AUTH_PASSWORD_HASH environment variable.
//
// Usage:
//   echo -n 'my-secret' | fipscan hash-password
//   FIPSCAN_AUTH_PASSWORD_HASH=$(echo -n 'my-secret' | fipscan hash-password)
// requireFIPSMode is the runtime trust-anchor. fipscan refuses to run any
// scanning, server, or hashing subcommand unless its embedded crypto is
// the Go 1.26 FIPS 140-3 cryptographic module AND that module is
// currently active. Operators can confirm the same posture externally
// via `fipscan -version` (which is exempt from this guard so it remains
// usable for diagnosis).
//
// Failure modes covered:
//   - Binary built without GOFIPS140=v1.0.0 (Version() == "")
//   - Built correctly but GODEBUG=fips140=off at runtime (Enabled() == false)
//
// Both are fail-closed: exit 2, clear remediation text, no silent fallback.
func requireFIPSMode() {
	ver := fips140.Version()
	if ver == "" {
		fmt.Fprintln(os.Stderr, "fipscan: refusing to start — binary was built without the FIPS 140-3 cryptographic module.")
		fmt.Fprintln(os.Stderr, "  Build: CGO_ENABLED=0 GOFIPS140=v1.0.0 go build ./cmd/fipscan")
		fmt.Fprintln(os.Stderr, "  Or pull the prebuilt image: docker pull ghcr.io/rbuilta/fipscan:latest")
		os.Exit(2)
	}
	if !fips140.Enabled() {
		fmt.Fprintln(os.Stderr, "fipscan: refusing to start — FIPS 140-3 mode is disabled at runtime.")
		fmt.Fprintf(os.Stderr, "  Module %s is linked but GODEBUG=fips140=off was set.\n", ver)
		fmt.Fprintln(os.Stderr, "  Unset GODEBUG=fips140 (or set it to `on` / `only`) and re-run.")
		os.Exit(2)
	}
}

func runHashPassword(args []string) {
	requireFIPSMode()
	pw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(2)
	}
	pwStr := strings.TrimRight(string(pw), "\r\n")
	if pwStr == "" {
		fmt.Fprintln(os.Stderr, "usage: echo -n '<password>' | fipscan hash-password")
		os.Exit(2)
	}
	hash, err := server.HashPassword(pwStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(hash)
}

// runServer launches the long-running watchlist + UI server.
//
// `fipscan server [-listen <addr>] [-data <dir>] [-interval <duration>]`
//
// The server is single-binary: it embeds its HTML UI via go:embed and
// stores all state as JSON files under -data so it remains auditable and
// works in air-gapped IL5+ environments. Default bind is 127.0.0.1:8080
// — explicit opt-in is required to expose it on a network interface.
func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "Address to bind (default localhost-only; use 0.0.0.0:8080 to expose)")
	dataDir := fs.String("data", "./fipscan-data", "Directory for persisted state (targets, scan results)")
	interval := fs.Duration("interval", 24*time.Hour, "How often to re-scan each watchlist target")
	authUser := fs.String("auth-user", "admin", "Username for HTTP Basic auth (when -auth-password-hash is set)")
	authHash := fs.String("auth-password-hash", "", "PBKDF2 password hash for HTTP Basic auth (or set FIPSCAN_AUTH_PASSWORD_HASH). Generate with `fipscan hash-password`.")
	publicURL := fs.String("public-url", "", "Externally visible base URL (e.g. https://fipscan.example.com). Embedded in alert payloads so clickable scan-detail links work.")
	auditLog := fs.String("audit-log", "", "Path to SIEM-friendly JSONL audit log (ECS 8.x). Or set FIPSCAN_AUDIT_LOG. Empty = audit events go to stderr.")
	_ = fs.Parse(args)

	hash := *authHash
	if hash == "" {
		hash = os.Getenv("FIPSCAN_AUTH_PASSWORD_HASH")
	}

	requireFIPSMode()

	pubURL := *publicURL
	if pubURL == "" {
		pubURL = os.Getenv("FIPSCAN_PUBLIC_URL")
	}
	auditPath := *auditLog
	if auditPath == "" {
		auditPath = os.Getenv("FIPSCAN_AUDIT_LOG")
	}

	if err := server.Run(server.Config{
		Listen:           *listen,
		DataDir:          *dataDir,
		Interval:         *interval,
		Version:          version,
		AuthUser:         *authUser,
		AuthPasswordHash: hash,
		PublicURL:        pubURL,
		AuditLogPath:     auditPath,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// firstNonEmpty returns the first non-empty string. Used to give CLI
// flags precedence over env-var defaults.
func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseExclude(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveRegistryAuth(userFlag, passFlag string) *registry.BasicAuth {
	user := userFlag
	if user == "" {
		user = os.Getenv("FIPSCAN_REGISTRY_USERNAME")
	}
	pass := passFlag
	if pass == "" {
		pass = os.Getenv("FIPSCAN_REGISTRY_PASSWORD")
	}
	if user == "" && pass == "" {
		return nil
	}
	return &registry.BasicAuth{Username: user, Password: pass}
}

func resolveScanRoot(path, repo, ref string, fetcher source.Fetcher) (string, func(), error) {
	if repo == "" {
		return path, func() {}, nil
	}
	fmt.Fprintf(os.Stderr, "fipscan: fetching %s (%s)", repo, fetcher.Platform())
	if ref != "" {
		fmt.Fprintf(os.Stderr, "@%s", ref)
	}
	fmt.Fprintln(os.Stderr, " ...")
	dir, err := fetcher.FetchRepo(repo, ref)
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

func relativizePaths(results []findings.Finding, root string) []findings.Finding {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return results
	}
	for i, f := range results {
		fileAbs, err := filepath.Abs(f.File)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, fileAbs)
		if err != nil {
			continue
		}
		// Strip GitHub's "{owner}-{repo}-{shortsha}/" wrapper directory.
		parts := strings.SplitN(rel, string(os.PathSeparator), 2)
		if len(parts) == 2 {
			rel = parts[1]
		}
		results[i].File = rel
	}
	return results
}

func shouldFail(results []findings.Finding, threshold string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	sevRank := map[findings.Severity]int{
		findings.SeverityLow:    1,
		findings.SeverityMedium: 2,
		findings.SeverityHigh:   3,
	}
	th, ok := rank[threshold]
	if !ok {
		return false
	}
	for _, f := range results {
		if sevRank[f.Severity] >= th {
			return true
		}
	}
	return false
}
