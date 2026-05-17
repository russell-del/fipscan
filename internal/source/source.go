// Package source provides ways to fetch a code tree to scan.
//
// All fetchers use tarball-over-HTTPS endpoints so fipscan can run in
// environments that have no `git` binary installed (typical of stripped
// container images and air-gapped environments where only an outbound
// proxy to api.github.com / gitlab.com / bitbucket.org is permitted).
//
// Supported platforms:
//   - GitHub (github.com + GitHub Enterprise Server)
//   - GitLab (gitlab.com + self-hosted GitLab)
//   - Bitbucket Cloud (bitbucket.org)
//
// Bitbucket Data Center (the on-prem product, formerly "Bitbucket
// Server") uses a different API shape and is a follow-up.
package source

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxArchiveBytes = 500 * 1024 * 1024 // 500 MiB cap to prevent decompression bombs
	maxFileBytes    = 50 * 1024 * 1024  // 50 MiB per file
	fetchTimeout    = 5 * time.Minute
)

// Fetcher downloads a repository as a gzipped tarball and extracts it
// to a fresh temporary directory. The caller owns the returned path and
// must os.RemoveAll it when done.
//
// `spec` is platform-conventional: "owner/repo" for GitHub, the same
// shape for GitLab projects ("group/project" or nested
// "group/subgroup/project"), and "workspace/repo" for Bitbucket.
//
// `ref` is a branch name, tag, or commit SHA. Empty means "default
// branch".
type Fetcher interface {
	FetchRepo(spec, ref string) (dir string, err error)
	Platform() string // short identifier: "github" | "gitlab" | "bitbucket"
}

// Config bundles credentials and overrides for all supported platforms,
// so callers can construct the right Fetcher via Choose() without
// knowing each platform's constructor signature.
type Config struct {
	GitHubToken       string
	GitLabToken       string
	BitbucketUsername string
	BitbucketPassword string
}

// Choose returns a Fetcher for the named platform. Accepted values:
// "github" (default for empty), "gitlab", "bitbucket"/"bitbucket-cloud".
func Choose(platform string, cfg Config) (Fetcher, error) {
	switch strings.ToLower(platform) {
	case "", "github":
		return NewGitHubFetcher(cfg.GitHubToken), nil
	case "gitlab":
		return NewGitLabFetcher(cfg.GitLabToken), nil
	case "bitbucket", "bitbucket-cloud":
		return NewBitbucketFetcher(cfg.BitbucketUsername, cfg.BitbucketPassword), nil
	default:
		return nil, fmt.Errorf("unknown repo platform %q (supported: github, gitlab, bitbucket)", platform)
	}
}

// ParseRepoSpec splits "owner/repo" into its parts. GitHub / Bitbucket
// style. GitLab can have nested groups — its fetcher handles them in
// FetchRepo by URL-encoding the whole spec.
func ParseRepoSpec(spec string) (owner, repo string, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
		strings.ContainsAny(parts[0], "/ ") || strings.ContainsAny(parts[1], "/ ") {
		return "", "", fmt.Errorf("invalid repo spec %q (expected owner/repo)", spec)
	}
	return parts[0], parts[1], nil
}

// downloadAndExtract performs the request, validates the response, and
// streams the resulting gzipped tarball into a fresh temp dir. Shared
// by every fetcher.
func downloadAndExtract(client *http.Client, req *http.Request, errPrefix string) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", errPrefix, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("%s: status %d: %s",
			errPrefix, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	dir, err := os.MkdirTemp("", "fipscan-*")
	if err != nil {
		return "", err
	}
	if err := extractTarGz(io.LimitReader(resp.Body, maxArchiveBytes), dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// extractTarGz extracts a gzipped tar stream into dest. It rejects any
// entry whose resolved path would escape dest (path-traversal /
// "tar slip"), skips symlinks and hardlinks, and caps per-file bytes.
func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	cleanDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		target := filepath.Join(cleanDest, hdr.Name)
		if target != cleanDest &&
			!strings.HasPrefix(target+string(os.PathSeparator), cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxFileBytes)); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		default:
			// Skip symlinks, hardlinks, devices, fifos, etc.
			continue
		}
	}
}
