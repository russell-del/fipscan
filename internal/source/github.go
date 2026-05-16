// Package source provides ways to fetch a code tree to scan.
//
// The GitHub fetcher uses the REST tarball endpoint over plain HTTPS so
// the tool can run in environments that have no `git` binary installed
// (typical of stripped container images and air-gapped environments with
// only an outbound proxy to api.github.com or a GHE instance).
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
	defaultGitHubAPI = "https://api.github.com"
	maxArchiveBytes  = 500 * 1024 * 1024 // 500 MiB cap to prevent decompression bombs
	maxFileBytes     = 50 * 1024 * 1024  // 50 MiB per file
	fetchTimeout     = 5 * time.Minute
)

type GitHubFetcher struct {
	APIBase string // override for GitHub Enterprise (e.g. https://ghe.example.com/api/v3)
	Token   string
	Client  *http.Client
}

func NewGitHubFetcher(token string) *GitHubFetcher {
	if v := os.Getenv("FIPSCAN_GITHUB_API"); v != "" {
		return &GitHubFetcher{APIBase: v, Token: token, Client: &http.Client{Timeout: fetchTimeout}}
	}
	return &GitHubFetcher{
		APIBase: defaultGitHubAPI,
		Token:   token,
		Client:  &http.Client{Timeout: fetchTimeout},
	}
}

// FetchRepo downloads {owner}/{repo}@{ref} as a gzip tarball and extracts
// it into a fresh temporary directory. The caller owns the returned path
// and must os.RemoveAll it when done.
func (g *GitHubFetcher) FetchRepo(owner, repo, ref string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/tarball", g.APIBase, owner, repo)
	if ref != "" {
		url += "/" + ref
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "fipscan/0.2")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("github fetch %s/%s: status %d: %s",
			owner, repo, resp.StatusCode, strings.TrimSpace(string(body)))
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
// entry whose resolved path would escape dest (path-traversal / "tar slip"),
// skips symlinks and hardlinks, and caps per-file bytes.
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
		// Reject path traversal: resolved target must stay under cleanDest.
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

// ParseRepoSpec splits "owner/repo" into its parts.
func ParseRepoSpec(spec string) (owner, repo string, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
		strings.ContainsAny(parts[0], "/ ") || strings.ContainsAny(parts[1], "/ ") {
		return "", "", fmt.Errorf("invalid repo spec %q (expected owner/repo)", spec)
	}
	return parts[0], parts[1], nil
}
