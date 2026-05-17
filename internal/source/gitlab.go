package source

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const defaultGitLabHost = "https://gitlab.com"

// GitLabFetcher pulls a repository tarball via the GitLab Projects API.
//
// Works against gitlab.com and any self-hosted GitLab instance (set
// BaseURL or FIPSCAN_GITLAB_HOST). Authenticates with a Personal Access
// Token (or Project / Group access token) sent in the PRIVATE-TOKEN
// header — required for private projects, optional for public ones.
type GitLabFetcher struct {
	BaseURL string // e.g. https://gitlab.com or https://gitlab.internal.example.com
	Token   string
	Client  *http.Client
}

func NewGitLabFetcher(token string) *GitLabFetcher {
	base := defaultGitLabHost
	if v := os.Getenv("FIPSCAN_GITLAB_HOST"); v != "" {
		base = normalizeBase(v)
	}
	return &GitLabFetcher{
		BaseURL: base,
		Token:   token,
		Client:  &http.Client{Timeout: fetchTimeout},
	}
}

func (g *GitLabFetcher) Platform() string { return "gitlab" }

// FetchRepo downloads `spec` (a project namespace path like
// "group/project" or "group/subgroup/project") at the requested ref.
//
// Endpoint:
//
//	GET {BaseURL}/api/v4/projects/{url-encoded-spec}/repository/archive.tar.gz?sha={ref}
func (g *GitLabFetcher) FetchRepo(spec, ref string) (string, error) {
	if spec == "" {
		return "", fmt.Errorf("invalid gitlab spec: empty")
	}
	encoded := url.PathEscape(spec) // turns "/" into "%2F"
	endpoint := g.BaseURL + "/api/v4/projects/" + encoded + "/repository/archive.tar.gz"
	if ref != "" {
		endpoint += "?sha=" + url.QueryEscape(ref)
	}
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "fipscan/1.1")
	if g.Token != "" {
		req.Header.Set("PRIVATE-TOKEN", g.Token)
	}
	return downloadAndExtract(g.Client, req, "gitlab fetch "+spec)
}

// normalizeBase prepends https:// if missing and strips a trailing slash.
func normalizeBase(s string) string {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}
