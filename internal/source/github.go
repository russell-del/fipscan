package source

import (
	"fmt"
	"net/http"
	"os"
)

const defaultGitHubAPI = "https://api.github.com"

type GitHubFetcher struct {
	APIBase string // override for GitHub Enterprise (e.g. https://ghe.example.com/api/v3)
	Token   string
	Client  *http.Client
}

func NewGitHubFetcher(token string) *GitHubFetcher {
	base := defaultGitHubAPI
	if v := os.Getenv("FIPSCAN_GITHUB_API"); v != "" {
		base = v
	}
	return &GitHubFetcher{
		APIBase: base,
		Token:   token,
		Client:  &http.Client{Timeout: fetchTimeout},
	}
}

func (g *GitHubFetcher) Platform() string { return "github" }

// FetchRepo downloads owner/repo@ref as a gzip tarball and extracts it
// into a fresh temporary directory.
func (g *GitHubFetcher) FetchRepo(spec, ref string) (string, error) {
	owner, repo, err := ParseRepoSpec(spec)
	if err != nil {
		return "", err
	}
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
	req.Header.Set("User-Agent", "fipscan/1.1")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	return downloadAndExtract(g.Client, req, "github fetch "+spec)
}
