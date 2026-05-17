package source

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

const defaultBitbucketHost = "https://bitbucket.org"

// BitbucketFetcher pulls a repository tarball from Bitbucket Cloud.
//
// Auth: HTTP Basic with a Bitbucket username and an "app password"
// (Bitbucket's term for a scoped PAT). Public repos work
// unauthenticated.
//
// Bitbucket Data Center (the self-hosted product) uses a completely
// different API and is a follow-up — set BaseURL to a known-good
// instance and you'll get a clear error if the endpoint isn't there.
type BitbucketFetcher struct {
	BaseURL  string // https://bitbucket.org by default
	Username string // your Bitbucket username (NOT email)
	Password string // app password — generate at bitbucket.org/account/settings/app-passwords
	Client   *http.Client
}

func NewBitbucketFetcher(username, password string) *BitbucketFetcher {
	base := defaultBitbucketHost
	if v := os.Getenv("FIPSCAN_BITBUCKET_HOST"); v != "" {
		base = normalizeBase(v)
	}
	return &BitbucketFetcher{
		BaseURL:  base,
		Username: username,
		Password: password,
		Client:   &http.Client{Timeout: fetchTimeout},
	}
}

func (b *BitbucketFetcher) Platform() string { return "bitbucket" }

// FetchRepo downloads "workspace/repo" @ ref. The Bitbucket Cloud
// tarball endpoint is `/{workspace}/{repo}/get/{ref}.tar.gz`. When ref
// is empty we use "HEAD" (Bitbucket's alias for the default branch).
func (b *BitbucketFetcher) FetchRepo(spec, ref string) (string, error) {
	workspace, repo, err := ParseRepoSpec(spec)
	if err != nil {
		return "", err
	}
	if ref == "" {
		ref = "HEAD"
	}
	endpoint := fmt.Sprintf("%s/%s/%s/get/%s.tar.gz",
		b.BaseURL,
		url.PathEscape(workspace),
		url.PathEscape(repo),
		url.PathEscape(ref))
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "fipscan/1.1")
	if b.Username != "" || b.Password != "" {
		req.SetBasicAuth(b.Username, b.Password)
	}
	return downloadAndExtract(b.Client, req, "bitbucket fetch "+spec)
}
