package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	mediaManifestV2   = "application/vnd.docker.distribution.manifest.v2+json"
	mediaManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex     = "application/vnd.oci.image.index.v1+json"

	defaultTimeout = 5 * time.Minute
)

// AcceptManifests is the comma-joined Accept header for manifest fetches.
const AcceptManifests = mediaManifestV2 + "," + mediaOCIManifest + "," +
	mediaManifestList + "," + mediaOCIIndex

// IsManifestList reports whether mediaType identifies a multi-arch
// manifest list / OCI image index.
func IsManifestList(mediaType string) bool {
	return mediaType == mediaManifestList || mediaType == mediaOCIIndex
}

// BasicAuth holds username/password credentials for private registries.
type BasicAuth struct {
	Username string
	Password string
}

// Client is a minimal OCI distribution client. It caches bearer tokens
// per (registry, scope) so consecutive blob fetches reuse one token.
type Client struct {
	HTTP      *http.Client
	BasicAuth *BasicAuth

	mu     sync.Mutex
	tokens map[string]string // key: realm+service+scope
}

func NewClient(auth *BasicAuth) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: defaultTimeout},
		BasicAuth: auth,
		tokens:    map[string]string{},
	}
}

// FetchManifest returns the raw manifest bytes and the response Content-Type.
func (c *Client) FetchManifest(ref Reference) ([]byte, string, error) {
	endpoint := fmt.Sprintf("https://%s/v2/%s/manifests/%s",
		ref.Registry, ref.Repository, ref.ManifestName())
	resp, err := c.authedGet(endpoint, AcceptManifests, ref)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("manifest fetch %s: status %d: %s",
			endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// FetchBlob streams a blob (layer or config). The caller must close the
// returned reader.
func (c *Client) FetchBlob(ref Reference, digest string) (io.ReadCloser, error) {
	endpoint := fmt.Sprintf("https://%s/v2/%s/blobs/%s",
		ref.Registry, ref.Repository, digest)
	resp, err := c.authedGet(endpoint, "*/*", ref)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("blob fetch %s: status %d: %s",
			endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

// authedGet performs a GET against the registry, transparently handling
// the 401 → token → retry dance. Tokens are cached per challenge.
func (c *Client) authedGet(endpoint, accept string, ref Reference) (*http.Response, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "fipscan/0.4")

	// First try cached token for this registry's default scope.
	scope := fmt.Sprintf("repository:%s:pull", ref.Repository)
	if token := c.cachedToken(ref.Registry, scope); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Need to (re-)authenticate based on the challenge.
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	if challenge == "" {
		return nil, fmt.Errorf("401 from %s with no WWW-Authenticate header", endpoint)
	}
	token, err := c.fetchToken(challenge, ref)
	if err != nil {
		return nil, err
	}

	req2, _ := http.NewRequest("GET", endpoint, nil)
	if accept != "" {
		req2.Header.Set("Accept", accept)
	}
	req2.Header.Set("User-Agent", "fipscan/0.4")
	req2.Header.Set("Authorization", "Bearer "+token)
	return c.HTTP.Do(req2)
}

func (c *Client) cachedToken(registry, scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens[registry+"|"+scope]
}

func (c *Client) cacheToken(registry, scope, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[registry+"|"+scope] = token
}

func (c *Client) fetchToken(challenge string, ref Reference) (string, error) {
	scheme, params := parseAuthChallenge(challenge)
	if !strings.EqualFold(scheme, "bearer") {
		return "", fmt.Errorf("unsupported auth scheme %q", scheme)
	}
	realm := params["realm"]
	service := params["service"]
	scope := params["scope"]
	if realm == "" {
		return "", fmt.Errorf("malformed WWW-Authenticate (no realm): %q", challenge)
	}
	if scope == "" {
		scope = fmt.Sprintf("repository:%s:pull", ref.Repository)
	}

	q := url.Values{}
	if service != "" {
		q.Set("service", service)
	}
	q.Set("scope", scope)
	u := realm + "?" + q.Encode()

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	if c.BasicAuth != nil {
		req.SetBasicAuth(c.BasicAuth.Username, c.BasicAuth.Password)
	}
	req.Header.Set("User-Agent", "fipscan/0.4")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("token fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("token fetch %s: status %d: %s",
			u, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	token := tr.Token
	if token == "" {
		token = tr.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("token response from %s contained no token", u)
	}
	c.cacheToken(ref.Registry, scope, token)
	return token, nil
}

// parseAuthChallenge parses `Bearer realm="...",service="...",scope="..."`
// into its scheme and parameter map. Tolerant of extra whitespace.
func parseAuthChallenge(s string) (scheme string, params map[string]string) {
	params = map[string]string{}
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		scheme = s[:i]
		s = strings.TrimSpace(s[i+1:])
	} else {
		scheme = s
		return scheme, params
	}
	// split on commas not inside quoted strings
	for _, part := range splitQuoted(s, ',') {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		v = strings.Trim(v, `"`)
		params[k] = v
	}
	return scheme, params
}

// splitQuoted splits s by sep, treating runs inside double-quotes as opaque.
func splitQuoted(s string, sep byte) []string {
	var out []string
	var buf strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case c == sep && !inQuote:
			out = append(out, buf.String())
			buf.Reset()
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}
