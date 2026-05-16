// Package registry implements a minimal OCI / Docker v2 distribution
// client: parsing image references, anonymous & basic-auth token flows,
// manifest and blob fetches. Stdlib only (net/http, crypto/tls, encoding/json).
package registry

import (
	"fmt"
	"strings"
)

// DefaultRegistry is the implicit registry when a reference has no
// hostname component (e.g. `nginx`, `library/redis`).
const DefaultRegistry = "registry-1.docker.io"

// Platform identifies a target architecture/OS for image scans.
type Platform struct {
	OS      string
	Arch    string
	Variant string
}

// DefaultPlatform is the platform used when none is specified.
var DefaultPlatform = Platform{OS: "linux", Arch: "amd64"}

func (p Platform) String() string {
	if p.Variant != "" {
		return p.OS + "/" + p.Arch + "/" + p.Variant
	}
	return p.OS + "/" + p.Arch
}

// ParsePlatform parses "os/arch" or "os/arch/variant" (e.g. "linux/amd64",
// "linux/arm64/v8", "linux/arm/v7").
func ParsePlatform(s string) (Platform, error) {
	if s == "" {
		return DefaultPlatform, nil
	}
	parts := strings.SplitN(s, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Platform{}, fmt.Errorf("invalid platform %q (expected os/arch[/variant])", s)
	}
	p := Platform{OS: parts[0], Arch: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

// Reference is a parsed image reference.
type Reference struct {
	Registry   string // hostname (with optional port), e.g. "registry-1.docker.io"
	Repository string // path, e.g. "library/nginx" or "distroless/python3"
	Tag        string // "latest"; empty if Digest is set
	Digest     string // "sha256:..."; empty if Tag is set
}

func (r Reference) String() string {
	out := r.Registry + "/" + r.Repository
	if r.Digest != "" {
		return out + "@" + r.Digest
	}
	if r.Tag != "" {
		return out + ":" + r.Tag
	}
	return out
}

// ManifestName is the {reference} path segment used in /v2/{name}/manifests/{reference}.
func (r Reference) ManifestName() string {
	if r.Digest != "" {
		return r.Digest
	}
	if r.Tag != "" {
		return r.Tag
	}
	return "latest"
}

// ParseReference parses a Docker / OCI image reference.
//
// Grammar (relaxed):
//
//	[REGISTRY/]REPO[:TAG][@DIGEST]
//
// The first slash-delimited segment is the registry only if it looks like
// a hostname — it contains `.` or `:` or is the literal "localhost".
// Otherwise the whole left side is treated as repo path under the default
// Docker Hub registry, which also gets the `library/` prefix for single-
// component names.
func ParseReference(s string) (Reference, error) {
	if s == "" {
		return Reference{}, fmt.Errorf("empty reference")
	}

	var digest string
	if i := strings.Index(s, "@"); i >= 0 {
		digest = s[i+1:]
		s = s[:i]
		if !strings.HasPrefix(digest, "sha256:") && !strings.HasPrefix(digest, "sha512:") {
			return Reference{}, fmt.Errorf("unsupported digest algorithm: %q", digest)
		}
	}

	var registry string
	if i := strings.Index(s, "/"); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			registry = first
			s = s[i+1:]
		}
	}
	if registry == "" {
		registry = DefaultRegistry
	}

	var tag string
	if i := strings.LastIndex(s, ":"); i >= 0 {
		// Make sure the colon isn't part of a host:port that wasn't peeled off.
		rest := s[i+1:]
		if !strings.Contains(rest, "/") {
			tag = rest
			s = s[:i]
		}
	}

	repo := s
	if repo == "" {
		return Reference{}, fmt.Errorf("invalid reference: empty repository")
	}
	if registry == DefaultRegistry && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	if tag == "" && digest == "" {
		tag = "latest"
	}

	return Reference{
		Registry:   registry,
		Repository: repo,
		Tag:        tag,
		Digest:     digest,
	}, nil
}
