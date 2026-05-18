package osv

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const bulkURL = "https://osv-vulnerabilities.storage.googleapis.com/"

// Bulk download endpoints — one ZIP per ecosystem, containing one
// JSON file per vulnerability. Documented at
// https://google.github.io/osv.dev/data/.
//
// The keys here are the OSV ecosystem identifier (as used in the URL),
// which matches the JSON `affected[].package.ecosystem` field.
var BulkEcosystems = []string{
	"PyPI",
	"npm",
	"Go",
	"Maven",
	"crates.io",
	"RubyGems",
	"Packagist",
	"NuGet",
}

// FetchEcosystem downloads the OSV bulk dump for one ecosystem and
// returns the parsed vulnerabilities. Streams the response body into
// an in-memory zip reader — bulk dumps are typically 1–20 MiB so this
// is fine; the alternative would be a temp-file path.
func FetchEcosystem(ecosystem string) ([]Vulnerability, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	url := bulkURL + ecosystem + "/all.zip"
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}
	// Cap the read to 200 MiB — current ecosystem dumps are well under
	// that; the cap stops a runaway response from exhausting memory.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("unzip %s: %w", url, err)
	}

	var out []Vulnerability
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !endsWithJSON(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 5*1024*1024))
		rc.Close()
		if err != nil {
			continue
		}
		var v Vulnerability
		if err := json.Unmarshal(body, &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func endsWithJSON(s string) bool {
	const ext = ".json"
	return len(s) >= len(ext) && s[len(s)-len(ext):] == ext
}
