package server

import (
	"crypto/fips140"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed ui/templates/*.html
var templatesFS embed.FS

//go:embed ui/static
var staticEmbed embed.FS

// staticFS exposes ui/static at the /static/ URL prefix.
var staticFS fs.FS

// pageTemplates is populated at startup. Each entry composes _layout.html
// with the named page template so handlers can render with a single call.
var pageTemplates map[string]*template.Template

func init() {
	sub, err := fs.Sub(staticEmbed, "ui/static")
	if err != nil {
		panic(err)
	}
	staticFS = staticAt{sub}

	pages := []string{"dashboard", "target_new", "target_show", "scan_show", "alerts", "alert_new"}
	pageTemplates = make(map[string]*template.Template, len(pages))
	funcMap := template.FuncMap{
		"shortID": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
		"sevClass": func(s string) string { return "sev-" + s },
	}
	for _, p := range pages {
		t := template.New("_layout.html").Funcs(funcMap)
		t = template.Must(t.ParseFS(templatesFS,
			"ui/templates/_layout.html",
			"ui/templates/"+p+".html"))
		pageTemplates[p] = t
	}
}

// render executes the named page template (composed with the layout)
// against w. Augments the page's data map with FIPS module state so the
// layout footer can display the badge on every page without each handler
// having to remember to set it.
func (h *handlers) render(w http.ResponseWriter, name string, data interface{}) {
	t, ok := pageTemplates[name]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown template %q", name), http.StatusInternalServerError)
		return
	}
	if m, ok := data.(map[string]interface{}); ok {
		if _, set := m["Version"]; !set {
			m["Version"] = h.version
		}
		m["FIPSModule"] = fips140.Version()
		m["FIPSEnabled"] = fips140.Enabled()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "_layout.html", data); err != nil {
		// Headers already sent — best we can do is log via the writer.
		fmt.Fprintf(w, "<!-- template error: %v -->", err)
	}
}

// staticAt is a wrapper that exposes the embedded static files under
// /static/<name> URLs. The http.FileServer call in routes.go prefixes
// /static/, so we need to strip that here.
type staticAt struct{ fs.FS }

func (s staticAt) Open(name string) (fs.File, error) {
	// http.FileServer requests look like "static/style.css" — strip the
	// leading "static/" segment to map onto the fs.Sub root.
	if len(name) > 7 && name[:7] == "static/" {
		name = name[7:]
	}
	return s.FS.Open(name)
}
