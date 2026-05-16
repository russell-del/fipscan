package server

import (
	"crypto/fips140"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rbuilta/fipscan/internal/audit"
)

type handlers struct {
	store   *Store
	sched   *Scheduler
	version string
	audit   *audit.Logger
}

func newHandlers(s *Store, sc *Scheduler, version string, auditor *audit.Logger) *handlers {
	if auditor == nil {
		auditor = audit.NopLogger()
	}
	return &handlers{store: s, sched: sc, version: version, audit: auditor}
}

// actor returns the authenticated username (if Basic auth set) and the
// source IP for an HTTP request. Both empty-string-safe.
func (h *handlers) actor(r *http.Request) (user, ip string) {
	if u, _, ok := r.BasicAuth(); ok {
		user = u
	}
	return user, clientIP(r)
}

func (h *handlers) registerRoutes(mux *http.ServeMux) {
	// Static assets (CSS).
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	// HTML pages.
	mux.HandleFunc("/", h.dashboard)
	mux.HandleFunc("/targets/new", h.targetNew)
	mux.HandleFunc("/targets/", h.targetRouter) // /targets/{id}, /targets/{id}/scan, /targets/{id}/delete
	mux.HandleFunc("/scans/", h.scanShow)
	mux.HandleFunc("/alerts", h.alertsList)
	mux.HandleFunc("/alerts/new", h.alertNew)
	mux.HandleFunc("/alerts/", h.alertRouter) // /alerts/{id}/delete, /alerts/{id}/test

	// JSON API (v1).
	mux.HandleFunc("/api/v1/targets", h.apiTargets)
	mux.HandleFunc("/api/v1/targets/", h.apiTargetItem)
	mux.HandleFunc("/api/v1/scans/", h.apiScanItem)
	mux.HandleFunc("/api/v1/alerts", h.apiAlerts)
	mux.HandleFunc("/api/v1/alerts/", h.apiAlertItem)
	mux.HandleFunc("/api/v1/healthz", h.apiHealth)
}

// ----- HTML routes ------------------------------------------------------

func (h *handlers) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	targets, err := h.store.ListTargets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Pull the most recent scan summary for each target.
	type row struct {
		Target Target
		Scan   *ScanRecord
	}
	rows := make([]row, 0, len(targets))
	for _, t := range targets {
		r := row{Target: t}
		if t.LastScanID != "" {
			if rec, ok, _ := h.store.GetScan(t.LastScanID); ok {
				r.Scan = &rec
			}
		}
		rows = append(rows, r)
	}
	h.render(w, "dashboard", map[string]interface{}{
		"Title":   "Dashboard",
		"Version": h.version,
		"Rows":    rows,
	})
}

func (h *handlers) targetNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		t := Target{
			Type:     TargetType(r.FormValue("type")),
			Value:    strings.TrimSpace(r.FormValue("value")),
			Ref:      strings.TrimSpace(r.FormValue("ref")),
			Platform: strings.TrimSpace(r.FormValue("platform")),
		}
		if t.Value == "" || (t.Type != TargetRepo && t.Type != TargetImage) {
			http.Error(w, "type and value are required", http.StatusBadRequest)
			return
		}
		t, err := h.store.AddTarget(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetAdded(t.ID, string(t.Type), t.Value, ip, user))
		h.sched.RequestScan(t.ID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.render(w, "target_new", map[string]interface{}{"Title": "Add target"})
}

// targetRouter dispatches /targets/{id}, /targets/{id}/scan, /targets/{id}/delete
func (h *handlers) targetRouter(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/targets/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	switch {
	case len(parts) == 1:
		h.targetShow(w, r, id)
	case len(parts) == 2 && parts[1] == "scan" && r.Method == http.MethodPost:
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetScanRequested(id, ip, user))
		h.sched.RequestScan(id)
		http.Redirect(w, r, "/targets/"+id, http.StatusSeeOther)
	case len(parts) == 2 && parts[1] == "delete" && r.Method == http.MethodPost:
		if err := h.store.DeleteTarget(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetDeleted(id, ip, user))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (h *handlers) targetShow(w http.ResponseWriter, r *http.Request, id string) {
	t, ok, err := h.store.GetTarget(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	scans, err := h.store.ListScansForTarget(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "target_show", map[string]interface{}{
		"Title":  t.Value,
		"Target": t,
		"Scans":  scans,
	})
}

func (h *handlers) scanShow(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/scans/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	rec, ok, err := h.store.GetScan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	t, _, _ := h.store.GetTarget(rec.TargetID)
	h.render(w, "scan_show", map[string]interface{}{
		"Title":  "Scan " + id[:8],
		"Scan":   rec,
		"Target": t,
	})
}

// ----- HTML: alerts ----------------------------------------------------

func (h *handlers) alertsList(w http.ResponseWriter, r *http.Request) {
	alerts, err := h.store.ListAlerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, "alerts", map[string]interface{}{
		"Title":  "Alerts",
		"Alerts": alerts,
	})
}

func (h *handlers) alertNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a := AlertDestination{
			Name:        strings.TrimSpace(r.FormValue("name")),
			URL:         strings.TrimSpace(r.FormValue("url")),
			MinSeverity: strings.ToUpper(strings.TrimSpace(r.FormValue("min_severity"))),
		}
		if a.URL == "" || a.Name == "" {
			http.Error(w, "name and url are required", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
			http.Error(w, "url must begin with http:// or https://", http.StatusBadRequest)
			return
		}
		added, err := h.store.AddAlert(a)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.AlertConfigured(added.ID, added.Name, ip, user))
		http.Redirect(w, r, "/alerts", http.StatusSeeOther)
		return
	}
	h.render(w, "alert_new", map[string]interface{}{"Title": "Add alert destination"})
}

func (h *handlers) alertRouter(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/alerts/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	switch {
	case len(parts) == 2 && parts[1] == "delete" && r.Method == http.MethodPost:
		if err := h.store.DeleteAlert(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.AlertUnconfigured(id, ip, user))
		http.Redirect(w, r, "/alerts", http.StatusSeeOther)
	case len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost:
		h.alertTest(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// alertTest builds a synthetic AlertPayload and POSTs it to the
// destination so operators can verify their Slack / Teams / webhook
// wiring without waiting for a real scan-and-diff to fire.
func (h *handlers) alertTest(w http.ResponseWriter, r *http.Request, id string) {
	a, ok, err := h.store.GetAlert(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	postAlert(a, testPayload(), h.audit)
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, 202, map[string]string{"status": "test queued"})
		return
	}
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}

// ----- JSON API ---------------------------------------------------------

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *handlers) apiHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"status":               "ok",
		"version":              h.version,
		"timestamp":            time.Now().UTC(),
		"fips140_module":       fips140.Version(),
		"fips140_mode_enabled": fips140.Enabled(),
	})
}

func (h *handlers) apiTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		targets, err := h.store.ListTargets()
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		writeJSON(w, 200, targets)
	case http.MethodPost:
		var in Target
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, apiError{err.Error()})
			return
		}
		if in.Value == "" || (in.Type != TargetRepo && in.Type != TargetImage) {
			writeJSON(w, 400, apiError{"type and value are required"})
			return
		}
		t, err := h.store.AddTarget(in)
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetAdded(t.ID, string(t.Type), t.Value, ip, user))
		h.sched.RequestScan(t.ID)
		writeJSON(w, 201, t)
	default:
		writeJSON(w, 405, apiError{"method not allowed"})
	}
}

func (h *handlers) apiTargetItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, 404, apiError{"not found"})
		return
	}
	id := parts[0]
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		t, ok, err := h.store.GetTarget(id)
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		if !ok {
			writeJSON(w, 404, apiError{"not found"})
			return
		}
		writeJSON(w, 200, t)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if err := h.store.DeleteTarget(id); err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetDeleted(id, ip, user))
		w.WriteHeader(204)
	case len(parts) == 2 && parts[1] == "scans" && r.Method == http.MethodGet:
		scans, err := h.store.ListScansForTarget(id)
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		writeJSON(w, 200, scans)
	case len(parts) == 2 && parts[1] == "scan" && r.Method == http.MethodPost:
		user, ip := h.actor(r)
		h.audit.Emit(audit.TargetScanRequested(id, ip, user))
		h.sched.RequestScan(id)
		writeJSON(w, 202, map[string]string{"status": "scan queued"})
	default:
		writeJSON(w, 405, apiError{"method not allowed"})
	}
}

func (h *handlers) apiAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		alerts, err := h.store.ListAlerts()
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		writeJSON(w, 200, alerts)
	case http.MethodPost:
		var in AlertDestination
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, apiError{err.Error()})
			return
		}
		if in.URL == "" || in.Name == "" {
			writeJSON(w, 400, apiError{"name and url are required"})
			return
		}
		a, err := h.store.AddAlert(in)
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.AlertConfigured(a.ID, a.Name, ip, user))
		writeJSON(w, 201, a)
	default:
		writeJSON(w, 405, apiError{"method not allowed"})
	}
}

func (h *handlers) apiAlertItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, 404, apiError{"not found"})
		return
	}
	id := parts[0]
	switch {
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if err := h.store.DeleteAlert(id); err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		user, ip := h.actor(r)
		h.audit.Emit(audit.AlertUnconfigured(id, ip, user))
		w.WriteHeader(204)
	case len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost:
		a, ok, err := h.store.GetAlert(id)
		if err != nil {
			writeJSON(w, 500, apiError{err.Error()})
			return
		}
		if !ok {
			writeJSON(w, 404, apiError{"not found"})
			return
		}
		postAlert(a, testPayload(), h.audit)
		writeJSON(w, 202, map[string]string{"status": "test queued"})
	default:
		writeJSON(w, 405, apiError{"method not allowed"})
	}
}

func (h *handlers) apiScanItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, 404, apiError{"not found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, 405, apiError{"method not allowed"})
		return
	}
	rec, ok, err := h.store.GetScan(id)
	if err != nil {
		writeJSON(w, 500, apiError{err.Error()})
		return
	}
	if !ok {
		writeJSON(w, 404, apiError{"not found"})
		return
	}
	writeJSON(w, 200, rec)
}
