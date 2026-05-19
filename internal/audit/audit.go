// Package audit emits security-relevant events to a JSONL file (or
// stderr) in a SIEM-friendly format.
//
// Wire format: Elastic Common Schema (ECS) 8.x, JSON one-event-per-line
// (a.k.a. NDJSON / JSONL). ECS is natively parsed by Elastic / Splunk
// (via the ECS app) / Datadog / Sumo / Wazuh / Grafana Loki. Operators
// who need different formats can transform with a one-line jq filter or
// a Logstash / Vector pipeline:
//
//	OCSF: ECS → OCSF crosswalk maintained by the OCSF project
//	CEF:  echo $json | jq -r '"CEF:0|fipscan|fipscan|\(.service.version)|\(.event.action)|\(.event.action)|3|src=\(.source.ip // "-") suser=\(.user.name // "-") outcome=\(.event.outcome)"'
//	LEEF: similar one-liner
//
// File handling:
//   - O_APPEND opens are atomic for writes up to PIPE_BUF (~4 KiB on
//     Linux/macOS). Our events comfortably fit, so concurrent writers
//     interleave by line, never by character.
//   - We do NOT rotate. Use logrotate / k8s sidecars / Vector etc.
//     to manage rotation. SIGHUP support is a future addition.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit-log entry, ECS 8.x-compatible.
//
// Required ECS fields: @timestamp, event.*, service.*, host.*.
// Optional ECS fields are populated only when relevant to the event.
// The fipscan-specific block sits under a namespaced "fipscan" key so
// it never collides with ECS reserved names.
type Event struct {
	Timestamp time.Time `json:"@timestamp"`

	Event   EventCore  `json:"event"`
	Service Service    `json:"service"`
	Host    Host       `json:"host"`
	Source  *NetSource `json:"source,omitempty"`
	User    *User      `json:"user,omitempty"`
	HTTP    *HTTPInfo  `json:"http,omitempty"`
	Message string     `json:"message,omitempty"` // free-form human-readable summary
	Fipscan *Fipscan   `json:"fipscan,omitempty"`
}

// EventCore is ECS's `event.*` group. We populate every field; readers
// like Splunk's ECS app rely on them being present.
type EventCore struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`     // "event" | "state"
	Category []string `json:"category"` // ECS controlled vocabulary
	Type     []string `json:"type"`     // ECS controlled vocabulary
	Action   string   `json:"action"`   // free-form short action name
	Outcome  string   `json:"outcome"`  // "success" | "failure" | "unknown"
	Module   string   `json:"module"`   // "fipscan"
	Dataset  string   `json:"dataset"`  // "fipscan.audit"
	Reason   string   `json:"reason,omitempty"`
}

type Service struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // "fipscan-server" | "fipscan-cli"
}

type Host struct {
	Hostname string `json:"hostname"`
}

type NetSource struct {
	IP string `json:"ip"`
}

type User struct {
	Name string `json:"name"`
}

type HTTPInfo struct {
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}
type HTTPRequest struct {
	Method string `json:"method"`
}
type HTTPResponse struct {
	StatusCode int `json:"status_code"`
}

// Fipscan is the namespaced custom block for product-specific detail
// that doesn't fit ECS's standard groups. SIEM dashboards can index
// these directly (e.g., `fipscan.target.value`, `fipscan.findings.high`).
type Fipscan struct {
	Target   *Target   `json:"target,omitempty"`
	Scan     *Scan     `json:"scan,omitempty"`
	Findings *Findings `json:"findings,omitempty"`
	Alert    *Alert    `json:"alert,omitempty"`
}

type Target struct {
	ID    string `json:"id,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}
type Scan struct {
	ID         string `json:"id,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}
type Findings struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}
type Alert struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// ---------------------------------------------------------------------

// Logger writes Events as JSON lines to a file (or stderr if path "").
// All methods are safe for concurrent use.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	file     *os.File
	hostname string
	service  Service
}

// New opens path for append, or returns a stderr-backed Logger when path
// is empty. Caller should defer Close().
func New(path, serviceVersion, serviceType string) (*Logger, error) {
	host, _ := os.Hostname()
	svc := Service{Name: "fipscan", Version: serviceVersion, Type: serviceType}

	if path == "" {
		return &Logger{w: os.Stderr, hostname: host, service: svc}, nil
	}
	// Ensure the parent directory exists so callers can point at e.g.
	// /var/lib/fipscan/audit.log without pre-creating the data dir.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create audit log dir %s: %w", dir, err)
		}
	}
	// 0o640: owner rw, group r — typical for audit logs that a SIEM
	// agent (running as a group member) needs to read.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &Logger{w: f, file: f, hostname: host, service: svc}, nil
}

// Path returns the on-disk path the logger writes to, or "" if writing
// to stderr.
func (l *Logger) Path() string {
	if l.file == nil {
		return ""
	}
	return l.file.Name()
}

// Emit serialises e and writes one JSON line. Required ECS metadata
// (timestamp, service, host, module, dataset, event id) is filled in
// automatically when callers leave the fields zero.
func (l *Logger) Emit(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Event.ID == "" {
		e.Event.ID = newEventID()
	}
	if e.Event.Module == "" {
		e.Event.Module = "fipscan"
	}
	if e.Event.Dataset == "" {
		e.Event.Dataset = "fipscan.audit"
	}
	e.Service = l.service
	e.Host = Host{Hostname: l.hostname}

	buf, err := json.Marshal(&e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// One write call per line keeps it atomic up to PIPE_BUF on POSIX
	// and avoids interleaving when multiple goroutines emit.
	_, _ = l.w.Write(append(buf, '\n'))
}

// Close releases the underlying file handle (if any).
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// newEventID returns a random 128-bit hex string. Uniqueness is the
// only requirement — we use crypto/rand so the source is FIPS-approved
// and consistent with the rest of the tool's posture, not for entropy.
func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// NopLogger returns a Logger that writes to io.Discard. Useful in
// places where audit emission is wanted but no logger is configured.
func NopLogger() *Logger {
	host, _ := os.Hostname()
	return &Logger{
		w:        io.Discard,
		hostname: host,
		service:  Service{Name: "fipscan", Type: "fipscan-server"},
	}
}
