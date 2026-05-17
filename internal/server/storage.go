// Package server implements the long-running fipscan service: a single
// binary that hosts an HTML dashboard, a JSON API, and a background
// scheduler that periodically re-scans a watchlist of code repositories
// and container images.
//
// State is persisted as JSON files on disk so the deployment remains
// auditable and works in air-gapped IL5+ environments without a database
// runtime dependency.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rbuilta/fipscan/internal/findings"
)

// TargetType identifies what kind of artifact a watchlist entry refers to.
type TargetType string

const (
	TargetRepo  TargetType = "repo"
	TargetImage TargetType = "image"
)

// Target is one entry in the scan watchlist.
type Target struct {
	ID         string     `json:"id"`
	Type       TargetType `json:"type"`
	Value      string     `json:"value"`               // owner/name for repos; image ref for images
	Ref        string     `json:"ref,omitempty"`       // git ref (repo only)
	Platform   string     `json:"platform,omitempty"`  // linux/amd64 etc. (image only)
	RepoHost   string     `json:"repo_host,omitempty"` // "github" | "gitlab" | "bitbucket" (repo only; default github)
	AddedAt    time.Time  `json:"added_at"`
	LastScan   *time.Time `json:"last_scan,omitempty"`
	LastScanID string     `json:"last_scan_id,omitempty"`
}

// ScanRecord is the persisted result of one scheduler run against one
// target. It captures enough to render the detail page and compute trend
// diffs without re-running the scan.
type ScanRecord struct {
	ID        string             `json:"id"`
	TargetID  string             `json:"target_id"`
	StartedAt time.Time          `json:"started_at"`
	Duration  time.Duration      `json:"duration"`
	Error     string             `json:"error,omitempty"`
	Summary   ScanSummary        `json:"summary"`
	Findings  []findings.Finding `json:"findings"`
}

type ScanSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// AlertDestination is a webhook URL the server POSTs to after every scan
// that produces new findings at or above MinSeverity. Generic enough to
// hit Slack / Teams / Discord / PagerDuty / any HTTP endpoint.
type AlertDestination struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	MinSeverity string    `json:"min_severity"` // "HIGH" | "MEDIUM" | "LOW"
	AddedAt     time.Time `json:"added_at"`
}

// Store is the concurrency-safe facade over the on-disk state. All file
// I/O passes through this type so callers don't need to lock or know
// about the layout.
type Store struct {
	root string
	mu   sync.Mutex
}

func NewStore(root string) (*Store, error) {
	for _, sub := range []string{"", "scans"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", filepath.Join(root, sub), err)
		}
	}
	s := &Store{root: root}
	// Initialise empty list files if they don't exist.
	for _, p := range []string{s.watchlistPath(), s.alertsPath()} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := writeJSONAtomic(p, []struct{}{}); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Store) watchlistPath() string { return filepath.Join(s.root, "watchlist.json") }
func (s *Store) alertsPath() string    { return filepath.Join(s.root, "alerts.json") }
func (s *Store) scanPath(id string) string {
	return filepath.Join(s.root, "scans", id+".json")
}

// ----- Targets ----------------------------------------------------------

func (s *Store) ListTargets() ([]Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readWatchlist()
}

func (s *Store) AddTarget(t Target) (Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readWatchlist()
	if err != nil {
		return Target{}, err
	}
	t.ID = newID()
	t.AddedAt = time.Now().UTC()
	list = append(list, t)
	if err := s.writeWatchlist(list); err != nil {
		return Target{}, err
	}
	return t, nil
}

func (s *Store) DeleteTarget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readWatchlist()
	if err != nil {
		return err
	}
	out := list[:0]
	for _, t := range list {
		if t.ID != id {
			out = append(out, t)
		}
	}
	return s.writeWatchlist(out)
}

func (s *Store) GetTarget(id string) (Target, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readWatchlist()
	if err != nil {
		return Target{}, false, err
	}
	for _, t := range list {
		if t.ID == id {
			return t, true, nil
		}
	}
	return Target{}, false, nil
}

// UpdateTargetScan stamps a target with the result of its most recent
// scan. Called by the scheduler after each run completes.
func (s *Store) UpdateTargetScan(id, scanID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readWatchlist()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ID == id {
			list[i].LastScan = &at
			list[i].LastScanID = scanID
			break
		}
	}
	return s.writeWatchlist(list)
}

// ----- Scans ------------------------------------------------------------

func (s *Store) SaveScan(rec ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONAtomic(s.scanPath(rec.ID), rec)
}

func (s *Store) GetScan(id string) (ScanRecord, bool, error) {
	var rec ScanRecord
	data, err := os.ReadFile(s.scanPath(id))
	if os.IsNotExist(err) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, false, err
	}
	return rec, true, nil
}

// ListScansForTarget returns scan records for one target, newest first.
// Reads every scan file and filters in-memory; acceptable at MVP scale.
func (s *Store) ListScansForTarget(targetID string) ([]ScanRecord, error) {
	dir := filepath.Join(s.root, "scans")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []ScanRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rec ScanRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if rec.TargetID == targetID {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// ----- Alerts -----------------------------------------------------------

func (s *Store) ListAlerts() ([]AlertDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAlerts()
}

func (s *Store) AddAlert(a AlertDestination) (AlertDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readAlerts()
	if err != nil {
		return AlertDestination{}, err
	}
	a.ID = newID()
	a.AddedAt = time.Now().UTC()
	if a.MinSeverity == "" {
		a.MinSeverity = "HIGH"
	}
	list = append(list, a)
	if err := s.writeAlerts(list); err != nil {
		return AlertDestination{}, err
	}
	return a, nil
}

func (s *Store) DeleteAlert(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readAlerts()
	if err != nil {
		return err
	}
	out := list[:0]
	for _, a := range list {
		if a.ID != id {
			out = append(out, a)
		}
	}
	return s.writeAlerts(out)
}

func (s *Store) GetAlert(id string) (AlertDestination, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readAlerts()
	if err != nil {
		return AlertDestination{}, false, err
	}
	for _, a := range list {
		if a.ID == id {
			return a, true, nil
		}
	}
	return AlertDestination{}, false, nil
}

func (s *Store) readAlerts() ([]AlertDestination, error) {
	data, err := os.ReadFile(s.alertsPath())
	if err != nil {
		return nil, err
	}
	var list []AlertDestination
	if len(data) == 0 {
		return list, nil
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Store) writeAlerts(list []AlertDestination) error {
	if list == nil {
		list = []AlertDestination{}
	}
	return writeJSONAtomic(s.alertsPath(), list)
}

// ----- Internals --------------------------------------------------------

func (s *Store) readWatchlist() ([]Target, error) {
	data, err := os.ReadFile(s.watchlistPath())
	if err != nil {
		return nil, err
	}
	var list []Target
	if len(data) == 0 {
		return list, nil
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Store) writeWatchlist(list []Target) error {
	if list == nil {
		list = []Target{}
	}
	return writeJSONAtomic(s.watchlistPath(), list)
}

// writeJSONAtomic writes v as pretty JSON to path, using a temp file +
// rename so concurrent readers never observe a partial file.
func writeJSONAtomic(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// newID returns a 16-byte random hex identifier. We use crypto/rand
// because it's the FIPS-validated source; for IDs the randomness quality
// is irrelevant but consistency with the FIPS posture matters.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read should never fail; fall back to timestamp-based id.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
