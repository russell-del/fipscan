package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/rbuilta/fipscan/internal/container"
	"github.com/rbuilta/fipscan/internal/deps"
	"github.com/rbuilta/fipscan/internal/findings"
	"github.com/rbuilta/fipscan/internal/registry"
	"github.com/rbuilta/fipscan/internal/scan/code"
	"github.com/rbuilta/fipscan/internal/source"
)

// Scheduler periodically walks the watchlist and runs a scan against any
// target whose last scan is older than the configured interval. It also
// accepts manual on-demand scan requests over the inFlight channel.
type Scheduler struct {
	store     *Store
	interval  time.Duration
	publicURL string
	log       *log.Logger

	mu      sync.Mutex
	running map[string]bool // targetID currently mid-scan
	manual  chan string     // manual scan requests by target ID
}

func NewScheduler(s *Store, interval time.Duration, publicURL string) *Scheduler {
	return &Scheduler{
		store:     s,
		interval:  interval,
		publicURL: publicURL,
		log:       log.New(os.Stderr, "[scheduler] ", log.LstdFlags),
		running:   map[string]bool{},
		manual:    make(chan string, 16),
	}
}

// Run blocks until ctx is cancelled. It runs the watchlist sweep on a
// fixed cadence (every minute) and processes manual scan requests as
// they arrive.
func (sc *Scheduler) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	sc.sweep(ctx) // run once immediately on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sc.sweep(ctx)
		case id := <-sc.manual:
			sc.scanOne(ctx, id)
		}
	}
}

// RequestScan queues a manual scan of the given target. Non-blocking; if
// the queue is full the request is dropped (deliberate: a duplicate
// request shortly after one is in flight is not worth backing up).
func (sc *Scheduler) RequestScan(id string) {
	select {
	case sc.manual <- id:
	default:
	}
}

func (sc *Scheduler) sweep(ctx context.Context) {
	targets, err := sc.store.ListTargets()
	if err != nil {
		sc.log.Printf("list targets: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, t := range targets {
		if t.LastScan != nil && now.Sub(*t.LastScan) < sc.interval {
			continue
		}
		sc.scanOne(ctx, t.ID)
	}
}

func (sc *Scheduler) scanOne(ctx context.Context, id string) {
	sc.mu.Lock()
	if sc.running[id] {
		sc.mu.Unlock()
		return
	}
	sc.running[id] = true
	sc.mu.Unlock()
	defer func() {
		sc.mu.Lock()
		delete(sc.running, id)
		sc.mu.Unlock()
	}()

	t, ok, err := sc.store.GetTarget(id)
	if err != nil || !ok {
		return
	}
	prevScanID := t.LastScanID // capture before we overwrite via UpdateTargetScan
	sc.log.Printf("scan start: %s (%s)", t.Value, t.Type)

	rec := ScanRecord{
		ID:        newID(),
		TargetID:  t.ID,
		StartedAt: time.Now().UTC(),
	}
	results, err := executeScan(t)
	rec.Duration = time.Since(rec.StartedAt)
	if err != nil {
		rec.Error = err.Error()
		sc.log.Printf("scan FAILED: %s — %v", t.Value, err)
	} else {
		rec.Findings = results
		rec.Summary = summarise(results)
		sc.log.Printf("scan ok: %s — %d findings (H:%d M:%d L:%d)",
			t.Value, rec.Summary.Total, rec.Summary.High, rec.Summary.Medium, rec.Summary.Low)
	}

	if err := sc.store.SaveScan(rec); err != nil {
		sc.log.Printf("save scan %s: %v", rec.ID, err)
		return
	}
	if err := sc.store.UpdateTargetScan(t.ID, rec.ID, rec.StartedAt); err != nil {
		sc.log.Printf("update target %s: %v", t.ID, err)
	}

	dispatchAlerts(sc.store, t, rec, prevScanID, sc.publicURL)
}

// executeScan dispatches to the correct backend based on the target type.
// Returns the merged findings list (or an error if the scan couldn't run).
func executeScan(t Target) ([]findings.Finding, error) {
	switch t.Type {
	case TargetRepo:
		owner, name, err := source.ParseRepoSpec(t.Value)
		if err != nil {
			return nil, err
		}
		token := os.Getenv("GITHUB_TOKEN")
		fetcher := source.NewGitHubFetcher(token)
		dir, err := fetcher.FetchRepo(owner, name, t.Ref)
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		codeFindings, err := code.ScanPath(dir, code.Options{})
		if err != nil {
			return nil, err
		}
		depFindings, err := deps.ScanPath(dir, deps.Options{})
		if err != nil {
			return nil, err
		}
		return append(codeFindings, depFindings...), nil
	case TargetImage:
		plat := registry.DefaultPlatform
		if t.Platform != "" {
			p, err := registry.ParsePlatform(t.Platform)
			if err != nil {
				return nil, err
			}
			plat = p
		}
		auth := authFromEnv()
		return container.ScanImage(t.Value, auth, plat)
	default:
		return nil, fmt.Errorf("unknown target type %q", t.Type)
	}
}

func authFromEnv() *registry.BasicAuth {
	u, p := os.Getenv("FIPSCAN_REGISTRY_USERNAME"), os.Getenv("FIPSCAN_REGISTRY_PASSWORD")
	if u == "" && p == "" {
		return nil
	}
	return &registry.BasicAuth{Username: u, Password: p}
}

func summarise(fs []findings.Finding) ScanSummary {
	s := ScanSummary{Total: len(fs)}
	for _, f := range fs {
		switch f.Severity {
		case findings.SeverityHigh:
			s.High++
		case findings.SeverityMedium:
			s.Medium++
		case findings.SeverityLow:
			s.Low++
		}
	}
	return s
}
