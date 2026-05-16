package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rbuilta/fipscan/internal/audit"
)

// Config controls the server runtime.
type Config struct {
	Listen           string
	DataDir          string
	Interval         time.Duration
	Version          string
	AuthUser         string // HTTP Basic username (default "admin")
	AuthPasswordHash string // empty = no auth; only allowed for localhost binds
	PublicURL        string // e.g. "https://fipscan.internal.example.com" — embedded in alert payloads
	AuditLogPath     string // empty = audit events go to stderr; set a path to write SIEM-friendly JSONL
}

// Run is the entry point invoked by `fipscan server`. It builds the
// storage layer, starts the scheduler goroutine, mounts the HTTP routes,
// and blocks until SIGTERM / SIGINT.
//
// Authentication policy:
//   - localhost binds may omit AuthPasswordHash (single-user dev mode)
//   - non-localhost binds REQUIRE AuthPasswordHash; Run refuses to start
//     otherwise to prevent accidentally exposing an unauthenticated
//     scanner to the network.
func Run(cfg Config) error {
	localhost := isLocalhostBind(cfg.Listen)
	if !localhost && cfg.AuthPasswordHash == "" {
		return fmt.Errorf(
			"refusing to listen on %s without authentication: "+
				"set FIPSCAN_AUTH_PASSWORD_HASH or use -auth-password-hash "+
				"(generate with `fipscan hash-password`); to override, bind to 127.0.0.1",
			cfg.Listen)
	}

	auditor, err := audit.New(cfg.AuditLogPath, cfg.Version, "fipscan-server")
	if err != nil {
		return fmt.Errorf("init audit log: %w", err)
	}
	defer auditor.Close()

	store, err := NewStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("init storage: %w", err)
	}
	sched := NewScheduler(store, cfg.Interval, cfg.PublicURL, auditor)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go sched.Run(ctx)

	mux := http.NewServeMux()
	h := newHandlers(store, sched, cfg.Version, auditor)
	h.registerRoutes(mux)

	var handler http.Handler = mux
	handler = basicAuth(cfg.AuthUser, cfg.AuthPasswordHash, auditor, handler)
	handler = accessLog(handler)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger := log.New(os.Stderr, "[server] ", log.LstdFlags)
	authState := "no auth (localhost only)"
	if cfg.AuthPasswordHash != "" {
		authState = "HTTP Basic auth as user=" + cfg.AuthUser
	}
	auditPath := auditor.Path()
	if auditPath == "" {
		auditPath = "stderr"
	}
	logger.Printf("fipscan %s — listening on http://%s  (data: %s, scan interval: %s, %s, audit: %s)",
		cfg.Version, cfg.Listen, cfg.DataDir, cfg.Interval, authState, auditPath)
	auditor.Emit(audit.ServerStarted(cfg.Listen, cfg.AuthPasswordHash != ""))

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Println("shutting down...")
		auditor.Emit(audit.ServerStopped())
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		return srv.Shutdown(shutCtx)
	}
}

// clientIP returns the best-effort source IP for an HTTP request. Falls
// back to RemoteAddr if no trustworthy proxy header is present.
//
// We deliberately do NOT honour X-Forwarded-For unless a future
// -trust-proxy-headers flag is added — trusting it by default would let
// any client spoof the recorded source IP in the audit log.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// accessLog is a tiny middleware that emits one line per request to
// stderr. It's the audit trail for the server's write activity.
func accessLog(h http.Handler) http.Handler {
	logger := log.New(os.Stderr, "[http] ", log.LstdFlags)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(rw, r)
		logger.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// isLocalhostBind reports whether addr is bound to a loopback interface
// (127.0.0.0/8, ::1, or the literal "localhost"). Used by Run to decide
// whether unauthenticated operation is safe.
func isLocalhostBind(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "localhost" {
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	return host == "::1"
}
