package management

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// newErrorLog routes net/http's own error output through the platform logger,
// so a TLS handshake failure or a malformed request lands in the same stream
// as everything else this process writes.
func newErrorLog(log logr.Logger) *stdlog.Logger {
	return stdlog.New(logrWriter{log: log}, "", 0)
}

type logrWriter struct{ log logr.Logger }

func (w logrWriter) Write(p []byte) (int, error) {
	w.log.Info("management http server", "message", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// Timeouts for the management listener. They are deliberately generous
// compared with the decision path: these calls talk to the API server and to
// the counter store, and a reset of a busy rule enumerates before it drops.
const (
	// DefaultReadHeaderTimeout bounds how long a connection may take to send
	// its headers, which is what stops a slow-loris from holding one open.
	DefaultReadHeaderTimeout = 10 * time.Second

	// DefaultWriteTimeout bounds an ordinary response. The audit stream clears
	// its own deadline, since a stream is supposed to stay open.
	DefaultWriteTimeout = 60 * time.Second

	// DefaultIdleTimeout closes a kept-alive connection nobody is using.
	DefaultIdleTimeout = 120 * time.Second

	// DefaultDrainTimeout bounds how long shutdown waits for in-flight calls.
	// A stream only ends when its client goes away, so this is also how long a
	// shutdown waits before dropping one.
	DefaultDrainTimeout = 10 * time.Second
)

// Runner serves the management API as a controller-runtime runnable.
type Runner struct {
	Addr    string
	Handler http.Handler
	Log     logr.Logger

	DrainTimeout time.Duration
}

// NeedLeaderElection reports false.
//
// Every replica serves this API for the same reason every replica answers rate
// limit checks: the Service load-balances across all of them, and an endpoint
// that only the leader answered would fail on most calls. Reads describe the
// replica that served them, and a reset against a shared store is global
// wherever it lands.
func (r *Runner) NeedLeaderElection() bool { return false }

// Start listens and serves until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", r.Addr, err)
	}

	server := &http.Server{
		Handler:           r.Handler,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
		// The server's own error log would otherwise write to the standard
		// logger, bypassing the platform format every other line uses.
		ErrorLog: newErrorLog(r.Log),
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	r.Log.Info("management API listening", "address", listener.Addr().String(), "basePath", BasePath)

	select {
	case err := <-served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve the management API: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	drainTimeout := r.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		// An open audit stream does not end on its own, so a shutdown that
		// times out on one is expected rather than a fault.
		r.Log.Info("management API drain timed out, closing connections", "timeout", drainTimeout)
		_ = server.Close()
	}
	<-served
	r.Log.Info("management API stopped")
	return nil
}
