package management

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gofiber/fiber/v2"

	fiberserver "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2"
	fibererrors "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2/errors"
	"github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2/security"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

// Timeouts for the management listener. They are deliberately generous
// compared with the decision path: these calls talk to the counter store, and a
// reset of a busy rule looks its keys up before it drops them.
const (
	// DefaultReadTimeout bounds how long a connection may take to send its
	// request, which is what stops a slow-loris from holding one open.
	DefaultReadTimeout = 10 * time.Second

	// DefaultWriteTimeout bounds an ordinary response.
	DefaultWriteTimeout = 60 * time.Second

	// DefaultIdleTimeout closes a kept-alive connection nobody is using.
	DefaultIdleTimeout = 120 * time.Second

	// DefaultDrainTimeout bounds how long shutdown waits for in-flight calls.
	DefaultDrainTimeout = 10 * time.Second
)

// NewApp builds the platform's Fiber app with this API mounted on it.
//
// The app comes from the platform builder rather than from net/http, so this
// service answers like every other service of the platform: the same context
// propagation, the same security middleware, and the same TMF error envelope
// for anything the handlers do not answer themselves. The instrumentation
// endpoints stay off, because health and metrics are served by the manager's own
// listener and a second copy of them here would be a second answer to the same
// question.
func NewApp(api *API) (*fiber.App, error) {
	// The builder requires a security middleware to be registered. A deployment
	// that installs its own registers it first and wins by priority; without
	// one the platform's pass-through applies, and authorization stays this
	// package's own path-and-verb check.
	if _, found := serviceloader.Load[security.SecurityMiddleware](); !found {
		serviceloader.Register(1, &security.DummyFiberServerSecurityMiddleware{})
	}

	app, err := fiberserver.New(fiber.Config{
		AppName:               "ratelimit-management",
		ReadTimeout:           DefaultReadTimeout,
		WriteTimeout:          DefaultWriteTimeout,
		IdleTimeout:           DefaultIdleTimeout,
		DisableStartupMessage: true,
		// Anything a handler did not answer itself lands here: a panic the
		// recovery middleware turned into an error, or a route the router
		// refused. RLS-0500 is the code such an error is reported under.
		ErrorHandler: fibererrors.DefaultErrorHandler(CodeInternal),
	}).Process()
	if err != nil {
		return nil, fmt.Errorf("build the management app: %w", err)
	}

	api.Register(app)

	// This app serves nothing but the management API, so a path outside it is a
	// mistake worth answering in the same envelope as everything else rather
	// than with the router's plain-text default. It is registered last, after
	// every route, which is what makes it the fallback.
	app.Use(withRequestID, func(c *fiber.Ctx) error {
		return notFound("no endpoint serves " + c.Method() + " on this path")
	})
	return app, nil
}

// Runner serves the management app as a controller-runtime runnable.
type Runner struct {
	Addr string
	App  *fiber.App

	// API is the mounted API, so an accepted sweep runs under this runnable's
	// context: a client that goes away does not stop it, and shutdown does.
	API *API

	Log Logger

	DrainTimeout time.Duration
}

// NeedLeaderElection reports false.
//
// Every replica serves this API for the same reason every replica answers rate
// limit checks: the Service load-balances across all of them, and an endpoint
// only the leader answered would fail on most calls. Reads describe the replica
// that served them, and a reset against a shared store is global wherever it
// lands.
func (r *Runner) NeedLeaderElection() bool { return false }

// Start listens and serves until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) error {
	listener, err := r.listen()
	if err != nil {
		return err
	}

	if r.API != nil {
		r.API.StartBackground(ctx)
	}

	served := make(chan error, 1)
	go func() { served <- r.App.Listener(listener) }()

	r.Log.InfoC(ctx, "management API listening address=%v basePath=%v",
		listener.Addr().String(), BasePath)

	select {
	case err := <-served:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("serve the management API: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	drainTimeout := r.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	if err := r.App.ShutdownWithTimeout(drainTimeout); err != nil {
		r.Log.InfoC(ctx, "management API drain timed out, closing connections timeout=%v", drainTimeout)
	}
	<-served
	r.Log.InfoC(ctx, "management API stopped")
	return nil
}

// listen opens the socket, honoring the platform's TLS configuration: a
// deployment that turns TLS on turns it on for every listener at once, and the
// one left in plaintext would be the one that matters. These endpoints lift
// limits.
func (r *Runner) listen() (net.Listener, error) {
	if utils.IsTlsEnabled() {
		listener, err := tls.Listen(r.App.Config().Network, r.Addr, utils.GetTlsConfig())
		if err != nil {
			return nil, fmt.Errorf("listen for TLS on %s: %w", r.Addr, err)
		}
		return listener, nil
	}
	listener, err := net.Listen("tcp", r.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", r.Addr, err)
	}
	return listener, nil
}
