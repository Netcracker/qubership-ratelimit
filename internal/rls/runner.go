package rls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// DefaultDrainTimeout bounds how long in-flight checks may hold up shutdown
// before the listener is closed the hard way.
const DefaultDrainTimeout = 10 * time.Second

// Runner serves the RLS gRPC endpoint as a controller-runtime runnable.
type Runner struct {
	Addr         string
	Server       *Server
	DrainTimeout time.Duration
	Log          logr.Logger

	serving atomic.Bool
}

// NeedLeaderElection reports false: every replica must answer checks, or the
// gateways would see errors from every pod that is not the leader.
func (r *Runner) NeedLeaderElection() bool { return false }

func (r *Runner) Serving() bool { return r.serving.Load() }

func (r *Runner) Healthz(_ *http.Request) error {
	if !r.Serving() {
		return errors.New("rls gRPC server is not serving")
	}
	return nil
}

// Start listens and serves until ctx is cancelled.
//
// Shutdown order is deliberate: stop accepting new calls, drain the in-flight
// ones, and only then return — the manager releases the leader lease after its
// runnables are done, so a replica never gives up the lease while it is still
// answering.
func (r *Runner) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", r.Addr, err)
	}

	grpcServer := grpc.NewServer()
	envoyratelimit.RegisterRateLimitServiceServer(grpcServer, r.Server)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	served := make(chan error, 1)
	go func() { served <- grpcServer.Serve(listener) }()

	r.serving.Store(true)
	r.Log.Info("rls gRPC server listening", "address", listener.Addr().String())

	select {
	case err := <-served:
		r.serving.Store(false)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve rls gRPC: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	r.serving.Store(false)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)

	drainTimeout := r.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	drained := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(drained)
	}()
	select {
	case <-drained:
		r.Log.Info("rls gRPC server stopped")
	case <-time.After(drainTimeout):
		r.Log.Info("rls gRPC drain timed out, closing connections", "timeout", drainTimeout)
		grpcServer.Stop()
		<-drained
	}
	<-served
	return nil
}
