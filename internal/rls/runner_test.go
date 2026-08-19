package rls

import (
	"context"
	"net"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netcracker/qubership-ratelimit/internal/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

func TestRunner_needsNoLeaderElection(t *testing.T) {
	// Every replica must answer checks. Gating the endpoint on the lease would
	// make every non-leader pod fail the gateways' calls.
	assert.False(t, (&Runner{}).NeedLeaderElection())
}

func TestRunner_servesAndStopsGracefully(t *testing.T) {
	log, _ := recordingLogger()
	ruleStore := storeFor("gateway.public")

	runner := &Runner{
		Addr:         freeAddr(t),
		Server:       NewServer(ruleStore, log),
		DrainTimeout: 2 * time.Second,
		Log:          logr.Discard(),
	}
	assert.False(t, runner.Serving(), "a runner that has not started must not report ready")

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()

	require.Eventually(t, runner.Serving, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, runner.Healthz(nil))

	conn, err := grpc.NewClient(runner.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := envoyratelimit.NewRateLimitServiceClient(conn).ShouldRateLimit(callCtx, request(
		"gateway.public",
		map[string]string{"path": "/api/v1/orders", "token": rawToken},
	))
	require.NoError(t, err)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())

	cancel()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the runner did not stop after its context was cancelled")
	}

	assert.False(t, runner.Serving())
	assert.Error(t, runner.Healthz(nil), "readiness must fail once the endpoint stops serving")
}

func TestRunner_reportsAnUnusableAddress(t *testing.T) {
	log, _ := recordingLogger()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	runner := &Runner{
		Addr:   occupied.Addr().String(),
		Server: NewServer(store.New(), log),
		Log:    logr.Discard(),
	}

	assert.Error(t, runner.Start(context.Background()))
}
