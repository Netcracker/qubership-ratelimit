package rls

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

func TestRunner_servesAndStopsGracefully(t *testing.T) {
	log, _ := recordingLogger()
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, "gateway.public"))

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

// A check larger than maxCheckBytes is refused by the transport, so a direct
// caller cannot hand the engine a value of megabytes.
func TestRunner_refusesAnOversizedCheck(t *testing.T) {
	log, _ := recordingLogger()
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, "gateway.public"))
	runner := &Runner{Addr: freeAddr(t), Server: NewServer(ruleStore, log), DrainTimeout: time.Second, Log: logr.Discard()}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()
	t.Cleanup(func() { cancel(); <-stopped })
	require.Eventually(t, runner.Serving, 5*time.Second, 10*time.Millisecond)

	conn, err := grpc.NewClient(runner.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := envoyratelimit.NewRateLimitServiceClient(conn)

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	_, err = client.ShouldRateLimit(callCtx, request("gateway.public",
		map[string]string{"path": "/" + strings.Repeat("a", maxCheckBytes)}))
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "an oversized check was accepted: %v", err)

	_, err = client.ShouldRateLimit(callCtx, request("gateway.public", map[string]string{"path": "/api/v1/orders"}))
	assert.NoError(t, err, "a check of ordinary size was refused")
}
