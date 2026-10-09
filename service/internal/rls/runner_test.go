package rls

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// startRunner starts a Runner of server on a free loopback address and returns
// once it reports serving. stop cancels the runner's context and returns what
// Start returned, or an error when Start has not returned within ten seconds;
// the test's cleanup calls it too.
func startRunner(t *testing.T, server *Server, drainTimeout time.Duration) (runner *Runner, stop func() error) {
	t.Helper()
	runner = &Runner{Addr: freeAddr(t), Server: server, DrainTimeout: drainTimeout, Log: logr.Discard()}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()

	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-stopped:
			case <-time.After(10 * time.Second):
				stopErr = errors.New("Runner.Start did not return within 10s of its context ending")
			}
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("stopping the runner on %s: %v", runner.Addr, err)
		}
	})

	require.Eventually(t, runner.Serving, 5*time.Second, 10*time.Millisecond,
		"Runner.Serving never reported true after Start on %s", runner.Addr)
	return runner, stop
}

// dialRunner returns a client of the rate limit service on runner's address,
// closed when the test ends.
func dialRunner(t *testing.T, runner *Runner) envoyratelimit.RateLimitServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(runner.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return envoyratelimit.NewRateLimitServiceClient(conn)
}

func TestRunner_isNotServingBeforeStart(t *testing.T) {
	server, _ := newServerOver(nil)
	runner := &Runner{Addr: freeAddr(t), Server: server, Log: logr.Discard()}

	assert.False(t, runner.Serving())
	assert.Error(t, runner.Healthz(nil), "Healthz before Start")
}

// A started runner reports itself ready and returns a verdict for a check over
// gRPC.
func TestRunner_servesChecksOnceStarted(t *testing.T) {
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))
	runner, _ := startRunner(t, server, 2*time.Second)
	client := dialRunner(t, runner)
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	resp, err := client.ShouldRateLimit(callCtx, request("gateway.public",
		map[string]string{"path": "/api/v1/orders", "token": rawToken}))

	assert.NoError(t, runner.Healthz(nil), "Healthz while serving")
	require.NoError(t, err)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
}

// The health service answers for the server and for the rate limit service by
// name, serving while the runner serves.
func TestRunner_answersHealthChecksForTheServiceByName(t *testing.T) {
	server, _ := newServerOver(nil)
	runner, _ := startRunner(t, server, 2*time.Second)
	conn, err := grpc.NewClient(runner.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)

	for _, service := range []string{"", "envoy.service.ratelimit.v3.RateLimitService"} {
		resp, err := client.Check(t.Context(), &healthpb.HealthCheckRequest{Service: service})
		require.NoError(t, err, "Check(%q)", service)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus(), "Check(%q)", service)
	}
}

// Once its context ends, Start drains and returns nil, and the runner reports
// itself not ready.
func TestRunner_stopsServingWhenItsContextEnds(t *testing.T) {
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))
	runner, stop := startRunner(t, server, 2*time.Second)

	err := stop()

	require.NoError(t, err, "Runner.Start after its context ended")
	assert.False(t, runner.Serving(), "Serving after Start returned")
	assert.Error(t, runner.Healthz(nil), "Healthz after Start returned")
}

func TestRunner_startFailsOnAnAddressInUse(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()
	server, _ := newServerOver(nil)
	runner := &Runner{Addr: occupied.Addr().String(), Server: server, Log: logr.Discard()}

	err = runner.Start(context.Background())

	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr, "Runner.Start on %s, which another listener holds", runner.Addr)
	assert.Equal(t, "listen", opErr.Op)
}

// A check larger than maxCheckBytes, 128 KiB (131072 bytes), is refused by the
// transport, so a direct caller cannot hand the engine a value of megabytes. A
// check of ordinary size on the same connection is the control.
func TestRunner_refusesACheckOverTheMessageSizeLimit(t *testing.T) {
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))
	runner, _ := startRunner(t, server, time.Second)
	client := dialRunner(t, runner)
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	_, err := client.ShouldRateLimit(callCtx, request("gateway.public",
		map[string]string{"path": "/" + strings.Repeat("a", 131072)}))
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "status of a check with a path of 131073 bytes: %v", err)

	_, err = client.ShouldRateLimit(callCtx, request("gateway.public", map[string]string{"path": "/api/v1/orders"}))
	assert.NoError(t, err, "a check of ordinary size")
}

// A check of exactly 128 KiB (131072 bytes), the size docs/limits.md allows,
// is served. TestRunner_refusesACheckOverTheMessageSizeLimit refuses a larger
// one.
func TestRunner_servesACheckOfExactlyTheMessageSizeLimit(t *testing.T) {
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))
	runner, _ := startRunner(t, server, time.Second)
	client := dialRunner(t, runner)
	atTheLimit := request("gateway.public", map[string]string{"path": "/" + strings.Repeat("a", 131037)})
	require.Equal(t, 131072, proto.Size(atTheLimit), "the encoded size of the check")
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	_, err := client.ShouldRateLimit(callCtx, atTheLimit)

	assert.NoError(t, err, "a check of 131072 bytes")
}

// heldCounters is a counter store that holds a decision in flight: Decide
// signals entered, and returns once the call's context ends.
type heldCounters struct {
	entered chan struct{}
}

func (h heldCounters) Decide(ctx context.Context, _ []counters.Bucket, _ int64) ([]counters.Verdict, error) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (heldCounters) Peek(context.Context, []counters.Bucket, int64) ([]counters.Verdict, error) {
	return nil, errors.New("heldCounters serves Decide alone")
}

func (heldCounters) Reset(context.Context, []string) error {
	return errors.New("heldCounters serves Decide alone")
}

// A check in flight when the context ends holds up the drain for
// DrainTimeout at most: Start then closes the connections and returns. Only
// the end of the check's context releases it from the store, so the drain
// alone never completes.
func TestRunner_endsTheDrainAtTheDrainTimeout(t *testing.T) {
	held := heldCounters{entered: make(chan struct{}, 1)}
	p := domainWidePolicy(1, time.Hour)
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", &p, held))
	runner, stop := startRunner(t, server, 200*time.Millisecond)
	client := dialRunner(t, runner)
	go func() {
		_, _ = client.ShouldRateLimit(context.Background(),
			request("gateway.public", map[string]string{"path": "/api"}))
	}()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("waited 5s for the check to reach the counter store")
	}
	started := time.Now()

	err := stop()

	require.NoError(t, err, "Runner.Start with a check in flight past the drain timeout")
	assert.GreaterOrEqual(t, time.Since(started), 200*time.Millisecond, "the time Start spent draining")
}
