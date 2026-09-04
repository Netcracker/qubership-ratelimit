//go:build !race

package rls

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// The throughput floor one replica has to clear, and the decision budget it has
// to clear it within.
//
// The floor is deliberately far under what the path measures — the engine
// answers in single-digit microseconds and the store script adds roughly nine
// plus four per bucket, so a healthy build clears this by an order of
// magnitude. That margin is the point: a CI runner is shared hardware, and an
// assertion pitched near the real number would fail for reasons that have
// nothing to do with the code. What this catches is a regression that changes
// the shape of the path — a lock held across the store call, a per-request
// allocation storm, an accidental round trip per rule.
const (
	loadFloorPerSecond = 5_000
	loadP99Budget      = 10 * time.Millisecond
)

// loadDuration is short on purpose: the floor is a shape check, and a test
// nobody is willing to keep in the default suite stops being run at all.
const (
	loadDuration = 3 * time.Second
	loadWorkers  = 16
)

// loadWorkerCount lets an experiment vary concurrency without a rebuild.
func loadWorkerCount() int {
	if raw := os.Getenv("LOAD_WORKERS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	return loadWorkers
}

// loadPolicy admits everything for the length of the run.
//
// A limit that could be reached would turn the measurement into a measurement
// of the refusal path, which is cheaper — refusals skip the write. The rule
// counts by client so every request keys its own bucket, which is the shape a
// gateway actually produces.
func loadPolicy() model.Policy {
	return model.Policy{
		Domain: "gateway.public",
		Blocks: []model.Block{{
			Name: "all",
			Rules: []model.Rule{{
				Name:     "per-client",
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{{Requests: 1_000_000_000, Period: time.Hour, Algorithm: "FixedWindow"}},
			}},
		}},
	}
}

// loadCounterStore returns the store the run counts in.
//
// Redis when REDIS_ADDR names one, which is what CI provides: the requirement
// is about a replica backed by a shared store, and the in-process store would
// measure the decision path with its most expensive leg removed. Without the
// variable the run still happens over the in-process store, so the test stays
// useful on a laptop and in a build without services.
//
// The store REDIS_ADDR names has to be as close as the latency budget assumes —
// loopback, or the same zone. Pointing it at a store across a tunnel or a WAN
// measures the link and fails on numbers that say nothing about this code.
func loadCounterStore(t *testing.T) (counters.Store, string) {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return memory.New(), "in-process"
	}

	client := goredis.NewUniversalClient(&goredis.UniversalOptions{Addrs: []string{addr}})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, client.Ping(ctx).Err(), "REDIS_ADDR is set but the store does not answer")
	return redisstore.New(client), "redis at " + addr
}

// TestLoad_oneReplicaHoldsTheFloor drives the real gRPC server over a real
// connection and asserts the throughput and latency a single replica owes.
//
// It goes through the transport rather than calling ShouldRateLimit directly:
// the requirement is about what a replica serves, and marshalling and dispatch
// are part of that. What it leaves out is the network between gateway and pod,
// which is the deployment's property and not this code's.
func TestLoad_oneReplicaHoldsTheFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("the load floor is not a -short test")
	}

	counterStore, backend := loadCounterStore(t)
	p := loadPolicy()
	snapshot, problems := compile.Compile(testNamespace, "gateway.public", &p)
	for _, problem := range problems {
		require.False(t, problem.Blocking, "blocking compile problem: %+v", problem)
	}

	ruleStore := store.New()
	ruleStore.Replace(store.NewRuleSet(map[string]store.Domain{
		"gateway.public": {Engine: engine.New(snapshot, counterStore), Snapshot: snapshot},
	}))

	runner := &Runner{
		Addr:         freeAddr(t),
		Server:       NewServer(ruleStore, discardLogger{}),
		DrainTimeout: 5 * time.Second,
		Log:          logr.Discard(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("the server did not stop")
		}
	})
	require.Eventually(t, runner.Serving, 10*time.Second, 10*time.Millisecond)

	conn, err := grpc.NewClient(runner.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := envoyratelimit.NewRateLimitServiceClient(conn)

	latencies := runLoad(t, client)
	require.NotEmpty(t, latencies, "no request completed")

	slices.Sort(latencies)
	perSecond := float64(len(latencies)) / loadDuration.Seconds()
	p99 := latencies[(len(latencies)*99)/100]

	t.Logf("backend=%s decisions=%d throughput=%.0f/s p50=%s p99=%s",
		backend, len(latencies), perSecond, latencies[len(latencies)/2], p99)

	require.GreaterOrEqualf(t, perSecond, float64(loadFloorPerSecond),
		"one replica served %.0f decisions/s over %s against %s; the floor is %d/s",
		perSecond, loadDuration, backend, loadFloorPerSecond)
	require.LessOrEqualf(t, p99, loadP99Budget,
		"p99 was %s against %s; the decision budget is %s", p99, backend, loadP99Budget)
}

// runLoad drives the server for loadDuration and returns every latency it
// measured. Each worker keys its own client so the run spreads over buckets
// the way real traffic does rather than contending on one.
func runLoad(t *testing.T, client envoyratelimit.RateLimitServiceClient) []time.Duration {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), loadDuration)
	defer cancel()

	var wg sync.WaitGroup
	workers := loadWorkerCount()
	perWorker := make([][]time.Duration, workers)
	for w := range workers {
		wg.Go(func() {
			req := request("gateway.public", map[string]string{
				"path":   "/api/v1/orders",
				"method": "GET",
				"client": fmt.Sprintf("load-%d", w),
			})
			// Sized so a healthy run never grows the slice mid-measurement.
			samples := make([]time.Duration, 0, loadFloorPerSecond*int(loadDuration.Seconds()))
			// Published on every exit path. The window almost always expires
			// while a call is in flight, and a worker that returned through
			// the error branch without publishing would drop its whole share
			// of the measurement — silently, as a throughput that varies with
			// how many workers happened to end mid-call.
			defer func() { perWorker[w] = samples }()

			for ctx.Err() == nil {
				start := time.Now()
				if _, err := client.ShouldRateLimit(ctx, req); err != nil {
					// The window closing mid-call is how the run ends. The
					// status code is what says so: reading ctx.Err() races the
					// deadline, and the call in flight when the timer fires
					// would then be reported as a failure on every run.
					if code := status.Code(err); code != codes.DeadlineExceeded && code != codes.Canceled {
						t.Errorf("ShouldRateLimit: %v", err)
					}
					return
				}
				samples = append(samples, time.Since(start))
			}
		})
	}
	wg.Wait()

	total := 0
	for _, samples := range perWorker {
		total += len(samples)
	}
	all := make([]time.Duration, 0, total)
	for _, samples := range perWorker {
		all = append(all, samples...)
	}
	return all
}

// discardLogger keeps the measurement about the decision path. The per-check
// debug line is real work, but it is work a production replica does at info
// level, not debug, and leaving it on would measure the test's logger.
type discardLogger struct{}

func (discardLogger) DebugC(context.Context, string, ...any) {}
func (discardLogger) InfoC(context.Context, string, ...any)  {}
func (discardLogger) ErrorC(context.Context, string, ...any) {}
