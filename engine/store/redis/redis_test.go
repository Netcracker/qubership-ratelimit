package redis_test

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis_rate/v10"
	goredis "github.com/redis/go-redis/v9"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	"github.com/netcracker/qubership-ratelimit/engine/store/storetest"
)

// tolerance absorbs the clock difference between this process and the store
// when durations are compared across the two.
const tolerance = 2 * time.Second

// client resolves the store under test in three steps: REDIS_ADDR when set
// (the CI service, a cluster, anything explicit); a disposable container this
// test binary starts itself when Docker is available; a skip otherwise. An
// explicit address that stays unreachable is a failure, never a silent skip.
func client(t testing.TB) goredis.UniversalClient {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		var reason string
		addr, reason = disposableRedis()
		if addr == "" {
			t.Skipf("REDIS_ADDR is not set and no disposable Redis: %s", reason)
		}
	}
	c := goredis.NewUniversalClient(&goredis.UniversalOptions{Addrs: strings.Split(addr, ",")})
	t.Cleanup(func() { _ = c.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := c.Ping(t.Context()).Err()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("Redis at %s is unreachable: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// disposable is the one throwaway container shared by every test in this
// binary; TestMain stops it. The testcontainers behavior without the
// dependency swarm: docker CLI via os/exec, a random host port, --rm.
var disposable struct {
	once sync.Once
	addr string
	err  string
	name string
}

func disposableRedis() (addr, reason string) {
	disposable.once.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			disposable.err = "docker is not in PATH"
			return
		}

		// A published port lands on the machine running the daemon, which is not
		// necessarily this one: DOCKER_HOST and docker contexts both point at
		// remote daemons routinely. Binding such a container to the loopback of
		// the daemon would publish it where no test can reach it, so the bind
		// address follows where the daemon lives.
		host := daemonHost()
		bind := "127.0.0.1"
		if host != "" {
			bind = "0.0.0.0"
		}

		name := fmt.Sprintf("ratelimit-test-redis-%d-%d", os.Getpid(), time.Now().UnixNano())
		if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
			"-p", bind+":0:6379", "redis:8-alpine").CombinedOutput(); err != nil {
			disposable.err = fmt.Sprintf("docker run failed: %v: %s", err, strings.TrimSpace(string(out)))
			return
		}
		disposable.name = name
		out, err := exec.Command("docker", "port", name, "6379/tcp").Output()
		if err != nil {
			disposable.err = fmt.Sprintf("docker port failed: %v", err)
			return
		}

		published := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		if host == "" {
			disposable.addr = published
			return
		}
		// docker port reports the bind address the daemon used, which is
		// 0.0.0.0 here; only the port number is ours to keep.
		_, port, err := net.SplitHostPort(published)
		if err != nil {
			disposable.err = fmt.Sprintf("docker port returned %q: %v", published, err)
			return
		}
		disposable.addr = net.JoinHostPort(host, port)
	})
	return disposable.addr, disposable.err
}

// daemonHost returns the host the Docker daemon runs on, or "" when it is this
// machine and a published port is therefore reachable as docker port reports it.
func daemonHost() string {
	endpoint := os.Getenv("DOCKER_HOST")
	if endpoint == "" {
		// DOCKER_HOST overrides the context, so the context is only consulted
		// when it is unset.
		if out, err := exec.Command("docker", "context", "inspect",
			"--format", "{{.Endpoints.docker.Host}}").Output(); err == nil {
			endpoint = strings.TrimSpace(string(out))
		}
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	switch parsed.Scheme {
	case "tcp", "ssh", "http", "https":
		return parsed.Hostname()
	default:
		// A unix socket, a named pipe, or something unrecognized: treat the
		// daemon as local rather than guessing at an address.
		return ""
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if disposable.name != "" {
		_ = exec.Command("docker", "stop", disposable.name).Run()
	}
	os.Exit(code)
}

// TestContract is the acceptance bar: the same conformance suite the
// in-memory store passes, now against a live Redis.
func TestContract(t *testing.T) {
	c := client(t)
	storetest.Run(t, func(t *testing.T) store.Store {
		return redisstore.New(c)
	})
}

// TestDifferentialAgainstMemory drives both stores through one scenario and
// compares verdicts field for field: the Lua script and the in-memory
// reference must be the same math.
func TestDifferentialAgainstMemory(t *testing.T) {
	r := redisstore.New(client(t))
	m := memory.New()
	waitOutHourBoundary()

	uniq := fmt.Sprintf("diff:{%d}", time.Now().UnixNano())
	buckets := []store.Bucket{
		{Key: uniq + ":g", Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 10, Period: time.Hour, Burst: 5}},
		{Key: uniq + ":f", Algorithm: algo.FixedWindowID,
			Window: algo.Window{Requests: 3, Period: time.Hour}},
		{Key: uniq + ":s", Algorithm: algo.GCRAID, Shadow: true,
			Window: algo.Window{Requests: 2, Period: time.Hour, Burst: 2}},
	}

	// Steps 1-3 admit; from step 4 the fixed window refuses and all-or-nothing
	// holds both stores in the refused shape, shadow exhaustion included.
	for step := 1; step <= 6; step++ {
		compareBoth(t, fmt.Sprintf("decide step %d", step), buckets, func(s store.Store) ([]store.Verdict, error) {
			return s.Decide(t.Context(), buckets, 1)
		}, r, m)
	}
	compareBoth(t, "peek after the run", buckets, func(s store.Store) ([]store.Verdict, error) {
		return s.Peek(t.Context(), buckets, 1)
	}, r, m)
	compareBoth(t, "impossible cost", buckets, func(s store.Store) ([]store.Verdict, error) {
		return s.Decide(t.Context(), buckets, 100)
	}, r, m)
}

func compareBoth(t *testing.T, label string, buckets []store.Bucket,
	op func(store.Store) ([]store.Verdict, error), r, m store.Store) {
	t.Helper()
	rv, rerr := op(r)
	mv, merr := op(m)
	if (rerr != nil) != (merr != nil) {
		t.Fatalf("%s: redis err = %v, memory err = %v", label, rerr, merr)
	}
	if rerr != nil {
		return
	}
	for i := range buckets {
		if rv[i].Allowed != mv[i].Allowed || rv[i].CostExceedsCapacity != mv[i].CostExceedsCapacity ||
			rv[i].Remaining != mv[i].Remaining {
			t.Errorf("%s, bucket %d: redis %+v, memory %+v", label, i, rv[i], mv[i])
		}
		if diff := rv[i].RetryAfter - mv[i].RetryAfter; diff > tolerance || diff < -tolerance {
			t.Errorf("%s, bucket %d: RetryAfter diverged: redis %s, memory %s", label, i,
				rv[i].RetryAfter, mv[i].RetryAfter)
		}
		if diff := rv[i].ResetAfter - mv[i].ResetAfter; diff > tolerance || diff < -tolerance {
			t.Errorf("%s, bucket %d: ResetAfter diverged: redis %s, memory %s", label, i,
				rv[i].ResetAfter, mv[i].ResetAfter)
		}
	}
}

// TestOracleRedisRate pins the Lua GCRA to the ported original on single
// buckets: the admission pattern must match request for request, and
// remaining within one unit (the oracle rounds, we floor).
func TestOracleRedisRate(t *testing.T) {
	c := client(t)
	r := redisstore.New(c)
	oracle := redis_rate.NewLimiter(c)

	uniq := fmt.Sprintf("oracle:{%d}", time.Now().UnixNano())
	b := store.Bucket{Key: uniq + ":g", Algorithm: algo.GCRAID,
		Window: algo.Window{Requests: 10, Period: time.Hour, Burst: 5}}
	limit := redis_rate.Limit{Rate: 10, Period: time.Hour, Burst: 5}

	for step := 1; step <= 8; step++ {
		ours, err := r.Decide(t.Context(), []store.Bucket{b}, 1)
		if err != nil {
			t.Fatalf("step %d: Decide: %v", step, err)
		}
		theirs, err := oracle.Allow(t.Context(), uniq+":oracle", limit)
		if err != nil {
			t.Fatalf("step %d: oracle: %v", step, err)
		}
		if ours[0].Allowed != (theirs.Allowed > 0) {
			t.Fatalf("step %d: admission diverged: ours %v, oracle %d", step, ours[0].Allowed, theirs.Allowed)
		}
		if ours[0].Allowed {
			diff := ours[0].Remaining - int64(theirs.Remaining)
			if diff > 1 || diff < -1 {
				t.Errorf("step %d: remaining diverged: ours %d, oracle %d", step, ours[0].Remaining, theirs.Remaining)
			}
		}
	}
}

// TestHighFrequencyStateExact pins the serialization of a 100 000 req/s GCRA
// bucket: Lua's tostring formats numbers as %.14g, which would round a
// 16-digit microsecond timestamp by ~100µs and silently forgive debt at this
// rate. The stored state must be an exact integer, and the in-script verdict
// must be exact to the request.
func TestHighFrequencyStateExact(t *testing.T) {
	c := client(t)
	r := redisstore.New(c)

	uniq := fmt.Sprintf("hf:{%d}", time.Now().UnixNano())
	gcra := store.Bucket{Key: uniq + ":g", Algorithm: algo.GCRAID,
		Window: algo.Window{Requests: 100_000, Period: time.Second, Burst: 10_000}}
	fixed := store.Bucket{Key: uniq + ":f", Algorithm: algo.FixedWindowID,
		Window: algo.Window{Requests: 100_000, Period: time.Second}}

	// Charged in-script at one instant: the verdict is exact, no clock races.
	v, err := r.Decide(t.Context(), []store.Bucket{gcra, fixed}, 9000)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !v[0].Allowed || v[0].Remaining != 1000 {
		t.Fatalf("gcra verdict = %+v, want allowed with exactly 1000 remaining", v[0])
	}

	nowUS := time.Now().UnixMicro()
	for _, b := range []store.Bucket{gcra, fixed} {
		raw, err := c.Get(t.Context(), b.Key).Result()
		if err != nil {
			t.Fatalf("GET %s: %v", b.Key, err)
		}
		assertExactTimestampState(t, b.Key, raw, nowUS)
	}

	// The stored debt must be honored on the next decision, not forgiven.
	if v, err = r.Decide(t.Context(), []store.Bucket{gcra}, 1); err != nil || !v[0].Allowed {
		t.Fatalf("follow-up decide = %+v, %v; want allowed", v, err)
	}
}

// assertExactTimestampState fails on tostring precision loss: every state
// segment must be a plain integer, and the leading one must parse to a
// microsecond timestamp near now.
func assertExactTimestampState(t *testing.T, key, raw string, nowUS int64) {
	t.Helper()
	for part := range strings.SplitSeq(raw, ":") {
		if part == "" || strings.ContainsAny(part, "eE.+") {
			t.Fatalf("state of %s = %q is not an exact integer; tostring precision loss", key, raw)
		}
	}
	ts, err := strconv.ParseInt(strings.Split(raw, ":")[0], 10, 64)
	if err != nil || ts < nowUS-2_000_000 || ts > nowUS+2_000_000 {
		t.Fatalf("state of %s = %q does not parse to a timestamp near now (%d)", key, raw, nowUS)
	}
}

// TestStateExpires covers TTL: state must vanish on its own once the window
// drains — the store has no cleanup process to fall back on.
func TestStateExpires(t *testing.T) {
	c := client(t)
	r := redisstore.New(c)

	uniq := fmt.Sprintf("ttl:{%d}", time.Now().UnixNano())
	buckets := []store.Bucket{
		{Key: uniq + ":g", Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 1, Period: time.Second, Burst: 1}},
		{Key: uniq + ":f", Algorithm: algo.FixedWindowID,
			Window: algo.Window{Requests: 1, Period: time.Second}},
	}
	if _, err := r.Decide(t.Context(), buckets, 1); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	for _, b := range buckets {
		ttl, err := c.PTTL(t.Context(), b.Key).Result()
		if err != nil || ttl <= 0 || ttl > 1100*time.Millisecond {
			t.Errorf("PTTL(%s) = %v, %v; want within (0, 1.1s]", b.Key, ttl, err)
		}
	}

	time.Sleep(1200 * time.Millisecond)

	for _, b := range buckets {
		exists, err := c.Exists(t.Context(), b.Key).Result()
		if err != nil || exists != 0 {
			t.Errorf("Exists(%s) = %d, %v after the window drained; want gone", b.Key, exists, err)
		}
	}
}

// waitOutHourBoundary keeps the fixed-window steps of the differential run
// from straddling a calendar boundary, best effort on the local clock.
func waitOutHourBoundary() {
	now := time.Now()
	boundary := now.Truncate(time.Hour).Add(time.Hour)
	if wait := boundary.Sub(now); wait < 10*time.Second {
		time.Sleep(wait + time.Second)
	}
}
