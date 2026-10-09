package redis_test

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"slices"
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
			requireCluster(t, c, addr)
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

// The conformance suite the in-memory store passes is the acceptance bar,
// here against a live Redis.
func TestConformsToTheStoreContract(t *testing.T) {
	c := client(t)
	storetest.Run(t, func(t *testing.T) store.Store {
		return redisstore.New(c)
	})
}

// Both stores run through one scenario, and their verdicts are compared field
// for field: the Lua script and the in-memory reference must be the same math.
func TestRedisAndMemoryReturnTheSameVerdicts(t *testing.T) {
	r := redisstore.New(client(t))
	m := memory.New()
	waitOutBoundary(time.Hour, 10*time.Second)

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

// compareBoth runs op on both stores and compares the verdicts bucket by
// bucket: Allowed, CostExceedsCapacity, and Remaining exactly, RetryAfter and
// ResetAfter within tolerance. Every call of the scenario is valid, so an
// error from either store fails the comparison.
func compareBoth(t *testing.T, label string, buckets []store.Bucket,
	op func(store.Store) ([]store.Verdict, error), r, m store.Store) {
	t.Helper()
	rv, rerr := op(r)
	mv, merr := op(m)
	if rerr != nil || merr != nil {
		t.Fatalf("%s: redis err = %v, memory err = %v, want neither", label, rerr, merr)
	}
	if len(rv) != len(buckets) || len(mv) != len(buckets) {
		t.Fatalf("%s: redis %d verdicts, memory %d, want %d", label, len(rv), len(mv), len(buckets))
	}
	for i, b := range buckets {
		if rv[i].Allowed != mv[i].Allowed || rv[i].CostExceedsCapacity != mv[i].CostExceedsCapacity ||
			rv[i].Remaining != mv[i].Remaining {
			t.Errorf("%s, bucket %s: redis %+v, memory %+v", label, b.Key, rv[i], mv[i])
		}
		if diff := rv[i].RetryAfter - mv[i].RetryAfter; diff > tolerance || diff < -tolerance {
			t.Errorf("%s, bucket %s: RetryAfter diverged: redis %s, memory %s", label, b.Key,
				rv[i].RetryAfter, mv[i].RetryAfter)
		}
		if diff := rv[i].ResetAfter - mv[i].ResetAfter; diff > tolerance || diff < -tolerance {
			t.Errorf("%s, bucket %s: ResetAfter diverged: redis %s, memory %s", label, b.Key,
				rv[i].ResetAfter, mv[i].ResetAfter)
		}
	}
}

// The Lua GCRA is a port of redis_rate, which serves as the oracle on single
// buckets: the admission pattern matches request for request, and remaining
// within one unit, because the oracle rounds where the script floors.
func TestTheGCRAScriptAdmitsAsRedisRateDoes(t *testing.T) {
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

// A GCRA bucket of 100000 requests a second stores its state as exact
// integers. Lua's tostring formats numbers as %.14g, which rounds a 16-digit
// microsecond timestamp by about 100 microseconds and at this rate forgives
// debt silently. The in-script verdict is exact to the request.
func TestAHighFrequencyBucketStoresItsStateAsExactIntegers(t *testing.T) {
	c := client(t)
	r := redisstore.New(c)

	uniq := fmt.Sprintf("hf:{%d}", time.Now().UnixNano())
	gcra := store.Bucket{Key: uniq + ":g", Algorithm: algo.GCRAID,
		Window: algo.Window{Requests: 100_000, Period: time.Second, Burst: 10_000}}
	fixed := store.Bucket{Key: uniq + ":f", Algorithm: algo.FixedWindowID,
		Window: algo.Window{Requests: 100_000, Period: time.Second}}

	// The fixed-window state expires at the second boundary, and the GET
	// below has to find it: the decision starts clear of the boundary.
	waitOutBoundary(time.Second, 200*time.Millisecond)

	// Charged in-script at one instant: the verdict is exact, no clock races.
	v, err := r.Decide(t.Context(), []store.Bucket{gcra, fixed}, 9000)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !v[0].Allowed || v[0].Remaining != 1000 {
		t.Fatalf("Decide(cost 9000) verdict of %s = %+v, want allowed with exactly 1000 remaining", gcra.Key, v[0])
	}

	nowUS := time.Now().UnixMicro()
	for _, b := range []store.Bucket{gcra, fixed} {
		raw, err := c.Get(t.Context(), b.Key).Result()
		if err != nil {
			t.Fatalf("GET %s: %v", b.Key, err)
		}
		assertExactTimestampState(t, b.Key, raw, nowUS)
	}

	// The next decision reads the stored integer state back. Time passes
	// between the two calls and refills the bucket, so the verdict cannot
	// show whether a rounding forgave part of the debt; the format check
	// above covers that.
	if v, err = r.Decide(t.Context(), []store.Bucket{gcra}, 1); err != nil || !v[0].Allowed {
		t.Fatalf("Decide(cost 1) after the stored state = %+v, %v; want allowed", v, err)
	}
}

// assertExactTimestampState fails on tostring precision loss: every state
// segment is a plain integer, and the leading one parses to a microsecond
// timestamp within two seconds of now.
func assertExactTimestampState(t *testing.T, key, raw string, nowUS int64) {
	t.Helper()
	for part := range strings.SplitSeq(raw, ":") {
		if part == "" || strings.ContainsAny(part, "eE.+") {
			t.Errorf("state of %s = %q, want integer segments; tostring precision loss", key, raw)
			return
		}
	}
	ts, err := strconv.ParseInt(strings.Split(raw, ":")[0], 10, 64)
	if err != nil {
		t.Errorf("state of %s = %q, want a leading timestamp: %v", key, raw, err)
		return
	}
	if ts < nowUS-2_000_000 || ts > nowUS+2_000_000 {
		t.Errorf("state of %s = %q: timestamp %d, want within 2 s of now, %d", key, raw, ts, nowUS)
	}
}

// State vanishes on its own once its window drains: the store has no cleanup
// process to fall back on. Both windows last one second, so the poll allows
// 200 ms more than a window for the keys to go.
func TestStateIsGoneOnceItsWindowDrains(t *testing.T) {
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

	deadline := time.Now().Add(1200 * time.Millisecond)
	for live := liveKeys(t, c, buckets); len(live) > 0; live = liveKeys(t, c, buckets) {
		if time.Now().After(deadline) {
			t.Fatalf("keys %v exist 1.2 s after the decision, want none once both windows drained", live)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// liveKeys returns the keys of the buckets that still exist in c.
func liveKeys(t *testing.T, c goredis.UniversalClient, buckets []store.Bucket) []string {
	t.Helper()
	var live []string
	for _, b := range buckets {
		exists, err := c.Exists(t.Context(), b.Key).Result()
		if err != nil {
			t.Fatalf("Exists(%s): %v", b.Key, err)
		}
		if exists != 0 {
			live = append(live, b.Key)
		}
	}
	return live
}

// waitOutBoundary keeps a test clear of the next boundary of a fixed window
// of the given period, best effort on the local clock: a window's state
// expires at its boundary, so a decision taken within a round trip of it
// leaves nothing to read back, and a run that straddles one counts in two
// windows. margin is how close to the boundary the test may start.
func waitOutBoundary(period, margin time.Duration) {
	now := time.Now()
	boundary := now.Truncate(period).Add(period)
	if wait := boundary.Sub(now); wait < margin {
		time.Sleep(wait + margin/10)
	}
}

// A cursor is opaque to the caller and checked by the store: text that is not
// a cursor, and a cursor naming a node this store does not have, are both
// refused with store.ErrBadCursor rather than resumed anywhere.
func TestScan_rejectsACursorItDidNotMint(t *testing.T) {
	r := redisstore.New(client(t))
	prefix := fmt.Sprintf("cursor:{%d}:", time.Now().UnixNano())

	for _, cursor := range []string{"not-a-cursor", "10.0.0.1:1@5"} {
		_, _, err := r.Scan(t.Context(), prefix, cursor, 10)
		if !errors.Is(err, store.ErrBadCursor) {
			t.Errorf("Scan(%q, %q, 10) = %v, want store.ErrBadCursor", prefix, cursor, err)
		}
	}
}

// Keys without a hash tag spread over the slots, and on a Cluster over the
// masters; a walk of such a prefix has to reach every master, or a key on
// the second one is reported as absent. On a standalone store the same walk
// reads its one node.
func TestScan_anUntaggedPrefixReachesEveryMaster(t *testing.T) {
	r := redisstore.New(client(t))
	prefix := fmt.Sprintf("untagged:%d:", time.Now().UnixNano())

	want := make([]string, 0, 12)
	for i := range 12 {
		b := store.Bucket{Key: fmt.Sprintf("%s%02d", prefix, i), Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 10, Period: time.Hour, Burst: 10}}
		// One bucket per decision: the keys are on different slots on purpose,
		// and a decision spanning two slots is refused with CROSSSLOT.
		if _, err := r.Decide(t.Context(), []store.Bucket{b}, 1); err != nil {
			t.Fatalf("Decide(%q): %v", b.Key, err)
		}
		want = append(want, b.Key)
	}

	var seen []string
	cursor := ""
	for step := 0; ; step++ {
		keys, next, err := r.Scan(t.Context(), prefix, cursor, 4)
		if err != nil {
			t.Fatalf("Scan(%q, %q, 4): %v", prefix, cursor, err)
		}
		seen = append(seen, keys...)
		if next == "" {
			break
		}
		if step > 100000 {
			t.Fatalf("Scan(%q) walk did not end; the last cursor is %q", prefix, next)
		}
		cursor = next
	}
	for _, k := range want {
		if !slices.Contains(seen, k) {
			t.Errorf("Scan(%q) walk = %v, missing %q", prefix, seen, k)
		}
	}
}

// requireCluster fails the test when REDIS_REQUIRE_CLUSTER is set and the
// server at addr runs with cluster support disabled. A cluster run that
// reached a standalone server passes every test it exists to fail.
func requireCluster(t testing.TB, c goredis.UniversalClient, addr string) {
	t.Helper()
	if os.Getenv("REDIS_REQUIRE_CLUSTER") == "" {
		return
	}
	info, err := c.Info(t.Context(), "cluster").Result()
	if err != nil {
		t.Fatalf("read the cluster section of INFO at %s: %v", addr, err)
	}
	if !strings.Contains(info, "cluster_enabled:1") {
		t.Fatalf("REDIS_REQUIRE_CLUSTER is set, but the Redis at %s is not a cluster", addr)
	}
}
