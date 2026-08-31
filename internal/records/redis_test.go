package records_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The shared store is where the atomicity this package promises actually lives:
// the acceptance, the fencing check, and the compare-and-set are Lua, and Lua is
// only exercised by a real server. These tests resolve one the way the engine's
// store tests do — an explicit address, a disposable container, or a skip — so
// the scripts are covered wherever a Redis can be had, and the suite still runs
// on a laptop without one.

func memoryFactory(t *testing.T) (records.Store, store.Store) {
	counters := memory.New()
	return records.NewMemory(counters), counters
}

func redisFactory(t *testing.T) (records.Store, store.Store) {
	client := redisClient(t)
	return records.NewRedis(client), redisstore.New(client)
}

// redisClient resolves the server under test: REDIS_ADDR when set (the CI
// service, a cluster, anything explicit), a disposable container this binary
// starts itself when Docker is available, or a skip. An explicit address that
// stays unreachable is a failure, never a silent skip.
func redisClient(t *testing.T) goredis.UniversalClient {
	t.Helper()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		var reason string
		addr, reason = disposableRedis()
		if addr == "" {
			t.Skipf("REDIS_ADDR is not set and no disposable Redis: %s", reason)
		}
	}

	client := goredis.NewUniversalClient(&goredis.UniversalOptions{Addrs: strings.Split(addr, ",")})
	t.Cleanup(func() { _ = client.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := client.Ping(t.Context()).Err(); err == nil {
			return client
		} else if time.Now().After(deadline) {
			t.Fatalf("Redis at %s is unreachable: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// disposable is the one throwaway container shared by every test in this
// binary; TestMain stops it.
var disposable struct {
	once sync.Once
	name string
	addr string
	err  string
}

func disposableRedis() (addr, reason string) {
	disposable.once.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			disposable.err = "docker is not in PATH"
			return
		}

		// A published port lands on the machine running the daemon, which is not
		// necessarily this one: DOCKER_HOST and docker contexts both point at
		// remote daemons routinely.
		host := daemonHost()
		bind := "127.0.0.1"
		if host != "" {
			bind = "0.0.0.0"
		}

		name := fmt.Sprintf("ratelimit-records-redis-%d-%d", os.Getpid(), time.Now().UnixNano())
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
		published := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
		port := published[strings.LastIndex(published, ":")+1:]
		if host == "" {
			host = "127.0.0.1"
		}
		disposable.addr = host + ":" + port
	})
	return disposable.addr, disposable.err
}

// daemonHost reports the host a published port lands on when the Docker daemon
// is not this machine.
func daemonHost() string {
	raw := os.Getenv("DOCKER_HOST")
	if !strings.HasPrefix(raw, "tcp://") {
		return ""
	}
	authority := strings.TrimPrefix(raw, "tcp://")
	if i := strings.LastIndex(authority, ":"); i >= 0 {
		return authority[:i]
	}
	return authority
}

func TestMain(m *testing.M) {
	code := m.Run()
	if disposable.name != "" {
		_ = exec.Command("docker", "rm", "-f", disposable.name).Run()
	}
	os.Exit(code)
}

// freshKeys names one command's storage, unique per call so tests in one binary
// never collide in a store they share.
func freshKeys(t *testing.T) records.Keys {
	t.Helper()

	unique := fmt.Sprintf("%s-%d", strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()),
		time.Now().UnixNano())
	return records.Keys{
		Record: "rlm:v1:{records-test}:idem:counter-resets:" + unique,
		Lease:  "rlm:v1:{records-test}:sweep:" + unique,
	}
}

// counterKey names one counter of the same domain, so its deletions share the
// record's slot the way the real layout does.
func counterKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("rl:v1:{records-test}:a/b/c:gcra:60:%d:", time.Now().UnixNano())
}
