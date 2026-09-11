package redis_test

// Benchmarks of the Redis store. The serial run measures decision latency
// (one round trip); the parallel runs measure how many decisions one Redis
// instance sustains through the connection pool. The bucket-count sweep pins
// the script's per-bucket slope, which is what sizes the decision budget.

import (
	"fmt"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
)

// benchBuckets builds n buckets in one slot, alternating the two algorithms,
// with limits high enough that every decision commits — the worst case, one
// GET and one SET per bucket.
func benchBuckets(tag string, n int) []store.Bucket {
	out := make([]store.Bucket, n)
	for i := range out {
		b := store.Bucket{Key: fmt.Sprintf("bench:{%s}:%d:", tag, i), Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 1_000_000, Period: time.Minute, Burst: 1_000_000}}
		if i%2 == 1 {
			b.Algorithm = algo.FixedWindowID
			b.Window = algo.Window{Requests: 100_000_000, Period: time.Hour}
		}
		out[i] = b
	}
	return out
}

func BenchmarkRedisDecide(b *testing.B) {
	s := redisstore.New(client(b))
	buckets := benchBuckets(fmt.Sprintf("serial-%d", time.Now().UnixNano()), 3)
	for b.Loop() {
		if _, err := s.Decide(b.Context(), buckets, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedisDecideParallel(b *testing.B) {
	s := redisstore.New(client(b))
	tag := fmt.Sprintf("parallel-%d", time.Now().UnixNano())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buckets := benchBuckets(tag, 3)
		for pb.Next() {
			if _, err := s.Decide(b.Context(), buckets, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRedisDecideBuckets(b *testing.B) {
	s := redisstore.New(client(b))
	for _, n := range []int{1, 4, 8, 16, 64} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			tag := fmt.Sprintf("sweep-%d-%d", n, time.Now().UnixNano())
			b.RunParallel(func(pb *testing.PB) {
				buckets := benchBuckets(tag, n)
				for pb.Next() {
					if _, err := s.Decide(b.Context(), buckets, 1); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// scanDomainKeys is the size of the domain the scan benchmarks walk, the
// "few hundred thousand keys" the management API describes as a busy domain.
const scanDomainKeys = 300_000

// seedScanKeys writes n keys under prefix through pipelines, with a TTL so a
// shared server forgets them on its own. The values are irrelevant to a walk.
func seedScanKeys(b *testing.B, prefix string, n int) {
	b.Helper()
	c := client(b)
	const chunk = 5000
	for start := 0; start < n; start += chunk {
		pipe := c.Pipeline()
		for i := start; i < start+chunk && i < n; i++ {
			pipe.Set(b.Context(), fmt.Sprintf("%sorders/per-client:gcra:3600:client-%06d:", prefix, i), "1", 10*time.Minute)
		}
		if _, err := pipe.Exec(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedisScanStep measures one step of 512 keys over a domain of
// scanDomainKeys keys, the unit of work a listing page repeats at most
// sixty-four times.
func BenchmarkRedisScanStep(b *testing.B) {
	s := redisstore.New(client(b))
	prefix := fmt.Sprintf("bench:{scan-%d}:", time.Now().UnixNano())
	seedScanKeys(b, prefix, scanDomainKeys)

	cursor := ""
	for b.Loop() {
		_, next, err := s.Scan(b.Context(), prefix, cursor, 512)
		if err != nil {
			b.Fatal(err)
		}
		cursor = next
	}
}

// BenchmarkRedisScanWalk measures a whole walk of the same domain, which is
// what a bulk sweep of it costs in store reads.
func BenchmarkRedisScanWalk(b *testing.B) {
	s := redisstore.New(client(b))
	prefix := fmt.Sprintf("bench:{walk-%d}:", time.Now().UnixNano())
	seedScanKeys(b, prefix, scanDomainKeys)

	for b.Loop() {
		cursor := ""
		steps, keys := 0, 0
		for {
			found, next, err := s.Scan(b.Context(), prefix, cursor, 512)
			if err != nil {
				b.Fatal(err)
			}
			steps++
			keys += len(found)
			if next == "" {
				break
			}
			cursor = next
		}
		b.ReportMetric(float64(steps), "steps/op")
		b.ReportMetric(float64(keys), "keys/op")
	}
}
