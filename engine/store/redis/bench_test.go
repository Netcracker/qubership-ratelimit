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
