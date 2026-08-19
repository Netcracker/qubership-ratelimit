// Package redis is the shared counter store: one Lua script per decision,
// atomic across every bucket of the request.
//
// The engine never learns the topology: New takes a UniversalClient, which the
// caller builds for standalone, Sentinel, or Cluster — the domain hash tag in
// the keys keeps a decision on one Cluster slot, so the script is valid on any
// of them. Time comes from the store's own clock (the TIME command inside the
// script), and the math is the same integer-microsecond formulation as the
// in-memory reference; a differential test holds the two together.
//
// Connection lifecycle belongs to the caller: the store never closes the
// client, and error policy (fail open or closed) belongs to the adapter above.
package redis

import (
	"context"
	// Blank import activates the go:embed directive below; nothing else of
	// the package is used.
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

//go:embed script.lua
var scriptSource string

// script is registered once; Run uses EVALSHA and falls back to EVAL when the
// store has not seen the script yet (restart, failover).
var script = goredis.NewScript(scriptSource)

// Store implements store.Store and store.Inspector over a shared Redis.
type Store struct {
	rdb goredis.UniversalClient
}

var (
	_ store.Store     = (*Store)(nil)
	_ store.Inspector = (*Store)(nil)
)

// New wraps a ready client. The caller owns the client's lifecycle and
// timeouts; the per-decision budget arrives as the context deadline.
func New(rdb goredis.UniversalClient) *Store {
	return &Store{rdb: rdb}
}

// Decide judges every bucket and commits atomically inside one script.
func (s *Store) Decide(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	return s.run(ctx, "decide", buckets, cost)
}

// Peek runs the same script with the commit pass switched off.
func (s *Store) Peek(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	return s.run(ctx, "peek", buckets, cost)
}

func (s *Store) run(ctx context.Context, mode string, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	if err := store.GuardBuckets(buckets, cost); err != nil {
		return nil, err
	}
	if len(buckets) == 0 {
		return nil, nil
	}

	keys := make([]string, len(buckets))
	argv := make([]any, 0, 2+len(buckets)*5)
	argv = append(argv, mode, cost)
	for i, b := range buckets {
		keys[i] = b.Key
		switch b.Algorithm {
		case algo.GCRAID:
			argv = append(argv, int64(algo.GCRAID),
				algo.EmissionMicros(b.Window), algo.TauMicros(b.Window), b.Window.Burst, boolArg(b.Shadow))
		case algo.FixedWindowID:
			argv = append(argv, int64(algo.FixedWindowID),
				algo.PeriodMicros(b.Window), b.Window.Requests, int64(0), boolArg(b.Shadow))
		default:
			return nil, fmt.Errorf("redis: unknown algorithm id %d", b.Algorithm)
		}
	}

	res, err := script.Run(ctx, s.rdb, keys, argv...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: decision script: %w", err)
	}
	return parseReply(res, len(buckets))
}

// Reset deletes counter state. Keys are deleted one per command inside a
// pipeline: a multi-key DEL would trip CROSSSLOT on a cluster the moment the
// keys span domains, while single-key commands route freely. Absent keys are
// a successful no-op by Redis semantics.
func (s *Store) Reset(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	pipe := s.rdb.Pipeline()
	for _, k := range keys {
		pipe.Del(ctx, k)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: reset: %w", err)
	}
	return nil
}

// Keys lists live keys under a prefix with SCAN — on a cluster, per master
// node. Expensive by design; callers are management endpoints.
func (s *Store) Keys(ctx context.Context, prefix string) ([]string, error) {
	match := escapeGlob(prefix) + "*"
	var (
		mu  sync.Mutex
		out []string
	)
	scan := func(ctx context.Context, c goredis.Cmdable) error {
		iter := c.Scan(ctx, 0, match, 512).Iterator()
		for iter.Next(ctx) {
			mu.Lock()
			out = append(out, iter.Val())
			mu.Unlock()
		}
		return iter.Err()
	}

	var err error
	if cc, ok := s.rdb.(*goredis.ClusterClient); ok {
		err = cc.ForEachMaster(ctx, func(ctx context.Context, node *goredis.Client) error {
			return scan(ctx, node)
		})
	} else {
		err = scan(ctx, s.rdb)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: keys: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// parseReply turns the script's flat integer array into verdicts, in bucket
// order. A malformed reply is a broken script deployment, not data.
func parseReply(res any, n int) ([]store.Verdict, error) {
	arr, ok := res.([]any)
	if !ok || len(arr) != 1+n*5 {
		return nil, fmt.Errorf("redis: decision script returned a malformed reply (%d values, want %d)",
			replyLen(res), 1+n*5)
	}
	verdicts := make([]store.Verdict, n)
	for i := range n {
		base := 1 + i*5
		vals := make([]int64, 5)
		for j := range vals {
			v, ok := arr[base+j].(int64)
			if !ok {
				return nil, fmt.Errorf("redis: decision script returned a non-integer at position %d", base+j)
			}
			vals[j] = v
		}
		verdicts[i] = store.Verdict{
			Allowed:             vals[0] == 1,
			CostExceedsCapacity: vals[1] == 1,
			Remaining:           vals[2],
			RetryAfter:          microsDuration(vals[3]),
			ResetAfter:          microsDuration(vals[4]),
		}
	}
	return verdicts, nil
}

func replyLen(res any) int {
	if arr, ok := res.([]any); ok {
		return len(arr)
	}
	return -1
}

// microsDuration mirrors the in-memory store: negative microseconds mean "no
// retry hint" and normalize to the same -1 the reference produces, so the
// differential test compares verdicts field for field.
func microsDuration(us int64) time.Duration {
	if us < 0 {
		return -1
	}
	return time.Duration(us) * time.Microsecond
}

// boolArg encodes a flag the way the script reads it.
func boolArg(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// escapeGlob escapes SCAN's glob metacharacters, so a prefix that carries a
// bracket in an axis value matches literally.
func escapeGlob(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`)
	return r.Replace(s)
}
