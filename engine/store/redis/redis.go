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
	"strconv"
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

// Scan implements [store.Inspector] with one SCAN per step. On a Cluster the
// walk reads the one master that owns the prefix's hash tag, where every key
// of a domain lives, and every master in address order when the prefix has
// no tag. The cursor names the node it belongs to, so a cursor minted before
// a slot moved or a master left is refused with [store.ErrBadCursor] rather
// than resumed on the wrong node.
func (s *Store) Scan(ctx context.Context, prefix, cursor string, limit int) ([]string, string, error) {
	if limit < 1 {
		return nil, "", fmt.Errorf("redis: scan: limit must be at least 1, got %d", limit)
	}
	nodes, err := s.scanNodes(ctx, prefix)
	if err != nil {
		return nil, "", fmt.Errorf("redis: scan: %w", err)
	}
	node, pos, err := parseScanCursor(cursor, nodes)
	if err != nil {
		return nil, "", err
	}

	match := escapeGlob(prefix) + "*"
	for {
		keys, next, err := nodes[node].client.Scan(ctx, pos, match, int64(limit)).Result()
		if err != nil {
			return nil, "", fmt.Errorf("redis: scan: %w", err)
		}
		sort.Strings(keys)
		switch {
		case next != 0:
			return keys, formatScanCursor(nodes[node].addr, next), nil
		case node+1 < len(nodes):
			// This master is exhausted. When its last SCAN returned keys,
			// they are the step and the cursor names the next master's start;
			// when it returned none, the step goes on with the next master.
			node, pos = node+1, 0
			if len(keys) > 0 {
				return keys, formatScanCursor(nodes[node].addr, 0), nil
			}
		default:
			return keys, "", nil
		}
	}
}

// scanNode is one master a walk reads. addr is empty on a standalone or
// Sentinel deployment, where there is one node and nothing to name.
type scanNode struct {
	addr   string
	client goredis.Cmdable
}

// scanNodes resolves the masters a walk of prefix reads, in the order the
// cursor counts them.
func (s *Store) scanNodes(ctx context.Context, prefix string) ([]scanNode, error) {
	cc, ok := s.rdb.(*goredis.ClusterClient)
	if !ok {
		return []scanNode{{client: s.rdb}}, nil
	}
	if hasHashTag(prefix) {
		owner, err := cc.MasterForKey(ctx, prefix)
		if err != nil {
			return nil, err
		}
		return []scanNode{{addr: owner.Options().Addr, client: owner}}, nil
	}

	var (
		mu    sync.Mutex
		nodes []scanNode
	)
	err := cc.ForEachMaster(ctx, func(_ context.Context, master *goredis.Client) error {
		mu.Lock()
		defer mu.Unlock()
		nodes = append(nodes, scanNode{addr: master.Options().Addr, client: master})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].addr < nodes[j].addr })
	return nodes, nil
}

// hasHashTag reports whether Redis Cluster hashes s by a tag: a non-empty
// stretch between the first "{" and the first "}" after it. A prefix with a
// tag names one slot, and every key under the prefix lives on that slot's
// master, because the key's first tag is the prefix's.
func hasHashTag(s string) bool {
	_, rest, opened := strings.Cut(s, "{")
	if !opened {
		return false
	}
	tag, _, closed := strings.Cut(rest, "}")
	return closed && tag != ""
}

// formatScanCursor carries a SCAN cursor together with the address of the
// node it belongs to; a node without an address carries the cursor alone.
func formatScanCursor(addr string, pos uint64) string {
	if addr == "" {
		return strconv.FormatUint(pos, 10)
	}
	return addr + "@" + strconv.FormatUint(pos, 10)
}

// parseScanCursor reads a cursor back into the index of its node among nodes
// and its SCAN position. An empty cursor starts the walk on the first node.
func parseScanCursor(cursor string, nodes []scanNode) (node int, pos uint64, err error) {
	if cursor == "" {
		return 0, 0, nil
	}
	addr, digits := "", cursor
	if i := strings.LastIndexByte(cursor, '@'); i >= 0 {
		addr, digits = cursor[:i], cursor[i+1:]
	}
	pos, err = strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("redis: scan: %w", store.ErrBadCursor)
	}
	for i, n := range nodes {
		if n.addr == addr {
			return i, pos, nil
		}
	}
	return 0, 0, fmt.Errorf("redis: scan: %w", store.ErrBadCursor)
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
