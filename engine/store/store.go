// Package store holds the counter contract: the only path from the engine to
// counter state.
//
// A decision covers several buckets at once — a rule may carry a minute window
// and a daily quota, and a request may match several rules. The contract is
// therefore atomic across the whole set: a refused request leaves no trace,
// an admitted one charges every enforcing bucket, and a shadow bucket is
// charged per its own verdict. Charging the buckets one by one would let a
// client burn a daily quota with requests a minute limit already rejected.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
)

// Bucket is one counter taking part in a decision.
type Bucket struct {
	// Key identifies the counter. It carries the schema version, domain, the
	// block/rule identity, the algorithm, the window period, and the axis
	// values: renaming a rule, switching its algorithm, or changing its period
	// starts a fresh bucket. Requests and burst are deliberately not part of
	// the key, so tuning a limit reinterprets live state instead of resetting
	// it — and what survives is per-algorithm: a fixed window keeps the
	// consumed count (a mid-window quota bump keeps what was spent), while
	// GCRA keeps drain depth in time, so consumed requests rescale with the
	// rate. Quota semantics is what FixedWindow is for.
	Key string

	Algorithm algo.ID

	// Window arrives resolved and checked: compile applies the defaults,
	// burst included, and runs algo.Check. Implementations run cheap guards
	// at most — an unvalidated window is undefined behavior.
	Window algo.Window

	// Shadow marks a bucket that counts but cannot reject: its verdict is
	// reported for metrics and ignored when deciding whether to admit. When
	// the request is admitted, a shadow bucket is charged exactly when its own
	// verdict allows — mirroring what enforcement would have done. Charging it
	// on its own refusals would grow unbounded debt and make the would-be
	// metrics report permanent rejection long after traffic drops back under
	// the limit.
	Shadow bool
}

// Verdict is the outcome for one bucket.
type Verdict struct {
	Allowed bool

	// Remaining is how many more requests the bucket would admit right now —
	// instantaneous capacity, which recovers over time under GCRA. It is
	// never negative, even when an implementation has counted past the limit.
	Remaining int64

	// CostExceedsCapacity marks a refusal no waiting can cure: the request
	// cost is larger than the bucket can ever hold. No retry hint applies,
	// and none must reach the response headers.
	CostExceedsCapacity bool

	// RetryAfter is how long until this bucket would admit the request.
	// Negative when the bucket is not limiting; meaningless when
	// CostExceedsCapacity is set.
	RetryAfter time.Duration

	// ResetAfter is how long until the bucket returns to its empty state.
	ResetAfter time.Duration
}

// Store counts requests against buckets.
//
// Implementations take the current time from the store itself, never from the
// caller: engine replicas disagree about the clock, and a bucket shared between
// them must not. Counter state expires on its own — implementations bound its
// lifetime by the window, and no external cleanup process exists. The storetest
// suite cannot verify expiry without waiting out a window, so this line is the
// contract.
type Store interface {
	// Decide judges every bucket and commits atomically: a refused request
	// leaves no trace, an admitted one charges every enforcing bucket, and a
	// shadow bucket is charged per its own verdict (see Shadow). The request
	// is admitted when no enforcing bucket refuses it. Verdicts come back in
	// the order the buckets were given. Cost below 1 is an error — a negative
	// cost would refund counter state — and must charge nothing. Callers never
	// pass an empty bucket list: a request that matched nothing is admitted
	// without a store round trip. Bucket keys within one decision are unique —
	// a duplicate is a caller bug and an error, because evaluating one key
	// twice in a single commit would lose a charge. The key layout pins a
	// domain's buckets to one Redis Cluster slot (see the key package), so a
	// decision commits as one atomic script on every supported topology.
	Decide(ctx context.Context, buckets []Bucket, cost int64) ([]Verdict, error)

	// Peek judges at the given cost without charging, so that introspection
	// reports the same numbers the enforcing path would produce. Cost and
	// duplicate-key rules match Decide.
	Peek(ctx context.Context, buckets []Bucket, cost int64) ([]Verdict, error)

	// Reset drops counter state, which is how an operator lifts a limit from a
	// client without waiting out the window. Keys that do not exist — already
	// reset, or expired — are a successful no-op: management operations retry.
	Reset(ctx context.Context, keys []string) error
}

// ErrBadCursor reports a cursor that Scan did not mint for this prefix on
// this store: malformed, or naming a node the store no longer has. The
// caller restarts its walk from an empty cursor.
var ErrBadCursor = errors.New("store: the cursor is not a continuation of this scan")

// Inspector is the management-side view of counter state, separate from Store
// so the decision path never carries enumeration it does not need. A store
// implementation is free to provide both.
type Inspector interface {
	// Scan lists the live keys under prefix one step at a time, so that a
	// caller holds one step of keys at once however many the prefix covers.
	//
	// A walk starts with an empty cursor; each step returns the cursor of the
	// next one, and an empty next ends the walk. A cursor is opaque and valid
	// for the same prefix on the same store; one the store cannot resume, a
	// malformed one or one minted for a node the store no longer has, is
	// refused with [ErrBadCursor].
	//
	// limit is the work one step asks for; a limit below 1 is refused with an
	// error. A step
	// returns about that many keys, sorted; a store that reads whole hash
	// table slots (Redis SCAN) may return somewhat more, so a caller sizes
	// its memory by limit plus that margin. A step may also return no keys
	// before the walk ends, where the prefix's keys are sparse in a keyspace
	// the store shares with other data.
	//
	// The walk is live rather than a snapshot: a key that exists for the
	// whole walk is returned at least once, and a key created, expired, or
	// deleted during it may be missed or returned twice. Expensive by
	// design: callers are management endpoints, never the decision path.
	Scan(ctx context.Context, prefix, cursor string, limit int) (keys []string, next string, err error)
}

// GuardBuckets applies the cheap edge of the caller contract, shared by every
// implementation: cost is positive, keys are unique within the decision, and
// windows carry the fields whose absence would divide by zero downstream.
// Full window semantics stay algo.Check's job at compile time.
func GuardBuckets(buckets []Bucket, cost int64) error {
	if cost < 1 {
		return fmt.Errorf("store: cost must be at least 1, got %d", cost)
	}
	seen := make(map[string]struct{}, len(buckets))
	for _, b := range buckets {
		if _, dup := seen[b.Key]; dup {
			return fmt.Errorf("store: duplicate bucket key %q in one decision", b.Key)
		}
		seen[b.Key] = struct{}{}
		if b.Window.Requests < 1 || b.Window.Period < time.Microsecond {
			return fmt.Errorf("store: bucket %q carries a window that did not pass validation", b.Key)
		}
	}
	return nil
}

// Admitted reports whether verdicts add up to letting the request through. A
// length mismatch is a broken Store implementation, not data, and the one
// function deciding admission must not paper over it.
func Admitted(buckets []Bucket, verdicts []Verdict) bool {
	if len(buckets) != len(verdicts) {
		panic(fmt.Sprintf("store: %d buckets but %d verdicts", len(buckets), len(verdicts)))
	}
	for i, v := range verdicts {
		if buckets[i].Shadow {
			continue
		}
		if !v.Allowed {
			return false
		}
	}
	return true
}
