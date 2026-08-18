// Package memory is the in-memory Store: the reference client of the storetest
// suite and the temporary counting backend until the shared store lands.
//
// It exists for tests and for the first milestone only — counters live per
// process, so N replicas enforce N times the configured limit. The math is
// written the way the server-side scripts will be: integer microseconds of
// Unix time, exact in Go's int64 and exact in Lua's doubles until the year
// 2255, so there are no float boundaries and no epsilon guards. Fixed windows
// align to Unix epoch boundaries; verdicts are assembled from the same
// quantities the script will return.
//
// Expiry is lazy: state is dropped when touched past its deadline, and swept
// during Keys. An entry nobody touches again lingers until then — acceptable
// for a fixture, wrong for production.
package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// Store implements store.Store and store.Inspector over one process-local map.
type Store struct {
	mu  sync.Mutex
	m   map[string]entry
	now func() time.Time
}

var (
	_ store.Store     = (*Store)(nil)
	_ store.Inspector = (*Store)(nil)
)

// New returns an empty store using the process clock — which for an in-process
// store is the store's own clock, as the contract demands.
func New() *Store {
	return &Store{m: map[string]entry{}, now: time.Now}
}

// entry is one bucket's state, all timestamps in Unix microseconds. GCRA
// stores a timestamp, fixed window a start and a count — deliberately nothing
// derived from requests or burst, so a tuned limit reinterprets the same
// state.
type entry struct {
	algorithm algo.ID
	tat       int64 // GCRA: theoretical arrival time
	start     int64 // FixedWindow: window start
	count     int64 // FixedWindow: consumed in the window
	deadline  int64 // past it the entry counts as absent
}

// outcome carries one bucket's evaluation in both variants: as if the request
// were charged, and as the state stands. Which one becomes the Verdict depends
// on whether the decision commits this bucket.
type outcome struct {
	allowed       bool
	costExceeds   bool
	retryAfter    time.Duration
	remainCharged int64
	remainCurrent int64
	resetCharged  time.Duration
	resetCurrent  time.Duration
	next          entry
}

// Decide implements the two-pass contract: evaluate everything, then commit
// only when no enforcing bucket refused; a shadow bucket commits only when its
// own verdict allowed.
func (s *Store) Decide(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	if err := store.GuardBuckets(buckets, cost); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	outs, err := s.evalAll(buckets, cost)
	if err != nil {
		return nil, err
	}

	admitted := true
	for i, b := range buckets {
		if !b.Shadow && !outs[i].allowed {
			admitted = false
		}
	}

	verdicts := make([]store.Verdict, len(buckets))
	for i, b := range buckets {
		if admitted && outs[i].allowed {
			s.m[b.Key] = outs[i].next
			verdicts[i] = chargedVerdict(outs[i])
			continue
		}
		verdicts[i] = currentVerdict(outs[i])
	}
	return verdicts, nil
}

// Peek runs the same evaluation as Decide at the given cost with the commit
// pass switched off.
func (s *Store) Peek(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	if err := store.GuardBuckets(buckets, cost); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	outs, err := s.evalAll(buckets, cost)
	if err != nil {
		return nil, err
	}
	verdicts := make([]store.Verdict, len(buckets))
	for i := range outs {
		verdicts[i] = currentVerdict(outs[i])
	}
	return verdicts, nil
}

// Reset drops state. Keys that are absent — already reset, or expired — are a
// successful no-op.
func (s *Store) Reset(ctx context.Context, keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.m, k)
	}
	return nil
}

// Keys lists live keys under a prefix and sweeps expired entries on the way.
func (s *Store) Keys(ctx context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUS := s.now().UnixMicro()
	var out []string
	for k, e := range s.m {
		if e.deadline <= nowUS {
			delete(s.m, k)
			continue
		}
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) evalAll(buckets []store.Bucket, cost int64) ([]outcome, error) {
	nowUS := s.now().UnixMicro()

	outs := make([]outcome, len(buckets))
	for i, b := range buckets {

		e, ok := s.m[b.Key]
		if ok && (e.deadline <= nowUS || e.algorithm != b.Algorithm) {
			delete(s.m, b.Key)
			ok = false
		}
		switch b.Algorithm {
		case algo.GCRAID:
			outs[i] = evalGCRA(e, ok, nowUS, b.Window, cost)
		case algo.FixedWindowID:
			outs[i] = evalFixed(e, ok, nowUS, b.Window, cost)
		default:
			return nil, fmt.Errorf("memory: unknown algorithm id %d", b.Algorithm)
		}
	}
	return outs, nil
}

// evalGCRA is the theoretical-arrival-time computation over integer
// microseconds, the same formulation the server-side script uses. The
// emission interval is at least one microsecond and the bucket depth is
// bounded — both enforced by validation — so nothing here overflows and no
// comparison needs a guard.
func evalGCRA(e entry, exists bool, nowUS int64, w algo.Window, cost int64) outcome {
	emission := algo.EmissionMicros(w)
	tau := algo.TauMicros(w)

	tat := nowUS
	if exists && e.tat > nowUS {
		tat = e.tat
	}
	depth := tat - nowUS
	current := nonNegative((tau - depth) / emission)

	if cost > w.Burst {
		return outcome{
			costExceeds:   true,
			retryAfter:    -1,
			remainCurrent: current,
			resetCurrent:  microsDuration(depth),
		}
	}

	increment := emission * cost
	newTat := tat + increment
	diff := nowUS - (newTat - tau)

	o := outcome{
		allowed:       diff >= 0,
		retryAfter:    -1,
		remainCharged: nonNegative(diff / emission),
		remainCurrent: current,
		resetCharged:  microsDuration(newTat - nowUS),
		resetCurrent:  microsDuration(depth),
		next:          entry{algorithm: algo.GCRAID, tat: newTat, deadline: newTat},
	}
	if !o.allowed {
		o.retryAfter = microsDuration(-diff)
	}
	return o
}

// evalFixed counts against the epoch-aligned window that contains now, with
// microsecond-precise boundaries.
func evalFixed(e entry, exists bool, nowUS int64, w algo.Window, cost int64) outcome {
	periodUS := algo.PeriodMicros(w)
	start := nowUS - nowUS%periodUS

	var count int64
	if exists && e.start == start {
		count = e.count
	}
	left := max(w.Requests-count, 0)
	boundary := microsDuration(start + periodUS - nowUS)

	o := outcome{
		allowed:       cost <= left,
		costExceeds:   cost > w.Requests,
		retryAfter:    -1,
		remainCharged: left - cost,
		remainCurrent: left,
		resetCharged:  boundary,
		resetCurrent:  boundary,
		next: entry{
			algorithm: algo.FixedWindowID,
			start:     start,
			count:     count + cost,
			deadline:  start + periodUS,
		},
	}
	if count == 0 {
		o.resetCurrent = 0
	}
	if !o.allowed && !o.costExceeds {
		o.retryAfter = boundary
	}
	return o
}

func chargedVerdict(o outcome) store.Verdict {
	return store.Verdict{
		Allowed:    true,
		Remaining:  o.remainCharged,
		RetryAfter: -1,
		ResetAfter: o.resetCharged,
	}
}

func currentVerdict(o outcome) store.Verdict {
	return store.Verdict{
		Allowed:             o.allowed,
		Remaining:           o.remainCurrent,
		CostExceedsCapacity: o.costExceeds,
		RetryAfter:          o.retryAfter,
		ResetAfter:          o.resetCurrent,
	}
}

func microsDuration(us int64) time.Duration {
	return time.Duration(us) * time.Microsecond
}

func nonNegative(x int64) int64 {
	if x < 0 {
		return 0
	}
	return x
}
