package management

import (
	"context"
	"errors"
	"maps"
	"sort"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The sweep is the cross-rule walk a bulk command runs on.
//
// It runs to completion inside the call. Each batch is one atomic step in the
// store: verify the fencing token, delete, advance the recorded progress. There
// is no gap between the check and the deletions for an expired lease to fall
// into, and a walker that lost the domain deletes nothing further. Because the
// progress commits together with the deletions it counts, a command that dies
// mid-walk can still say exactly what it did, up to the last batch that ran.

// sweepBatch is how many keys are judged and deleted per store round trip.
// Larger batches cost fewer round trips; smaller ones keep the recorded
// progress closer to the truth when a walk is cut short.
const sweepBatch = 256

// errDeadline reports a walk that ran out of its deadline. It is separate from
// a defect because its recovery is: narrow the selection.
var errDeadline = errors.New("management: the sweep reached its deadline")

// sweeper walks a domain's counter keys for one bulk command.
type sweeper struct {
	api      *API
	snapshot *compile.Snapshot
	index    rateIndex

	// keys names the record, the lease, and the token; fencing is what proves
	// this walker still owns the domain.
	keys    records.Keys
	fencing string

	// sel is the selection; domainWide replaces it with "everything in this
	// domain", which is the one selection that needs no filter at all.
	sel        selector
	domainWide bool

	// execute is false for a preview, which matches and counts and deletes
	// nothing.
	execute bool

	progress records.Progress
	rules    map[string]int
}

// newSweeper prepares a walk over the selection.
func (a *API) newSweeper(
	snapshot *compile.Snapshot,
	command bulkCommand,
	keys records.Keys,
	fencing string,
) *sweeper {
	return &sweeper{
		api:        a,
		snapshot:   snapshot,
		index:      newRateIndex(snapshot),
		keys:       keys,
		fencing:    fencing,
		sel:        command.Selector,
		domainWide: command.DomainWide,
		execute:    !command.DryRun,
		rules:      map[string]int{},
	}
}

// run walks the whole selection, committing as it goes.
//
// The deadline is the server's own bound on synchronous work: a client's
// patience does not decide when a destructive command stops, and a command that
// outlives its caller's connection still runs to a recorded outcome.
func (s *sweeper) run(ctx context.Context, deadline time.Time) error {
	inspector, ok := s.api.Counters.(counters.Inspector)
	if !ok {
		return errors.New("the configured counter store cannot enumerate keys")
	}

	prefix := key.DomainPrefix(s.snapshot.Domain)
	if !s.domainWide {
		prefix = scanPrefix(s.snapshot.Domain, s.sel)
	}
	keys, err := inspector.Keys(ctx, prefix)
	if err != nil {
		return err
	}
	sort.Strings(keys)

	batch := make([]counterCandidate, 0, sweepBatch)
	for _, k := range keys {
		if s.api.now().After(deadline) {
			return errDeadline
		}

		s.progress.Scanned++
		candidate, ok := s.consider(ctx, k)
		if !ok {
			continue
		}

		batch = append(batch, candidate)
		if len(batch) < sweepBatch {
			continue
		}
		if err := s.commitBatch(ctx, batch); err != nil {
			return err
		}
		batch = batch[:0]
	}
	return s.commitBatch(ctx, batch)
}

// consider applies the filters that need nothing but the key and the snapshot.
//
// The split matters: rule ids, algorithm, and period parse the key itself, so
// they reach counters of rules a rollout has removed while their state lives out
// its TTL, which is what keeps those sweepable. Axes and the limited filter need
// the rule's definition, so they only ever match counters of rules currently
// enforced.
func (s *sweeper) consider(ctx context.Context, k string) (counterCandidate, bool) {
	parsed, err := parseCounterKey(s.snapshot.Domain, k)
	if err != nil {
		s.api.Log.DebugC(ctx, "skipping an unparsable counter key domain=%v reason=%v",
			s.snapshot.Domain, err)
		return counterCandidate{}, false
	}
	if !s.domainWide && !s.sel.matches(parsed) {
		return counterCandidate{}, false
	}

	ref, enforced := s.index[parsed.RatePrefix]
	if !enforced {
		if len(s.sel.Axes) > 0 || s.sel.LimitedOnly {
			// Those filters need the rule's definition, the axis-name mapping
			// and the window budgets, which a removed rule no longer offers.
			return counterCandidate{}, false
		}
		// An orphan otherwise: no rule left to render it against, but its key is
		// enough to sweep it and its own id is enough to count it.
		return counterCandidate{key: k, ruleID: parsed.RuleID}, true
	}

	axes, err := parsed.namedAxes(ref.rule.Counters)
	if err != nil {
		s.api.Log.DebugC(ctx, "skipping a counter whose axes do not fit its rule domain=%v reason=%v",
			s.snapshot.Domain, err)
		return counterCandidate{}, false
	}
	if !s.domainWide && !s.sel.matchesAxes(axes) {
		return counterCandidate{}, false
	}
	return counterCandidate{key: k, ref: ref, axes: axes, ruleID: parsed.RuleID}, true
}

// commitBatch judges the batch, then deletes and records it in one step.
func (s *sweeper) commitBatch(ctx context.Context, batch []counterCandidate) error {
	if len(batch) == 0 {
		return nil
	}

	kept := batch
	if s.sel.LimitedOnly {
		var err error
		if kept, err = s.refusing(ctx, batch); err != nil {
			return err
		}
	}

	drop := make([]string, 0, len(kept))
	for _, candidate := range kept {
		s.count(candidate.key, candidate.ruleID)
		if s.execute {
			drop = append(drop, candidate.key)
		}
	}
	if len(kept) == 0 {
		return nil
	}

	// One step: the fencing token is checked, the batch is deleted, and the
	// progress those deletions produced is recorded, with no gap between them.
	return s.api.Records.Batch(ctx, records.Batch{
		Keys:     s.keys,
		Fencing:  s.fencing,
		Delete:   drop,
		Progress: s.snapshotProgress(),
	})
}

// refusing keeps the counters that would refuse the next cost-1 request. Only a
// selection that named the limited filter reaches here, and such a selection
// never carries counters of removed rules, so every candidate has its rule.
func (s *sweeper) refusing(ctx context.Context, batch []counterCandidate) ([]counterCandidate, error) {
	buckets := make([]counters.Bucket, 0, len(batch))
	for _, candidate := range batch {
		buckets = append(buckets, counters.Bucket{
			Key:       candidate.key,
			Algorithm: candidate.ref.rate.Algorithm.ID(),
			Window:    candidate.ref.rate.Window,
			Shadow:    candidate.ref.shadow(),
		})
	}

	verdicts, err := s.api.Counters.Peek(ctx, buckets, 1)
	if err != nil {
		return nil, err
	}
	if len(verdicts) != len(buckets) {
		return nil, errors.New("the counter store answered a different number of verdicts than keys")
	}

	kept := make([]counterCandidate, 0, len(batch))
	for i, candidate := range batch {
		if !verdicts[i].Allowed {
			kept = append(kept, candidate)
		}
	}
	return kept, nil
}

// count records one matched key against its rule and, while the sample has
// room, into the sample.
func (s *sweeper) count(k, ruleID string) {
	s.progress.Matched++
	if s.execute {
		s.progress.Reset++
	}
	s.rules[ruleID]++

	if len(s.progress.Keys) < keySampleLimit {
		s.progress.Keys = append(s.progress.Keys, k)
		return
	}
	s.progress.Truncated = true
}

// snapshotProgress is what the store records: the walk so far, whole. The
// fencing token makes this walker the only writer, so writing the whole value
// beats incrementing pieces of it.
func (s *sweeper) snapshotProgress() records.Progress {
	progress := s.progress
	progress.Rules = maps.Clone(s.rules)
	return progress
}

// result renders the completed walk.
func (s *sweeper) result(domain string) BulkResult {
	progress := s.snapshotProgress()
	result := BulkResult{
		Domain:    domain,
		DryRun:    !s.execute,
		Scanned:   progress.Scanned,
		Keys:      progress.Keys,
		Truncated: progress.Truncated,
		Rules:     ruleCounts(progress.Rules, !s.execute),
	}
	if result.Keys == nil {
		result.Keys = []string{}
	}
	if s.execute {
		reset := progress.Reset
		result.ResetCount = &reset
		return result
	}
	matched := progress.Matched
	result.MatchedCount = &matched
	return result
}
