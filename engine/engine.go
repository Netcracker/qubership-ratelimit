// Package engine is the public face of the decision core: a compiled
// snapshot bound to a counter store, answering one request at a time.
//
// The pipeline behind Decide is the request lifecycle of the specification:
// identity extraction from the token, matching into buckets, one atomic store
// decision, and header aggregation from the strictest rule. Everything above
// — protocols, statuses, fail-open policy, metrics emission — belongs to the
// caller; the engine returns facts.
package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/identity"
	"github.com/netcracker/qubership-ratelimit/engine/match"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// Engine binds one domain's snapshot to a store. Its configuration is
// immutable — swapping a snapshot means swapping the engine value,
// atomically, on the caller's side; the token cache inside is
// concurrency-safe internal state and retires with the engine value.
type Engine struct {
	snap  *compile.Snapshot
	store store.Store
	cache *tokenCache
}

// options collects construction-time settings before anything is allocated.
type options struct {
	tokenCache int
}

// Option adjusts an Engine at construction.
type Option func(*options)

// DefaultTokenCacheSize is the token-cache bound New applies when no
// WithTokenCache option overrides it.
const DefaultTokenCacheSize = 10_000

// WithTokenCache bounds the identity-extraction cache to capacity tokens;
// zero or a negative value disables caching. Extraction is a pure function
// of the token and the snapshot, so the cache changes cost, never results.
func WithTokenCache(capacity int) Option {
	return func(o *options) { o.tokenCache = capacity }
}

// New builds an engine over a compiled snapshot. The snapshot comes from
// compile.Compile and is treated as read-only. Identity extraction is cached
// per token (see WithTokenCache); the cache retires with the engine value on
// a snapshot swap.
func New(snap *compile.Snapshot, s store.Store, opts ...Option) *Engine {
	o := options{tokenCache: DefaultTokenCacheSize}
	for _, apply := range opts {
		apply(&o)
	}
	e := &Engine{snap: snap, store: s}
	if o.tokenCache > 0 {
		e.cache = newTokenCache(o.tokenCache)
	}
	return e
}

// MaxDecisionBuckets caps how many buckets one decision may carry to the
// store, across every matched policy. Compilation already bounds each policy
// by model.MaxDecisionBucketsPerPolicy and reports a domain over this bound
// as an informational problem; this backstop is the hard stop behind both.
// Every bucket is one read and possibly one write inside a single atomic
// store script, so an unbounded decision would monopolize the domain's
// shard.
const MaxDecisionBuckets = model.MaxDomainDecisionBuckets

// ErrTooManyBuckets refuses a decision over MaxDecisionBuckets before the
// store is touched. Unlike a store error, it reports a configuration
// violation, not unavailability: an adapter must map it to a denial
// regardless of its fail-open policy, or an oversized policy set would turn
// the busiest paths into unlimited ones. The operator keeps the active set
// within the budget at admission, so in that deployment this error marks a
// bypassed gate, not a store incident.
var ErrTooManyBuckets = errors.New("engine: the decision exceeds the bucket budget")

// Request is one request in either of its two forms: a gateway sends the raw
// path and token and the engine extracts identity itself; a direct consumer
// sends pre-extracted Keys. When both are present, explicit Keys win per key.
type Request struct {
	Path   string
	Method string

	// Token is the raw token descriptor value; extraction never verifies the
	// signature and never lets the raw value past the identity layer.
	Token string

	// Keys are pre-extracted identity values, overriding extraction per key.
	Keys map[string][]string

	// Cost is the protocol's hits_addend; zero means the default of one.
	Cost int64
}

// Headers is the x-ratelimit source: the strictest applied enforcing rule.
type Headers struct {
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration // negative when no retry hint applies
	ResetAfter time.Duration
}

// RuleOutcome is one applied rule's own verdict, for metrics and the decision
// audit stream: a shadow rule reports what it would have done without
// affecting Allowed.
type RuleOutcome struct {
	Policy  string
	Block   string
	Rule    string
	Shadow  bool
	Allowed bool

	// Limit, Remaining, and RetryAfter come from the rule's own strictest
	// bucket, chosen by the same tie-break the response headers use — the
	// numbers behind near-limit metrics and per-rule audit records.
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
}

// Decision is the answer plus the facts the adapter turns into a protocol
// response and metrics.
type Decision struct {
	// Allowed is the verdict: no enforcing bucket refused.
	Allowed bool

	// CostExceedsCapacity marks a refusal no waiting can cure; no retry hint
	// must reach the response.
	CostExceedsCapacity bool

	// Headers is nil when no counting rule matched — a request outside all
	// rules is allowed without a store round trip and without headers.
	Headers *Headers

	Rules []RuleOutcome

	// Skips are extraction anomalies for the metrics layer. Identity is
	// resolved only when at least one block targets the request; a request
	// outside every target reports no skips.
	Skips []identity.Skip

	// ExtractedKeys are the names — never the values — of the declared
	// identity keys the request carried, sorted. They feed the per-key
	// success counters of the "key declared, tokens arriving, zero
	// extractions" detector. Like Skips, they are empty when no block
	// targets the request.
	ExtractedKeys []string
}

// Decide runs the full pipeline for one request. An error means no decision
// was made. For store errors, failing open or closed is the caller's policy;
// the one exception is ErrTooManyBuckets, whose contract requires a denial —
// see its documentation.
func (e *Engine) Decide(ctx context.Context, req Request) (Decision, error) {
	cost := req.Cost
	if cost == 0 {
		cost = 1
	}

	cands := match.Match(e.snap, req.Path, req.Method)
	if cands.Empty() {
		return Decision{Allowed: true}, nil
	}

	keys, skips := e.extractKeys(req)
	matched := cands.Evaluate(keys)

	buckets := matched.Buckets()
	if len(buckets) == 0 {
		return Decision{Allowed: true, Skips: skips, ExtractedKeys: e.keyNames(keys)}, nil
	}
	if len(buckets) > MaxDecisionBuckets {
		return Decision{}, fmt.Errorf("%w: the request matched %d buckets", ErrTooManyBuckets, len(buckets))
	}

	verdicts, err := e.store.Decide(ctx, buckets, cost)
	if err != nil {
		return Decision{}, err
	}

	decision := Decision{
		Allowed:       store.Admitted(buckets, verdicts),
		Rules:         ruleOutcomes(matched, buckets, verdicts),
		Skips:         skips,
		ExtractedKeys: e.keyNames(keys),
	}
	decision.Headers, decision.CostExceedsCapacity = aggregate(buckets, verdicts, decision.Allowed)
	return decision, nil
}

// keyNames lists the declared identity keys the request carried, sorted.
// EffectiveKeys is already sorted, so presence filtering preserves order;
// names an embedder overlays beyond the declared set are not identity keys
// and stay out. Values never leave here.
func (e *Engine) keyNames(keys map[string][]string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range e.snap.EffectiveKeys {
		if _, ok := keys[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

// extractKeys resolves identity: extraction from the token first, explicit
// keys layered on top.
func (e *Engine) extractKeys(req Request) (map[string][]string, []identity.Skip) {
	extracted, skips := e.cachedExtract(req.Token)
	if len(req.Keys) == 0 {
		return extracted, skips
	}
	if extracted == nil {
		extracted = make(map[string][]string, len(req.Keys))
	}
	maps.Copy(extracted, req.Keys)
	return extracted, skips
}

// ruleOutcomes folds bucket verdicts back onto their rules: a rule allowed
// is a rule none of whose buckets refused, and its numbers come from its own
// strictest bucket.
func ruleOutcomes(matched match.Result, buckets []store.Bucket, verdicts []store.Verdict) []RuleOutcome {
	out := make([]RuleOutcome, 0, len(matched.Rules))
	i := 0
	for _, m := range matched.Rules {
		from, to := i, i+len(m.Buckets)
		i = to

		outcome := RuleOutcome{Policy: m.Policy, Block: m.Block, Rule: m.Rule, Shadow: m.Shadow, Allowed: true}
		for j := from; j < to; j++ {
			if !verdicts[j].Allowed {
				outcome.Allowed = false
			}
		}
		if best := strictestIndex(buckets, verdicts, from, to, outcome.Allowed, false); best >= 0 {
			outcome.Limit = buckets[best].Window.Requests
			outcome.Remaining = verdicts[best].Remaining
			outcome.RetryAfter = verdicts[best].RetryAfter
		}
		out = append(out, outcome)
	}
	return out
}

// aggregate picks the strictest enforcing bucket for the response headers.
//
// On allow it is the minimum remaining; on refusal, the refusing bucket with
// the longest wait — the constraint that actually binds the client. Ties
// break lexicographically by bucket key, which is ordering by the
// policy/block/rule triple: deterministic across replicas, so headers do not
// jitter between them. A refusal that no waiting cures surfaces as
// CostExceedsCapacity with no retry hint.
func aggregate(buckets []store.Bucket, verdicts []store.Verdict, allowed bool) (*Headers, bool) {
	costExceeds := false
	if !allowed {
		for i := range buckets {
			if !buckets[i].Shadow && verdicts[i].CostExceedsCapacity {
				costExceeds = true
			}
		}
	}

	best := strictestIndex(buckets, verdicts, 0, len(buckets), allowed, true)
	if best < 0 {
		return nil, false
	}

	h := &Headers{
		Limit:      buckets[best].Window.Requests,
		Remaining:  verdicts[best].Remaining,
		RetryAfter: verdicts[best].RetryAfter,
		ResetAfter: verdicts[best].ResetAfter,
	}
	if costExceeds {
		h.RetryAfter = -1
	}
	return h, costExceeds
}

// strictestIndex picks the strictest bucket of a range: on allow, the minimum
// remaining; on refusal, the refusing bucket with the longest wait. Ties break
// lexicographically by bucket key — deterministic across replicas.
func strictestIndex(buckets []store.Bucket, verdicts []store.Verdict, from, to int, allowed, skipShadow bool) int {
	best := -1
	for i := from; i < to; i++ {
		if skipShadow && buckets[i].Shadow {
			continue
		}
		if !allowed && verdicts[i].Allowed {
			continue
		}
		if best < 0 || stricter(buckets, verdicts, i, best, allowed) {
			best = i
		}
	}
	return best
}

// stricter reports whether bucket i binds harder than the current best: less
// remaining on allow, a longer wait on refusal, the smaller key on a tie.
func stricter(buckets []store.Bucket, verdicts []store.Verdict, i, best int, allowed bool) bool {
	if allowed {
		if verdicts[i].Remaining != verdicts[best].Remaining {
			return verdicts[i].Remaining < verdicts[best].Remaining
		}
	} else if verdicts[i].RetryAfter != verdicts[best].RetryAfter {
		return verdicts[i].RetryAfter > verdicts[best].RetryAfter
	}
	return buckets[i].Key < buckets[best].Key
}
