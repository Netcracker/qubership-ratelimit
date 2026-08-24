package management

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
)

// CounterScope says how far a counter operation reaches. It is reported on
// every reset because the answer depends on how the release was installed, and
// an operator who resets a limit needs to know whether they lifted it for the
// domain or for one replica out of several.
type CounterScope string

const (
	// ScopeShared is a counter store every replica shares — Redis. A reset is
	// domain-wide and immediate.
	ScopeShared CounterScope = "shared"

	// ScopeReplica is the in-process store. Each replica counts on its own, so
	// a reset reaches only the replica that served the call and the other
	// replicas keep refusing.
	ScopeReplica CounterScope = "replica"
)

// maxScannedKeys bounds how many keys one listing request enumerates before it
// gives up on completeness. Enumeration walks the whole key space of the
// selection, so an unfiltered listing of a domain limiting many clients is
// expensive by nature; the cap turns that into a truncated answer rather than
// a request that never returns.
const maxScannedKeys = 50_000

// defaultPageSize and maxPageSize bound a page of counters. Each page costs
// one Peek across its keys, so the ceiling is what keeps a listing from
// becoming as expensive as a decision storm.
const (
	defaultPageSize = 100
	maxPageSize     = 500
)

// CounterView is one live counter and what it would do to the next request.
//
// The numbers come from the same code path enforcement uses, at a cost of one
// request: the store is asked what it would answer, without charging. So a
// counter reported as limited is one that would refuse right now, not one
// inferred from a count.
type CounterView struct {
	Key string `json:"key"`

	RuleID string `json:"ruleId"`
	Policy string `json:"policy"`
	Block  string `json:"block"`
	Rule   string `json:"rule"`

	Algorithm     string `json:"algorithm"`
	PeriodSeconds int64  `json:"periodSeconds"`

	// Axes are the identity values this counter belongs to — which client,
	// which captured path segment. A rule counting the whole domain has none.
	Axes map[string]string `json:"axes,omitempty"`

	Limit     int64 `json:"limit"`
	Remaining int64 `json:"remaining"`

	// Limited marks a counter that would refuse the next request. A shadow
	// rule can be limited and still admit traffic — that is what shadow mode
	// is for, and why the flag sits beside Shadow rather than replacing it.
	Limited bool `json:"limited"`
	Shadow  bool `json:"shadow"`

	RetryAfterSeconds float64 `json:"retryAfterSeconds,omitempty"`
	ResetAfterSeconds float64 `json:"resetAfterSeconds,omitempty"`
}

// counterQuery is a parsed listing request.
type counterQuery struct {
	policy string
	block  string
	rule   string

	limitedOnly bool
	pageSize    int
	cursor      string
}

// bucketRef pairs a counter key with the rule and rate that own it, so the
// verdicts coming back from the store can be rendered without a second lookup.
type bucketRef struct {
	key   string
	block *compile.Block
	rule  *compile.Rule
	rate  *compile.Rate
}

// rejection is a request the caller got wrong, carrying the sentence they are
// shown. It is a type rather than a plain error because these strings are
// user-facing prose — whole sentences, ending in a period — and the endpoint
// hands them to the client verbatim.
type rejection struct{ detail string }

func (e rejection) Error() string { return e.detail }

// rejectf builds a rejection.
func rejectf(format string, args ...any) error {
	return rejection{detail: fmt.Sprintf(format, args...)}
}

// errNotInspectable reports a counter store that cannot enumerate its keys.
// Both shipped stores can; the error exists so that a store which cannot says
// so plainly instead of reporting an empty domain.
var errNotInspectable = errors.New("this counter store cannot enumerate keys")

// queryCounters enumerates the counters of a domain and asks the store what
// each would do next.
func queryCounters(
	ctx context.Context,
	snapshot *compile.Snapshot,
	store counters.Store,
	query counterQuery,
) (List[CounterView], error) {
	inspector, ok := store.(counters.Inspector)
	if !ok {
		return List[CounterView]{}, errNotInspectable
	}

	refs, scanTruncated, err := scanBuckets(ctx, snapshot, inspector, query)
	if err != nil {
		return List[CounterView]{}, err
	}

	// One order for every page. The store returns keys in whatever order its
	// scan produced, which is not stable between calls, so a cursor over an
	// unsorted list would skip and repeat rows.
	sort.Slice(refs, func(i, j int) bool { return refs[i].key < refs[j].key })

	page, pageTruncated := paginate(refs, query)
	views, err := peekPage(ctx, store, page, query.limitedOnly)
	if err != nil {
		return List[CounterView]{}, err
	}

	result := newList(views)
	result.Truncated = scanTruncated || pageTruncated
	if pageTruncated && len(page) > 0 {
		result.NextCursor = page[len(page)-1].key
	}
	return result, nil
}

// selectedRule is one rule the query asked for, with the block that owns it —
// a rule's identity is the triple, so the block travels with it.
type selectedRule struct {
	block *compile.Block
	rule  *compile.Rule
}

// selectRules flattens the snapshot down to the rules the query names.
func selectRules(snapshot *compile.Snapshot, query counterQuery) []selectedRule {
	var selected []selectedRule
	for i := range snapshot.Blocks {
		block := &snapshot.Blocks[i]
		if !query.matchesBlock(block) {
			continue
		}
		for j := range block.Rules {
			rule := &block.Rules[j]
			if query.rule != "" && rule.Name != query.rule {
				continue
			}
			selected = append(selected, selectedRule{block: block, rule: rule})
		}
	}
	return selected
}

// matchesBlock reports whether the block survives the policy and block filters.
func (q counterQuery) matchesBlock(block *compile.Block) bool {
	if q.policy != "" && block.Policy != q.policy {
		return false
	}
	if q.block != "" && block.Name != q.block {
		return false
	}
	return true
}

// bucketCollector gathers scanned keys, dropping duplicates and stopping at the
// scan cap.
type bucketCollector struct {
	refs []bucketRef
	seen map[string]struct{}
}

// add records one key and reports whether there is room for another.
//
// Duplicates are dropped rather than rejected: two rates of one rule that
// resolve to the same algorithm and period share a prefix, and Peek refuses a
// repeated key in one call — rightly, since evaluating it twice would lose a
// charge — but a listing must not fail over a rule that merely repeats itself.
func (c *bucketCollector) add(bucketKey string, selected selectedRule, rate *compile.Rate) bool {
	if _, duplicate := c.seen[bucketKey]; !duplicate {
		c.seen[bucketKey] = struct{}{}
		c.refs = append(c.refs, bucketRef{
			key: bucketKey, block: selected.block, rule: selected.rule, rate: rate,
		})
	}
	return len(c.refs) < maxScannedKeys
}

// scanBuckets enumerates the keys of every rate the query selects.
func scanBuckets(
	ctx context.Context,
	snapshot *compile.Snapshot,
	inspector counters.Inspector,
	query counterQuery,
) ([]bucketRef, bool, error) {
	collector := &bucketCollector{seen: make(map[string]struct{})}

	for _, selected := range selectRules(snapshot, query) {
		for i := range selected.rule.Rates {
			rate := &selected.rule.Rates[i]
			keys, err := inspector.Keys(ctx, rate.Prefix)
			if err != nil {
				return nil, false, fmt.Errorf("list the keys of %s: %w",
					ruleID(selected.block.Policy, selected.block.Name, selected.rule.Name), err)
			}
			for _, bucketKey := range keys {
				if !collector.add(bucketKey, selected, rate) {
					return collector.refs, true, nil
				}
			}
		}
	}
	return collector.refs, false, nil
}

// paginate cuts the page the cursor asks for, reporting whether more follows.
func paginate(refs []bucketRef, query counterQuery) ([]bucketRef, bool) {
	if query.cursor != "" {
		start := sort.Search(len(refs), func(i int) bool { return refs[i].key > query.cursor })
		refs = refs[start:]
	}
	size := query.pageSize
	if size <= 0 {
		size = defaultPageSize
	}
	if len(refs) > size {
		return refs[:size], true
	}
	return refs, false
}

// peekPage asks the store what each counter of the page would do, at the cost
// of one request, and renders the answers.
func peekPage(
	ctx context.Context,
	store counters.Store,
	page []bucketRef,
	limitedOnly bool,
) ([]CounterView, error) {
	if len(page) == 0 {
		return nil, nil
	}

	buckets := make([]counters.Bucket, 0, len(page))
	for _, ref := range page {
		buckets = append(buckets, counters.Bucket{
			Key:       ref.key,
			Algorithm: ref.rate.Algorithm.ID(),
			Window:    ref.rate.Window,
			Shadow:    ref.rule.Behavior == model.BehaviorShadow,
		})
	}

	verdicts, err := store.Peek(ctx, buckets, 1)
	if err != nil {
		return nil, fmt.Errorf("read the counters: %w", err)
	}
	if len(verdicts) != len(buckets) {
		return nil, fmt.Errorf("the counter store answered %d verdicts for %d keys",
			len(verdicts), len(buckets))
	}

	views := make([]CounterView, 0, len(page))
	for i, ref := range page {
		if limitedOnly && verdicts[i].Allowed {
			continue
		}
		view, err := counterView(ref, buckets[i], verdicts[i])
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func counterView(ref bucketRef, bucket counters.Bucket, verdict counters.Verdict) (CounterView, error) {
	axes, err := decodeAxes(ref.key, ref.rate.Prefix, ref.rule.Counters)
	if err != nil {
		return CounterView{}, fmt.Errorf("decode the axes of a counter: %w", err)
	}
	view := CounterView{
		Key:           ref.key,
		RuleID:        ruleID(ref.block.Policy, ref.block.Name, ref.rule.Name),
		Policy:        ref.block.Policy,
		Block:         ref.block.Name,
		Rule:          ref.rule.Name,
		Algorithm:     ref.rate.Algorithm.Name(),
		PeriodSeconds: int64(ref.rate.Window.Period / time.Second),
		Axes:          axes,
		Limit:         bucket.Window.Requests,
		Remaining:     verdict.Remaining,
		Limited:       !verdict.Allowed,
		Shadow:        bucket.Shadow,
	}
	if verdict.RetryAfter > 0 {
		view.RetryAfterSeconds = verdict.RetryAfter.Seconds()
	}
	if verdict.ResetAfter > 0 {
		view.ResetAfterSeconds = verdict.ResetAfter.Seconds()
	}
	return view, nil
}

// resetTarget is a validated reset request: a rule that exists in the current
// rule set, and the axis values narrowing it.
type resetTarget struct {
	block *compile.Block
	rule  *compile.Rule

	// axes are the values in the rule's axis order, a leading run of it.
	axes []string

	// named is the same selection keyed by axis name, for the audit record and
	// the response.
	named map[string]string
}

// resolveTarget finds the rule in the snapshot and checks the axis selection
// against it.
//
// A partial selection has to name a leading run of the rule's axes. That is
// not an arbitrary restriction: the axis values are concatenated into the key
// in that order, so a selection skipping one addresses no prefix and could
// only be honored by scanning and filtering every counter of the rule.
func resolveTarget(snapshot *compile.Snapshot, policy, block, rule string, axes map[string]string) (resetTarget, error) {
	var target resetTarget
	for i := range snapshot.Blocks {
		candidate := &snapshot.Blocks[i]
		if candidate.Policy != policy || candidate.Name != block {
			continue
		}
		for j := range candidate.Rules {
			if candidate.Rules[j].Name == rule {
				target.block = candidate
				target.rule = &candidate.Rules[j]
			}
		}
	}
	if target.rule == nil {
		return resetTarget{}, rejectf(
			"No rule %q is being enforced for domain %q. "+
				"A rule missing here but present in a policy object means the policy was rejected or is running on an earlier spec.",
			ruleID(policy, block, rule), snapshot.Domain)
	}

	declared := target.rule.Counters
	for name := range axes {
		if !slices.Contains(declared, name) {
			return resetTarget{}, rejectf(
				"Rule %q does not count by axis %q. It counts by: %v.",
				ruleID(policy, block, rule), name, declared)
		}
	}
	if len(axes) > len(declared) {
		return resetTarget{}, rejectf(
			"Rule %q counts by %d axes, and the request names %d.",
			ruleID(policy, block, rule), len(declared), len(axes))
	}

	target.axes = make([]string, 0, len(axes))
	target.named = make(map[string]string, len(axes))
	for _, name := range declared[:len(axes)] {
		value, ok := axes[name]
		if !ok {
			return resetTarget{}, rejectf(
				"Axis values must name a leading run of the rule's axes, in order. "+
					"Rule %q counts by %v, so selecting %d of them means naming %v.",
				ruleID(policy, block, rule), declared, len(axes), declared[:len(axes)])
		}
		if value == "" {
			return resetTarget{}, rejectf(
				"Axis %q has an empty value, which addresses no counter.", name)
		}
		target.axes = append(target.axes, value)
		target.named[name] = value
	}
	return target, nil
}

// dropCounters drops the counter state the target selects and reports the
// keys it dropped.
//
// The keys are enumerated before they are dropped rather than computed, so the
// answer says what was actually there. That matters for the audit record: "the
// limit on alice was lifted" and "nothing was counting for alice" are different
// events, and an operator who resets a client that was never limited should be
// able to see that they did.
func dropCounters(
	ctx context.Context,
	snapshot *compile.Snapshot,
	store counters.Store,
	target resetTarget,
) ([]string, error) {
	prefixes := resetPrefixes(snapshot.Domain, target)

	inspector, ok := store.(counters.Inspector)
	if !ok {
		// Without enumeration only a fully specified selection can be
		// addressed, because every other one is a prefix over keys this
		// process cannot list.
		if len(target.axes) != len(target.rule.Counters) {
			return nil, errNotInspectable
		}
		if err := store.Reset(ctx, prefixes); err != nil {
			return nil, fmt.Errorf("reset the counters: %w", err)
		}
		return prefixes, nil
	}

	var found []string
	seen := make(map[string]struct{})
	for _, prefix := range prefixes {
		keys, err := inspector.Keys(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("list the counters to reset: %w", err)
		}
		for _, k := range keys {
			if _, duplicate := seen[k]; duplicate {
				continue
			}
			seen[k] = struct{}{}
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		return nil, nil
	}

	sort.Strings(found)
	if err := store.Reset(ctx, found); err != nil {
		return nil, fmt.Errorf("reset the counters: %w", err)
	}
	return found, nil
}

// resetPrefixes builds the key prefixes covering the selection.
//
// Without axes one prefix covers the rule whole, every algorithm and window
// included. With axes the algorithm and the period sit in the key ahead of the
// values, so the selection has to be expressed once per rate.
func resetPrefixes(domain string, target resetTarget) []string {
	id := key.Ident{
		Domain: domain,
		Policy: target.block.Policy,
		Block:  target.block.Name,
		Rule:   target.rule.Name,
	}
	if len(target.axes) == 0 {
		return []string{key.RulePrefix(id)}
	}

	prefixes := make([]string, 0, len(target.rule.Rates))
	seen := make(map[string]struct{}, len(target.rule.Rates))
	for i := range target.rule.Rates {
		prefix := key.Bucket(target.rule.Rates[i].Prefix, target.axes)
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
