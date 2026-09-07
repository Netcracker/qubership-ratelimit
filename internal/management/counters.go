package management

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
)

// scanBudget bounds the keys one call examines.
//
// The size of a selection cannot be known in advance, because a scan does not
// count matches cheaply. Work is bounded instead of predicted: a page stops at
// the budget and says how far it got, which turns an unbounded listing over a
// busy domain into a short page rather than a request that never returns.
const scanBudget = 12_000

// defaultPageSize and maxPageSize bound one page of counters. Each page costs
// one Peek across its keys.
const (
	defaultPageSize = 100
	maxPageSize     = 500
)

// CounterList is one page of live counters.
type CounterList struct {
	Items []CounterView `json:"items"`

	// NextCursor is the only signal that more follows. A page can be short
	// mid-collection when the scan budget fills first, so page fill says
	// nothing.
	NextCursor string `json:"nextCursor,omitempty"`

	Truncated bool `json:"truncated,omitempty"`

	// Scanned is how many keys were examined to build this page, including the
	// keys of rules no longer enforced, which the page skips.
	Scanned int `json:"scanned"`
}

// CounterView is one live counter and what it would do to the next request.
//
// The numbers come from the code path enforcement uses, judged at a cost of
// one and charging nothing: a counter reported as limited is one that would
// refuse right now, not one inferred from a count.
type CounterView struct {
	// Key is the store key, for support quotes and log correlation. Resets
	// address counters by rule and axes, never by key.
	Key string `json:"key"`

	RuleID string `json:"ruleId"`
	Block  string `json:"block"`
	Rule   string `json:"rule"`

	Algorithm     string `json:"algorithm"`
	PeriodSeconds int64  `json:"periodSeconds"`

	// Mode is enforce or shadow; a bypass rule carries no counters.
	Mode string `json:"mode"`

	// Axes are the identity values this counter belongs to: which client, which
	// captured path segment. A rule counting the whole domain has none.
	Axes map[string]string `json:"axes,omitempty"`

	Limit     int64 `json:"limit"`
	Remaining int64 `json:"remaining"`

	// Limited marks a counter that would refuse the next cost-1 request. A shadow
	// counter can be limited and still admit traffic, which is what shadow mode
	// is for.
	Limited bool `json:"limited"`

	RetryAfterSeconds float64 `json:"retryAfterSeconds,omitempty"`
	ResetAfterSeconds float64 `json:"resetAfterSeconds,omitempty"`
}

// rateRef is one rate of the enforced set, with the rule and block that own it.
type rateRef struct {
	block *compile.Block
	rule  *compile.Rule
	rate  *compile.Rate
}

// shadow reports whether this rate's counters count without refusing.
func (r rateRef) shadow() bool { return r.rule.Behavior == model.BehaviorShadow }

// rateIndex maps a rate prefix back to the rule that owns it, which is how a
// scanned key is rendered against the enforced set, and how a key belonging to
// no current rule is recognized as the leftover it is.
type rateIndex map[string]rateRef

func newRateIndex(snapshot *compile.Snapshot) rateIndex {
	index := rateIndex{}
	for i := range snapshot.Blocks {
		block := &snapshot.Blocks[i]
		for j := range block.Rules {
			rule := &block.Rules[j]
			for k := range rule.Rates {
				rate := &rule.Rates[k]
				// Two rates of one rule can resolve to the same algorithm and
				// period, and then they are one bucket; the first wins, as it
				// does on the decision path.
				if _, taken := index[rate.Prefix]; !taken {
					index[rate.Prefix] = rateRef{block: block, rule: rule, rate: rate}
				}
			}
		}
	}
	return index
}

// counterCandidate is a scanned key that survived the key-level and identity
// filters, waiting to be judged.
type counterCandidate struct {
	key string
	ref rateRef

	// ruleID is the triple the key itself carries. It is read from the key
	// rather than from the rule, so a counter whose rule a rollout removed can
	// still be counted against the rule it belonged to.
	ruleID string

	axes map[string]string
}

// listCounters enumerates a page of a domain's counters and asks the store what
// each would do next.
func (a *API) listCounters(
	ctx context.Context,
	snapshot *compile.Snapshot,
	sel selector,
	pageSize int,
	after string,
	now time.Time,
) (CounterList, *apiError) {
	inspector, ok := a.Counters.(counters.Inspector)
	if !ok {
		// Both shipped stores enumerate. A store that cannot must say so rather
		// than report an empty domain, which reads as "nothing is limited".
		return CounterList{}, errorf(CodeInternal,
			"the configured counter store cannot enumerate keys, so counters cannot be listed")
	}

	keys, err := inspector.Keys(ctx, scanPrefix(a.Namespace, snapshot.Domain, sel))
	if err != nil {
		a.Log.ErrorC(ctx, "failed to scan counter keys domain=%v error=%v", snapshot.Domain, err)
		return CounterList{}, storeDown("the counter store did not answer the scan")
	}
	sort.Strings(keys)

	page := a.selectCandidates(ctx, snapshot, keys, sel, pageSize, after)
	views, apiErr := a.judge(ctx, page.candidates, sel.LimitedOnly)
	if apiErr != nil {
		return CounterList{}, apiErr
	}

	list := CounterList{Items: views, Scanned: page.scanned}
	// The cursor is minted from the last key the walk looked at, not from the
	// last one it kept. A page that filled its budget without a match would
	// otherwise end the listing — a missing nextCursor is what the contract
	// defines as the end — and a narrow filter over a busy domain would report
	// that a counter which exists does not. Resuming from the last candidate
	// would also rescan the tail between it and the budget.
	if page.more {
		list.Truncated = true
		list.NextCursor = encodeCursor(page.lastScanned, sel, now)
	}
	return list, nil
}

// page is what one walk of the sorted keys produced: the counters it kept, how
// many keys it looked at, whether it stopped early, and the last key it looked
// at, which is where the next page resumes.
type page struct {
	candidates  []counterCandidate
	scanned     int
	more        bool
	lastScanned string
}

// selectCandidates walks the sorted keys after the cursor, keeping the ones the
// selection admits, and stops at the page size or the scan budget.
func (a *API) selectCandidates(
	ctx context.Context,
	snapshot *compile.Snapshot,
	keys []string,
	sel selector,
	pageSize int,
	after string,
) page {
	index := newRateIndex(snapshot)
	out := page{}

	for _, k := range keys {
		if after != "" && k <= after {
			continue
		}
		if len(out.candidates) >= pageSize || out.scanned >= scanBudget {
			out.more = true
			return out
		}
		out.scanned++
		out.lastScanned = k

		parsed, err := parseCounterKey(a.Namespace, snapshot.Domain, k)
		if err != nil {
			// A key that does not parse belongs to another layout or another
			// writer. It is reported once and skipped: a listing is not the
			// place to fail the whole call over one foreign key.
			a.Log.DebugC(ctx, "skipping an unparsable counter key domain=%v reason=%v",
				snapshot.Domain, err)
			continue
		}
		if !sel.matches(parsed) {
			continue
		}
		ref, enforced := index[parsed.RatePrefix]
		if !enforced {
			// A rollout removed the rule while its counters live out their TTL.
			// There is nothing in the serving snapshot to render them against, so
			// they are skipped; they were examined, and scanned says so.
			continue
		}
		axes, err := parsed.namedAxes(ref.rule.Counters)
		if err != nil {
			a.Log.DebugC(ctx, "skipping a counter whose axes do not fit its rule domain=%v reason=%v",
				snapshot.Domain, err)
			continue
		}
		if !sel.matchesAxes(axes) {
			continue
		}
		out.candidates = append(out.candidates, counterCandidate{
			key: k, ref: ref, ruleID: parsed.RuleID, axes: axes,
		})
	}
	return out
}

// judge asks the store what each candidate would do to the next request.
func (a *API) judge(ctx context.Context, candidates []counterCandidate, limitedOnly bool) ([]CounterView, *apiError) {
	views := make([]CounterView, 0, len(candidates))
	if len(candidates) == 0 {
		return views, nil
	}

	buckets := make([]counters.Bucket, 0, len(candidates))
	for _, candidate := range candidates {
		buckets = append(buckets, counters.Bucket{
			Key:       candidate.key,
			Algorithm: candidate.ref.rate.Algorithm.ID(),
			Window:    candidate.ref.rate.Window,
			Shadow:    candidate.ref.shadow(),
		})
	}

	verdicts, err := a.Counters.Peek(ctx, buckets, 1)
	if err != nil {
		a.Log.ErrorC(ctx, "failed to read counters error=%v", err)
		return nil, storeDown("the counter store did not answer the read")
	}
	if len(verdicts) != len(buckets) {
		return nil, errorf(CodeInternal, fmt.Sprintf(
			"the counter store answered %d verdicts for %d keys", len(verdicts), len(buckets)))
	}

	for i, candidate := range candidates {
		if limitedOnly && verdicts[i].Allowed {
			continue
		}
		views = append(views, counterView(candidate, buckets[i], verdicts[i]))
	}
	return views, nil
}

func counterView(candidate counterCandidate, bucket counters.Bucket, verdict counters.Verdict) CounterView {
	ref := candidate.ref
	view := CounterView{
		Key:           candidate.key,
		RuleID:        ruleID(ref.block.Name, ref.rule.Name),
		Block:         ref.block.Name,
		Rule:          ref.rule.Name,
		Algorithm:     ruleview.Algorithm(ref.rate),
		PeriodSeconds: int64(ref.rate.Window.Period / time.Second),
		Mode:          ruleview.Mode(ref.rule.Behavior),
		Axes:          candidate.axes,
		Limit:         bucket.Window.Requests,
		Remaining:     verdict.Remaining,
		Limited:       !verdict.Allowed,
	}
	if verdict.RetryAfter > 0 {
		view.RetryAfterSeconds = verdict.RetryAfter.Seconds()
	}
	if verdict.ResetAfter > 0 {
		view.ResetAfterSeconds = verdict.ResetAfter.Seconds()
	}
	return view
}

// scanPrefix narrows the scan to what the selection can prove it needs.
//
// One id addresses a subtree: a whole block/rule id its own, a lone block name
// all of its rules. Anything else — several ids, or none — has to walk the
// domain, because the layout puts the window ahead of the axis values and there
// is no prefix that covers a set of rules.
func scanPrefix(namespace, domain string, sel selector) string {
	if len(sel.RuleIDs) == 1 {
		id := sel.RuleIDs[0]
		if block, rule, ok := ruleview.SplitID(id); ok {
			return key.RulePrefix(key.Ident{
				Namespace: namespace, Domain: domain, Block: block, Rule: rule})
		}
		if id != "" && !strings.Contains(id, "/") {
			return key.BlockPrefix(namespace, domain, id)
		}
	}
	return key.DomainPrefix(namespace, domain)
}

// ruleID joins the pair that identifies a rule within a domain.
func ruleID(block, rule string) string {
	return ruleview.ID(block, rule)
}
