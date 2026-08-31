package match

import (
	"slices"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// Candidates is the outcome of the target phase: the blocks that target one
// request, each with the view its matched route built. The target phase
// needs no identity, so an empty set lets the caller skip token parsing
// altogether.
type Candidates struct {
	method string
	hits   []hit
}

// hit is one targeted block. pathAxis is what the path axis reports inside
// the block — the template string when a template route matched, the request
// path otherwise — and captures are the route's template placeholders.
type hit struct {
	block    *compile.Block
	pathAxis string
	captures map[string]string
}

// Match runs the target phase over the path and method alone. A query
// string never participates: it is stripped before any path predicate and
// before path serves as an axis.
func Match(snap *compile.Snapshot, path, method string) Candidates {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	out := Candidates{method: method}
	for i := range snap.Blocks {
		block := &snap.Blocks[i]
		pathAxis, captures, ok := matchTarget(block, path, method)
		if !ok {
			continue
		}
		out.hits = append(out.hits, hit{block: block, pathAxis: pathAxis, captures: captures})
	}
	return out
}

// Empty reports that no block targets the request: it is allowed as it
// stands, and identity extraction has nothing to feed.
func (c Candidates) Empty() bool { return len(c.hits) == 0 }

// Blocks lists the targeted blocks in snapshot order.
//
// It exists for introspection: an operator asking which rules guard a path
// deserves the answer the decision path would give, and a caller filtering the
// rule listing by hand would reimplement segment-based prefixes and template
// captures, which is the exact place where a second matcher drifts from this
// one. The blocks belong to the snapshot and are read-only.
func (c Candidates) Blocks() []*compile.Block {
	out := make([]*compile.Block, 0, len(c.hits))
	for i := range c.hits {
		out = append(out, c.hits[i].block)
	}
	return out
}

// Evaluate runs the rule phase over the candidates. Keys are the extracted
// identity values; a key's value is a set — scalar keys carry one element,
// array keys their elements, absent keys nothing. Built-in path and method
// are not listed there; the matcher derives them itself.
func (c Candidates) Evaluate(keys map[string][]string) Result {
	var out Result
	for i := range c.hits {
		h := &c.hits[i]
		ctx := blockCtx{method: c.method, keys: keys, pathAxis: h.pathAxis, captures: h.captures}
		out.Rules = append(out.Rules, evalBlock(h.block, &ctx)...)
	}
	return out
}

// Result is the store-ready expansion of one request: the applied rules in
// deterministic order — snapshot block order, authored rule order — each
// carrying one bucket per window.
type Result struct {
	Rules []MatchedRule
}

// Buckets flattens the result in rule order for one store call.
func (r Result) Buckets() []store.Bucket {
	n := 0
	for _, m := range r.Rules {
		n += len(m.Buckets)
	}
	out := make([]store.Bucket, 0, n)
	for _, m := range r.Rules {
		out = append(out, m.Buckets...)
	}
	return out
}

// MatchedRule is one applied rule with its counter identity, for metrics and
// header attribution.
type MatchedRule struct {
	Policy string
	Block  string
	Rule   string

	// Shadow mirrors the rule's behavior: its buckets count and report but
	// never veto.
	Shadow bool

	Buckets []store.Bucket
}

// blockCtx is the request as one block sees it: the path axis takes the
// template string when a template route matched — axis cardinality bounded by
// construction — and the route's captures become block-scoped keys.
type blockCtx struct {
	method   string
	keys     map[string][]string
	pathAxis string
	captures map[string]string
}

// valueOf resolves a key to its value set within the block.
func (c *blockCtx) valueOf(k string) []string {
	switch k {
	case model.KeyPath:
		return []string{c.pathAxis}
	case model.KeyMethod:
		return []string{c.method}
	}
	if v, ok := c.captures[k]; ok {
		return []string{v}
	}
	return c.keys[k]
}

// matchTarget finds the first matching route in authored order — the only
// deterministic choice when several of an OR-list match — and reports the
// block's path-axis view plus the route's captures. A block without routes is
// the documented "whole domain" form and matches everything.
func matchTarget(block *compile.Block, path, method string) (string, map[string]string, bool) {
	if len(block.Routes) == 0 {
		return path, nil, true
	}
	for i := range block.Routes {
		route := &block.Routes[i]
		if len(route.Methods) > 0 {
			if _, ok := route.Methods[method]; !ok {
				continue
			}
		}
		captures, ok := matchPath(route, path)
		if !ok {
			continue
		}
		if route.Type == model.PathTemplate {
			return route.Value, captures, true
		}
		return path, captures, true
	}
	return "", nil, false
}

func matchPath(route *compile.Route, path string) (map[string]string, bool) {
	switch route.Type {
	case model.PathExact:
		return nil, path == route.Value
	case model.PathPrefix:
		return nil, strings.HasPrefix(path, route.Value)
	case model.PathTemplate:
		return matchTemplate(route.Segments, path)
	}
	return nil, false
}

// matchTemplate compares segment-wise: a placeholder takes exactly one
// non-empty segment, and the template covers the whole path.
func matchTemplate(segments []compile.Segment, path string) (map[string]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	if len(parts) != len(segments) {
		return nil, false
	}
	var captures map[string]string
	for i, s := range segments {
		if s.Capture == "" {
			if parts[i] != s.Literal {
				return nil, false
			}
			continue
		}
		if parts[i] == "" {
			return nil, false
		}
		if captures == nil {
			captures = map[string]string{}
		}
		captures[s.Capture] = parts[i]
	}
	return captures, true
}

// evalBlock applies the block's mode over its rules.
func evalBlock(block *compile.Block, ctx *blockCtx) []MatchedRule {
	if block.Mode == model.ModeFirstMatch {
		return evalFirstMatch(block, ctx)
	}
	return evalAll(block, ctx)
}

// evalFirstMatch walks the cascade. A shadow rule counts without stopping
// it; bypass and enforce both end it — one by allowing, one by applying.
func evalFirstMatch(block *compile.Block, ctx *blockCtx) []MatchedRule {
	var out []MatchedRule
	for i := range block.Rules {
		rule := &block.Rules[i]
		if !ruleMatches(rule, ctx) {
			continue
		}
		if rule.Behavior == model.BehaviorBypass {
			return out
		}
		out = append(out, matchedRule(block, rule, ctx))
		if rule.Behavior != model.BehaviorShadow {
			return out
		}
	}
	return out
}

// evalAll applies every matching rule. A matching rule's replaces suppresses
// the rules it names; for a bypass that is the whole effect — a targeted
// exemption, never the whole block.
func evalAll(block *compile.Block, ctx *blockCtx) []MatchedRule {
	var out []MatchedRule
	var suppressed map[string]struct{} // lazy: replaces is the rare case

	for i := range block.Rules {
		rule := &block.Rules[i]
		if !ruleMatches(rule, ctx) {
			continue
		}
		if rule.Behavior != model.BehaviorBypass {
			out = append(out, matchedRule(block, rule, ctx))
		}
		for _, name := range rule.Replaces {
			if suppressed == nil {
				suppressed = map[string]struct{}{}
			}
			suppressed[name] = struct{}{}
		}
	}

	if len(suppressed) == 0 {
		return out
	}
	kept := out[:0]
	for _, m := range out {
		if _, drop := suppressed[m.Rule]; !drop {
			kept = append(kept, m)
		}
	}
	return kept
}

// ruleMatches evaluates the when predicates and requires every counter axis
// to carry exactly one value: a bucket with nothing to key it is a rule that
// does not match — the mechanism by which per-client rules skip anonymous
// traffic — and a bucket with several candidate keys is an ambiguity the
// matcher refuses to resolve by guessing.
func ruleMatches(rule *compile.Rule, ctx *blockCtx) bool {
	for i := range rule.When {
		if !conditionHolds(&rule.When[i], ctx) {
			return false
		}
	}
	for _, axis := range rule.Counters {
		if len(ctx.valueOf(axis)) != 1 {
			return false
		}
	}
	return true
}

func conditionHolds(c *compile.Condition, ctx *blockCtx) bool {
	set := ctx.valueOf(c.Key)
	switch c.Operator {
	case model.OperatorEquals:
		return len(set) == 1 && set[0] == c.Value
	case model.OperatorIn, model.OperatorInGroup:
		for _, v := range set {
			if _, ok := c.Values[v]; ok {
				return true
			}
		}
		return false
	case model.OperatorContains:
		return slices.Contains(set, c.Value)
	case model.OperatorExists:
		return len(set) > 0
	case model.OperatorNotExists:
		return len(set) == 0
	}
	return false
}

func matchedRule(block *compile.Block, rule *compile.Rule, ctx *blockCtx) MatchedRule {
	axes := make([]string, len(rule.Counters))
	for i, axis := range rule.Counters {
		axes[i] = ctx.valueOf(axis)[0]
	}

	out := MatchedRule{
		Policy:  block.Policy,
		Block:   block.Name,
		Rule:    rule.Name,
		Shadow:  rule.Behavior == model.BehaviorShadow,
		Buckets: make([]store.Bucket, 0, len(rule.Rates)),
	}
	for i := range rule.Rates {
		rate := &rule.Rates[i]
		out.Buckets = append(out.Buckets, store.Bucket{
			Key:       key.Bucket(rate.Prefix, axes),
			Algorithm: rate.Algorithm.ID(),
			Window:    rate.Window,
			Shadow:    out.Shadow,
		})
	}
	return out
}
