package management

import (
	"net/url"
	"slices"
	"sort"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
)

// Applicability answers the question an operator actually has when a client
// complains: which rules act on this client, and which could.
//
// A caller knows part of an identity, a client id and maybe a plan, and never
// the whole token. Against that partial identity every rule is annotated
// always (it applies for every completion of what is unknown), conditional (for
// some completions, and the gates say which), or never. The analysis lives here
// rather than in a client because it is the engine's cascade semantics: a rule
// can be unreachable because an earlier FirstMatch rule decides first, or
// because a narrow rule replaces it, and no amount of filtering over the
// rendered view reproduces that.
//
// Supplying more axes sharpens the answer monotonically: a gate a new value
// closes moves rules between the classes and never reopens.

// scope is a partial identity: what the caller supplied about one client.
type scope struct {
	// values are the supplied value sets. A list-valued key's set is complete, so
	// Contains and Exists decide against it, and a scalar key carries one value.
	values map[string][]string

	// declared marks every key the caller spoke about, including the ones
	// declared known-absent, whose value set is empty.
	declared map[string]struct{}

	// present is false when the caller supplied no identity at all, and then no
	// rule is annotated: an annotation without a question would be an assertion
	// about every possible client.
	present bool
}

// parseScope reads the identity scope out of a rules query.
//
// Names are validated against what the domain can actually carry: its effective
// keys plus the blocks' template captures. An unknown name is almost always a
// typo, and silently ignoring it would answer a question nobody asked with an
// authoritative-looking annotation.
func parseScope(snapshot *compile.Snapshot, query url.Values) (scope, *apiError) {
	valid := knownKeys(snapshot)
	listValued := make(map[string]struct{})
	for _, name := range ruleview.ListValuedKeys(snapshot) {
		listValued[name] = struct{}{}
	}

	sc := scope{values: map[string][]string{}, declared: map[string]struct{}{}}

	for parameter, raw := range query {
		name, found := cutAxisParameter(parameter)
		if !found {
			continue
		}
		if _, ok := valid[name]; !ok {
			return scope{}, invalid("no identity key "+logSafe(name)+" is declared in domain "+
				logSafe(snapshot.Domain), parameter)
		}
		values := sortedUnique(raw)
		if slices.Contains(values, "") {
			return scope{}, invalid("axis "+logSafe(name)+" has an empty value; declare the key "+
				"known-absent with absent="+logSafe(name)+" instead", parameter)
		}
		if _, isList := listValued[name]; !isList && len(values) > 1 {
			return scope{}, invalid("identity key "+logSafe(name)+
				" is scalar, so one caller carries exactly one value for it", parameter)
		}
		sc.values[name] = values
		sc.declared[name] = struct{}{}
		sc.present = true
	}

	for _, name := range query["absent"] {
		if _, ok := valid[name]; !ok {
			return scope{}, invalid("no identity key "+logSafe(name)+" is declared in domain "+
				logSafe(snapshot.Domain), "absent")
		}
		if _, supplied := sc.values[name]; supplied {
			return scope{}, invalid("identity key "+logSafe(name)+
				" is declared both known-absent and with a value", "absent")
		}
		// An empty value set is exactly how the engine reads a missing key, so
		// known-absent is representable rather than special-cased.
		sc.values[name] = nil
		sc.declared[name] = struct{}{}
		sc.present = true
	}
	return sc, nil
}

// cutAxisParameter recognizes the dynamic axis family.
func cutAxisParameter(parameter string) (string, bool) {
	if len(parameter) <= len(axisPrefix) || parameter[:len(axisPrefix)] != axisPrefix {
		return "", false
	}
	return parameter[len(axisPrefix):], true
}

// knownKeys is every identity key name this domain can carry: the domain-wide
// effective keys, the built-in request keys, and every block's captures.
func knownKeys(snapshot *compile.Snapshot) map[string]struct{} {
	out := map[string]struct{}{
		model.KeyPath:   {},
		model.KeyMethod: {},
	}
	for _, name := range snapshot.EffectiveKeys {
		out[name] = struct{}{}
	}
	for i := range snapshot.Blocks {
		for _, capture := range snapshot.Blocks[i].Captures {
			out[capture] = struct{}{}
		}
	}
	return out
}

// state is a three-valued answer: a condition or an axis that the supplied
// identity decides one way, decides the other way, or leaves open.
type state int

const (
	stateFailed state = iota
	stateSatisfied
	stateUndecided
)

// keyValues is what the scope says about one key.
type keyValues struct {
	// known marks a value set the caller pinned down, including the empty set of
	// a known-absent key.
	known  bool
	values []string

	// nonEmpty marks a key whose presence is guaranteed even though its value
	// is not known: a block's template captures are produced by any request
	// that reaches the route.
	nonEmpty bool
}

func (s scope) lookup(block *compile.Block, name string) keyValues {
	if values, ok := s.values[name]; ok {
		return keyValues{known: true, values: values}
	}
	if name == model.KeyPath || name == model.KeyMethod {
		// Every request carries a path and a method; their values are the
		// caller's route question, not their identity question.
		return keyValues{nonEmpty: true}
	}
	if slices.Contains(block.Captures, name) {
		return keyValues{nonEmpty: true}
	}
	return keyValues{}
}

// annotate fills the applicability annotations of one rendered block.
func annotate(block *compile.Block, view *ruleview.BlockView, sc scope) {
	base := make([]state, len(block.Rules))
	gates := make([][]ruleview.ApplicabilityGate, len(block.Rules))
	for i := range block.Rules {
		base[i], gates[i] = evaluateRule(block, &block.Rules[i], sc)
	}

	for i := range block.Rules {
		verdict, conditionalOn := preempt(block, base, gates, i)
		view.Rules[i].Applicability = verdict
		view.Rules[i].ConditionalOn = conditionalOn
	}
}

// evaluateRule judges one rule against the scope, ignoring the other rules of
// its block.
func evaluateRule(block *compile.Block, rule *compile.Rule, sc scope) (state, []ruleview.ApplicabilityGate) {
	var (
		gates     []ruleview.ApplicabilityGate
		undecided = map[string]struct{}{}
	)

	for i := range rule.When {
		condition := &rule.When[i]
		switch conditionState(block, condition, sc) {
		case stateFailed:
			return stateFailed, nil
		case stateUndecided:
			if _, already := undecided[condition.Key]; !already {
				undecided[condition.Key] = struct{}{}
				gates = append(gates, ruleview.ApplicabilityGate{
					Reason: ruleview.GateUndecidedCondition, Key: condition.Key,
				})
			}
		}
	}

	for _, axis := range rule.Counters {
		values := sc.lookup(block, axis)
		switch {
		case values.known && len(values.values) == 1:
			// The axis takes exactly the one value the caller named.
		case values.known:
			// A known-absent key, or a set the matcher cannot key a bucket by:
			// this rule counts by something this client can never produce.
			return stateFailed, nil
		case values.nonEmpty:
			// A capture, or a built-in: any request reaching this block has it.
		default:
			// The axis stays open. A condition already reported on the same key
			// stands for both, since deciding the condition decides the axis, so
			// the gates say each thing once.
			if _, sameKey := undecided[axis]; !sameKey {
				gates = append(gates, ruleview.ApplicabilityGate{
					Reason: ruleview.GateMissingAxis, Key: axis,
				})
			}
		}
	}

	if len(gates) > 0 {
		return stateUndecided, gates
	}
	return stateSatisfied, nil
}

// conditionState evaluates one compiled condition against the scope, with the
// same set semantics the matcher uses: a key's value is a set, and an absent
// key is the empty set.
func conditionState(block *compile.Block, condition *compile.Condition, sc scope) state {
	values := sc.lookup(block, condition.Key)

	if !values.known {
		// Presence alone decides the unary operators, and nothing else.
		if values.nonEmpty {
			switch condition.Operator {
			case model.OperatorExists:
				return stateSatisfied
			case model.OperatorNotExists:
				return stateFailed
			}
		}
		return stateUndecided
	}

	set := values.values
	switch condition.Operator {
	case model.OperatorEquals:
		return boolState(len(set) == 1 && set[0] == condition.Value)
	case model.OperatorIn, model.OperatorInGroup:
		for _, value := range set {
			if _, ok := condition.Values[value]; ok {
				return stateSatisfied
			}
		}
		return stateFailed
	case model.OperatorContains:
		return boolState(slices.Contains(set, condition.Value))
	case model.OperatorExists:
		return boolState(len(set) > 0)
	case model.OperatorNotExists:
		return boolState(len(set) == 0)
	}
	return stateUndecided
}

func boolState(ok bool) state {
	if ok {
		return stateSatisfied
	}
	return stateFailed
}

// preempt folds in the effect of the block's other rules: a FirstMatch cascade
// where an earlier rule decides, and a replaces that silences this one.
func preempt(
	block *compile.Block,
	base []state,
	gates [][]ruleview.ApplicabilityGate,
	i int,
) (string, []ruleview.ApplicabilityGate) {
	if base[i] == stateFailed {
		return ruleview.ApplicabilityNever, nil
	}

	conditionalOn := gates[i]
	for _, j := range preemptors(block, i) {
		switch base[j] {
		case stateSatisfied:
			// The other rule matches for every completion, so this one is
			// reached for none.
			return ruleview.ApplicabilityNever, nil
		case stateUndecided:
			conditionalOn = append(conditionalOn, ruleview.ApplicabilityGate{
				Reason: ruleview.GateMayBePreempted,
				Rule:   ruleview.ID(block.Policy, block.Name, block.Rules[j].Name),
			})
		}
	}

	if len(conditionalOn) > 0 {
		return ruleview.ApplicabilityConditional, conditionalOn
	}
	return ruleview.ApplicabilityAlways, nil
}

// preemptors lists the rules of the block that can keep rule i from applying.
//
// In a FirstMatch cascade that is every earlier rule that decides. Shadow rules
// count and report without stopping the walk, so they preempt nothing, while
// bypass ends it. In an All block it is every rule that names this one in its
// replaces.
func preemptors(block *compile.Block, i int) []int {
	var out []int
	if block.Mode == model.ModeFirstMatch {
		for j := range i {
			if block.Rules[j].Behavior == model.BehaviorShadow {
				continue
			}
			out = append(out, j)
		}
		return out
	}
	for j := range block.Rules {
		if j == i {
			continue
		}
		if slices.Contains(block.Rules[j].Replaces, block.Rules[i].Name) {
			out = append(out, j)
		}
	}
	sort.Ints(out)
	return out
}
