// Package ruleview renders a compiled domain the way the management API
// reports it, and derives that rendering's version.
//
// It sits below the API rather than inside it because the version is computed
// where snapshots are swapped: the hash is of exactly this rendering, so the
// renderer and the hash cannot live apart without one of them drifting.
package ruleview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// Runtime mode vocabulary. It is lowercase and shared by every runtime view
// (rules, counters, outcomes), while BlockView.Mode and RouteView.Type keep the
// custom resource's own spelling, because those views report configuration.
const (
	ModeEnforce = "enforce"
	ModeShadow  = "shadow"
	ModeBypass  = "bypass"
)

// Applicability classes for a listing scoped by a partial identity.
const (
	ApplicabilityAlways      = "always"
	ApplicabilityConditional = "conditional"
	ApplicabilityNever       = "never"
)

// DomainSummary is one row of the domain index: enough to render a list
// without fetching a rule set per domain.
type DomainSummary struct {
	Domain string `json:"domain"`

	// RuleSetVersion is this domain's enforced-set identity, the same value
	// GET /rules reports.
	RuleSetVersion string `json:"ruleSetVersion"`

	Policies int `json:"policies"`
	Blocks   int `json:"blocks"`
	Rules    int `json:"rules"`

	EffectiveKeys  []string `json:"effectiveKeys"`
	ListValuedKeys []string `json:"listValuedKeys,omitempty"`
}

// RuleSetView is the compiled rule set of one domain: what the decision path
// enforces, which is not the sum of the policy objects. A policy the operator
// rejected has objects in the namespace and no rules here, and a policy running
// on its last-good spec shows the spec being enforced rather than the one last
// submitted.
type RuleSetView struct {
	Domain string `json:"domain"`

	// RuleSetVersion identifies this domain's enforced set and changes only
	// when that set changes. The addressed DELETE takes it as
	// expectedRuleSetVersion to refuse acting on a set nobody looked at.
	RuleSetVersion string `json:"ruleSetVersion"`

	EffectiveKeys []string `json:"effectiveKeys"`

	// ListValuedKeys are the keys whose value is a set, such as the roles array
	// claim. They never appear in rule axes, since counters key by scalars, but
	// conditions read them and the applicability scope accepts them as
	// repeatable parameters forming a complete set.
	ListValuedKeys []string `json:"listValuedKeys,omitempty"`

	Blocks []BlockView `json:"blocks"`
}

// BlockView is one compiled limits block: the routes and the rules sharing
// them.
type BlockView struct {
	Policy string `json:"policy"`
	Block  string `json:"block"`

	// Mode is All or FirstMatch, spelled as the custom resource spells it.
	Mode string `json:"mode"`

	Routes []RouteView `json:"routes"`

	// Captures are the template placeholder names of this block's routes:
	// block-scoped identity keys its rules may count by, and no other block's.
	Captures []string `json:"captures,omitempty"`

	Rules []RuleView `json:"rules"`
}

// RouteView is one compiled route matcher.
type RouteView struct {
	Type  string `json:"type"`
	Value string `json:"value"`

	// Methods is absent when the route accepts any method.
	Methods []string `json:"methods,omitempty"`
}

// RuleView is one compiled rule with its mode, axes, conditions, and windows.
type RuleView struct {
	// ID is policy/block/rule, the identity counters, metrics, and the audit
	// stream share, so a rule round-trips from this listing into a reset without
	// being reassembled.
	ID string `json:"id"`

	Policy string `json:"policy"`
	Block  string `json:"block"`
	Rule   string `json:"rule"`

	// Mode is the single runtime mode field; there is no second boolean to
	// contradict it.
	Mode string `json:"mode"`

	// Axes are the identity keys this rule counts separately by, in the order
	// the counter key carries them. The addressed DELETE requires one value for
	// every one of them.
	Axes []string `json:"axes"`

	When []ConditionView `json:"when,omitempty"`

	// Replaces names the rules of the same block this rule silences when it
	// matches: the narrow rule suppressing the wide one.
	Replaces []string `json:"replaces,omitempty"`

	Rates []RateView `json:"rates"`

	// Applicability and ConditionalOn are annotations of a scoped listing. They
	// are a property of the question, not of the rule set, which is why the
	// version below is computed over a view that carries neither.
	Applicability string              `json:"applicability,omitempty"`
	ConditionalOn []ApplicabilityGate `json:"conditionalOn,omitempty"`
}

// ApplicabilityGate is one reason a rule is only conditionally applicable to
// the supplied partial identity.
type ApplicabilityGate struct {
	Reason string `json:"reason"`

	// Key carries the missing_axis and undecided_condition gates; Rule carries
	// may_be_preempted.
	Key  string `json:"key,omitempty"`
	Rule string `json:"rule,omitempty"`
}

// Gate reasons.
const (
	GateMissingAxis        = "missing_axis"
	GateUndecidedCondition = "undecided_condition"
	GateMayBePreempted     = "may_be_preempted"
)

// ConditionView is one compiled when predicate. Group indirection ends at
// compile time: an InGroup renders as In with the group resolved into the value
// set, so what is reported is the set the rule actually tests.
type ConditionView struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`

	// Value serves Equals and Contains; Values serves In. The unary operators
	// carry neither, mirroring the engine's arity check.
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

// RateView is one window of a rule. PeriodSeconds is canonical and Period is
// the same number rendered for a reader.
type RateView struct {
	Algorithm string `json:"algorithm"`

	Requests      int64  `json:"requests"`
	PeriodSeconds int64  `json:"periodSeconds"`
	Period        string `json:"period"`

	// Burst is the momentary allowance above the steady rate, on the
	// algorithms that have one.
	Burst int64 `json:"burst,omitempty"`
}

// Summary counts a snapshot for the domain index.
func Summary(snapshot *compile.Snapshot, version string) DomainSummary {
	summary := DomainSummary{
		Domain:         snapshot.Domain,
		RuleSetVersion: version,
		Blocks:         len(snapshot.Blocks),
		EffectiveKeys:  nonNil(snapshot.EffectiveKeys),
		ListValuedKeys: ListValuedKeys(snapshot),
	}
	policies := make(map[string]struct{}, len(snapshot.Blocks))
	for i := range snapshot.Blocks {
		policies[snapshot.Blocks[i].Policy] = struct{}{}
		summary.Rules += len(snapshot.Blocks[i].Rules)
	}
	summary.Policies = len(policies)
	return summary
}

// Render renders a whole snapshot, unannotated and without a version. Both are
// added by the caller: the version because it is computed once at the swap, the
// annotations because they answer a question this package was not asked.
func Render(snapshot *compile.Snapshot) RuleSetView {
	view := RuleSetView{
		Domain:         snapshot.Domain,
		EffectiveKeys:  nonNil(snapshot.EffectiveKeys),
		ListValuedKeys: ListValuedKeys(snapshot),
		Blocks:         make([]BlockView, 0, len(snapshot.Blocks)),
	}
	for i := range snapshot.Blocks {
		view.Blocks = append(view.Blocks, Block(&snapshot.Blocks[i]))
	}
	return view
}

// Block renders one compiled block.
func Block(block *compile.Block) BlockView {
	mode := block.Mode
	if mode == "" {
		mode = model.ModeAll
	}
	view := BlockView{
		Policy:   block.Policy,
		Block:    block.Name,
		Mode:     string(mode),
		Captures: block.Captures,
		Routes:   make([]RouteView, 0, len(block.Routes)),
		Rules:    make([]RuleView, 0, len(block.Rules)),
	}
	for i := range block.Routes {
		view.Routes = append(view.Routes, route(&block.Routes[i]))
	}
	for i := range block.Rules {
		view.Rules = append(view.Rules, Rule(block, &block.Rules[i]))
	}
	return view
}

func route(r *compile.Route) RouteView {
	view := RouteView{Type: string(r.Type), Value: r.Value}
	if len(r.Methods) > 0 {
		view.Methods = sortedKeys(r.Methods)
	}
	return view
}

// Rule renders one compiled rule.
func Rule(block *compile.Block, rule *compile.Rule) RuleView {
	view := RuleView{
		ID:       ID(block.Policy, block.Name, rule.Name),
		Policy:   block.Policy,
		Block:    block.Name,
		Rule:     rule.Name,
		Mode:     Mode(rule.Behavior),
		Axes:     nonNil(rule.Counters),
		Replaces: rule.Replaces,
		Rates:    make([]RateView, 0, len(rule.Rates)),
	}
	for i := range rule.When {
		view.When = append(view.When, condition(&rule.When[i]))
	}
	for i := range rule.Rates {
		view.Rates = append(view.Rates, Rate(&rule.Rates[i]))
	}
	return view
}

func condition(c *compile.Condition) ConditionView {
	// A compiled InGroup is an In whose group is already resolved; reporting
	// the group name would name something no longer consulted at decision time.
	operator := c.Operator
	if operator == model.OperatorInGroup {
		operator = model.OperatorIn
	}
	view := ConditionView{Key: c.Key, Operator: string(operator)}
	switch operator {
	case model.OperatorEquals, model.OperatorContains:
		view.Value = c.Value
	case model.OperatorIn:
		view.Values = sortedKeys(c.Values)
	}
	return view
}

// Rate renders one window.
func Rate(rate *compile.Rate) RateView {
	return RateView{
		Algorithm:     Algorithm(rate),
		Requests:      rate.Window.Requests,
		PeriodSeconds: int64(rate.Window.Period / time.Second),
		Period:        rate.Window.Period.String(),
		Burst:         rate.Window.Burst,
	}
}

// Algorithm renders a rate's algorithm the way the counter key spells it, so a
// value read out of a key and a value read out of a view compare equal.
func Algorithm(rate *compile.Rate) string {
	return strings.ToLower(rate.Algorithm.Name())
}

// Mode renders a behavior in the runtime vocabulary.
func Mode(behavior model.Behavior) string {
	switch behavior {
	case model.BehaviorShadow:
		return ModeShadow
	case model.BehaviorBypass:
		return ModeBypass
	default:
		return ModeEnforce
	}
}

// ListValuedKeys lists the domain's array-valued identity keys, sorted.
func ListValuedKeys(snapshot *compile.Snapshot) []string {
	var out []string
	for _, extraction := range snapshot.Extraction {
		if extraction.Type == model.ValueStringArray {
			out = append(out, extraction.Key)
		}
	}
	sort.Strings(out)
	return out
}

// Version is the identity of one domain's enforced rule set: a content hash of
// exactly the rendering above.
//
// Hashing the rendering rather than the objects behind it is what makes the
// value mean what a reader thinks it means. A domain is assembled from several
// custom resources, so there is no single generation to quote; annotations,
// resource versions, and the order objects arrived in are not part of what is
// enforced, and neither are other domains. What remains is a pure function of
// the enforced set: blocks in compiled order, their rules, routes, conditions
// with sorted value sets, windows, and the domain's key set. Two replicas
// serving the same rules therefore report the same version, a restart reports
// the same version, and a last-good generation is hashed for what it actually
// serves.
//
// The applicability annotations stay out by construction: Render never sets
// them, and they answer a request rather than describe the set.
func Version(snapshot *compile.Snapshot) string {
	// The view is JSON with no maps left in it, since every set was sorted into a
	// slice on the way in, so the encoding is a deterministic function of the
	// snapshot rather than of Go's map iteration.
	canonical, err := json.Marshal(Render(snapshot))
	if err != nil {
		// The view is this package's own struct tree of strings, numbers, and
		// slices; nothing in it can fail to marshal.
		panic("ruleview: the rule set view failed to marshal: " + err.Error())
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])[:12]
}

// ID joins the triple that identifies a rule within a domain.
func ID(policy, block, rule string) string {
	return policy + "/" + block + "/" + rule
}

// SplitID takes a rule id apart. The parts cannot contain a slash: they are
// resource names, which the schema constrains to a DNS label.
func SplitID(id string) (policy, block, rule string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
