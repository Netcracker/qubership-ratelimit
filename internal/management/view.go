package management

import (
	"sort"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// DomainSummary is one row of the domain list: enough to render an index
// without fetching every rule set.
type DomainSummary struct {
	Domain string `json:"domain"`

	Policies int `json:"policies"`
	Blocks   int `json:"blocks"`
	Rules    int `json:"rules"`

	// EffectiveKeys are the identity keys this domain can limit by — the
	// built-ins plus whatever its RateLimitMapping declares. A client
	// composing a rule needs the list, and so does anyone reading one.
	EffectiveKeys []string `json:"effectiveKeys"`
}

// RuleSetView is the effective rule set of one domain: what the engine is
// deciding with right now, which is not the same as the sum of the policy
// objects. A policy the operator rejected has objects in the namespace and no
// rules here, and a policy running on its last-good spec shows the spec being
// enforced rather than the one last submitted.
type RuleSetView struct {
	Domain        string      `json:"domain"`
	EffectiveKeys []string    `json:"effectiveKeys"`
	Blocks        []BlockView `json:"blocks"`
}

// BlockView is one compiled limits block.
type BlockView struct {
	Policy string `json:"policy"`
	Block  string `json:"block"`

	// Mode decides whether every matching rule applies or only the first.
	Mode string `json:"mode"`

	Routes []RouteView `json:"routes"`

	// Captures are the template placeholders this block's routes bind, usable
	// as axis names by its rules and by no others.
	Captures []string `json:"captures,omitempty"`

	Rules []RuleView `json:"rules"`
}

// RouteView is one compiled route matcher.
type RouteView struct {
	Type  string `json:"type"`
	Value string `json:"value"`

	// Methods is empty when the route matches any method.
	Methods []string `json:"methods,omitempty"`
}

// RuleView is one compiled rule.
type RuleView struct {
	// ID is the rule's identity within the domain, "policy/block/rule". It is
	// what the counter key carries and what a reset request names, so a client
	// can round-trip a rule from a list to a reset without reassembling it.
	ID string `json:"id"`

	Policy string `json:"policy"`
	Block  string `json:"block"`
	Rule   string `json:"rule"`

	// Behavior is Enforce, Shadow, or Bypass. Shadow counts and reports
	// without refusing, which is why a shadow rule can show a limited counter
	// and admit traffic at the same time.
	Behavior string `json:"behavior"`
	Shadow   bool   `json:"shadow"`

	// Axes are the identity keys this rule counts separately by, in the order
	// the counter key carries them. The order is part of the contract: a
	// partial reset can only name a leading run of these, because a key is
	// addressed by prefix.
	Axes []string `json:"axes"`

	When     []ConditionView `json:"when,omitempty"`
	Rates    []RateView      `json:"rates"`
	Replaces []string        `json:"replaces,omitempty"`
}

// ConditionView is one when predicate, with group indirection already
// resolved: what is reported is the client set the rule actually tests, not
// the group name it was written with.
type ConditionView struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`

	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

// RateView is one window of a rule.
type RateView struct {
	Algorithm string `json:"algorithm"`

	Requests      int64 `json:"requests"`
	PeriodSeconds int64 `json:"periodSeconds"`

	// Period is the same window as a duration string, so a client can show
	// "1h" without formatting seconds itself.
	Period string `json:"period"`

	// Burst is the momentary allowance above the steady rate, on the
	// algorithms that have one.
	Burst int64 `json:"burst,omitempty"`
}

// domainSummary counts a snapshot for the index.
func domainSummary(snapshot *compile.Snapshot) DomainSummary {
	summary := DomainSummary{
		Domain:        snapshot.Domain,
		Blocks:        len(snapshot.Blocks),
		EffectiveKeys: nonNil(snapshot.EffectiveKeys),
	}
	policies := make(map[string]struct{}, len(snapshot.Blocks))
	for i := range snapshot.Blocks {
		policies[snapshot.Blocks[i].Policy] = struct{}{}
		summary.Rules += len(snapshot.Blocks[i].Rules)
	}
	summary.Policies = len(policies)
	return summary
}

// ruleSetView renders a whole snapshot.
func ruleSetView(snapshot *compile.Snapshot) RuleSetView {
	view := RuleSetView{
		Domain:        snapshot.Domain,
		EffectiveKeys: nonNil(snapshot.EffectiveKeys),
		Blocks:        make([]BlockView, 0, len(snapshot.Blocks)),
	}
	for i := range snapshot.Blocks {
		view.Blocks = append(view.Blocks, blockView(&snapshot.Blocks[i]))
	}
	return view
}

func blockView(block *compile.Block) BlockView {
	view := BlockView{
		Policy:   block.Policy,
		Block:    block.Name,
		Mode:     string(block.Mode),
		Captures: block.Captures,
		Routes:   make([]RouteView, 0, len(block.Routes)),
		Rules:    make([]RuleView, 0, len(block.Rules)),
	}
	for i := range block.Routes {
		view.Routes = append(view.Routes, routeView(&block.Routes[i]))
	}
	for i := range block.Rules {
		view.Rules = append(view.Rules, ruleView(block, &block.Rules[i]))
	}
	return view
}

func routeView(route *compile.Route) RouteView {
	view := RouteView{Type: string(route.Type), Value: route.Value}
	if len(route.Methods) > 0 {
		view.Methods = sortedKeys(route.Methods)
	}
	return view
}

func ruleView(block *compile.Block, rule *compile.Rule) RuleView {
	view := RuleView{
		ID:       ruleID(block.Policy, block.Name, rule.Name),
		Policy:   block.Policy,
		Block:    block.Name,
		Rule:     rule.Name,
		Behavior: string(rule.Behavior),
		Shadow:   rule.Behavior == model.BehaviorShadow,
		Axes:     nonNil(rule.Counters),
		Replaces: rule.Replaces,
		Rates:    make([]RateView, 0, len(rule.Rates)),
	}
	for i := range rule.When {
		view.When = append(view.When, conditionView(&rule.When[i]))
	}
	for i := range rule.Rates {
		view.Rates = append(view.Rates, rateView(&rule.Rates[i]))
	}
	return view
}

func conditionView(condition *compile.Condition) ConditionView {
	view := ConditionView{
		Key:      condition.Key,
		Operator: string(condition.Operator),
		Value:    condition.Value,
	}
	if len(condition.Values) > 0 {
		view.Values = sortedKeys(condition.Values)
	}
	return view
}

func rateView(rate *compile.Rate) RateView {
	return RateView{
		Algorithm:     rate.Algorithm.Name(),
		Requests:      rate.Window.Requests,
		PeriodSeconds: int64(rate.Window.Period / time.Second),
		Period:        rate.Window.Period.String(),
		Burst:         rate.Window.Burst,
	}
}

// ruleID joins the triple that identifies a rule within a domain.
func ruleID(policy, block, rule string) string {
	return policy + "/" + block + "/" + rule
}

// splitRuleID takes an id apart. The parts cannot contain a slash: they are
// resource names, which the CRD schema constrains to a DNS label.
func splitRuleID(id string) (policy, block, rule string, ok bool) {
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
