package policy

import (
	"strconv"
	"time"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The engine never learns that Kubernetes exists — it takes plain model
// structures — so this file is the only place that knows both vocabularies.
//
// The enums are string-typed on both sides and carry the same values, which makes
// most of the conversion a rename rather than a translation. That is a deliberate
// coupling and a fragile one, so a test asserts the two vocabularies still agree
// rather than trusting them to.

// modelPolicy converts one policy spec. The name travels with it because the
// engine puts it in the counter key: the namespace of a block name is its policy.
func modelPolicy(name string, spec *v1alpha1.RateLimitPolicySpec) model.Policy {
	out := model.Policy{
		Name:   name,
		Domain: spec.Domain,
		Groups: modelGroups(spec.Groups),
		Blocks: make([]model.Block, 0, len(spec.Limits)),
	}

	for i := range spec.Limits {
		block := &spec.Limits[i]
		converted := model.Block{
			Name:  block.Name,
			Mode:  model.Mode(block.Mode),
			Rules: make([]model.Rule, 0, len(block.Rules)),
		}
		if block.Target != nil {
			converted.Target = model.Target{Routes: modelRoutes(block.Target.Routes)}
		}
		for j := range block.Rules {
			converted.Rules = append(converted.Rules, modelRule(&block.Rules[j]))
		}
		out.Blocks = append(out.Blocks, converted)
	}
	return out
}

func modelRoutes(routes []v1alpha1.Route) []model.Route {
	if len(routes) == 0 {
		return nil
	}
	out := make([]model.Route, 0, len(routes))
	for i := range routes {
		route := &routes[i]
		converted := model.Route{
			Path: model.PathMatch{
				Type:  model.PathType(route.Path.Type),
				Value: route.Path.Value,
			},
		}
		for _, method := range route.Methods {
			converted.Methods = append(converted.Methods, string(method))
		}
		out = append(out, converted)
	}
	return out
}

func modelRule(rule *v1alpha1.Rule) model.Rule {
	out := model.Rule{
		Name:     rule.Name,
		Counters: rule.Counters,
		Behavior: model.Behavior(rule.Behavior),
		Replaces: rule.Replaces,
	}
	for i := range rule.When {
		predicate := &rule.When[i]
		out.When = append(out.When, model.Condition{
			Key:      predicate.Key,
			Operator: model.Operator(predicate.Operator),
			Value:    predicate.Value,
			Values:   predicate.Values,
		})
	}
	for i := range rule.Rates {
		rate := &rule.Rates[i]
		converted := model.Rate{
			Requests:  int64(rate.Requests),
			Period:    modelPeriod(rate.Period),
			Algorithm: string(rate.Algorithm),
		}
		// A nil burst stays zero. The engine reads that as the documented
		// default — a full bucket — so spelling it out here would put the same
		// rule in two places.
		if rate.Burst != nil {
			converted.Burst = int64(*rate.Burst)
		}
		out.Rates = append(out.Rates, converted)
	}
	return out
}

// modelMapping converts the mapping of a domain. A nil spec is the domain running
// on its built-in keys, which the engine expects as a nil mapping.
func modelMapping(spec *v1alpha1.RateLimitMappingSpec) *model.Mapping {
	if spec == nil {
		return nil
	}
	out := &model.Mapping{
		Domain: spec.Domain,
		Groups: modelGroups(spec.Groups),
	}
	for i := range spec.Mappings {
		entry := &spec.Mappings[i]
		out.Mappings = append(out.Mappings, model.KeyMapping{
			Key:       entry.Key,
			Claim:     entry.Claim,
			ClaimPath: entry.ClaimPath,
			Type:      model.ValueType(entry.Type),
			Normalize: model.Normalize(entry.Normalize),
			Fallbacks: entry.Fallbacks,
		})
	}
	return out
}

func modelGroups(groups []v1alpha1.ClientGroup) []model.Group {
	if len(groups) == 0 {
		return nil
	}
	out := make([]model.Group, 0, len(groups))
	for i := range groups {
		out = append(out, model.Group{Name: groups[i].Name, Clients: groups[i].Clients})
	}
	return out
}

// modelPeriod reads a period written the way the CRD spells it: one count and one
// unit. time.ParseDuration is no help — it rejects the d suffix the schema accepts
// and accepts the compound forms it does not.
//
// A value that does not parse yields zero rather than an error. The schema already
// rejects every such value, and a zero period is one the engine reports as an
// invalid window, so the diagnosis stays in the one place that owns it.
func modelPeriod(period string) time.Duration {
	if len(period) < 2 {
		return 0
	}
	count, err := strconv.ParseInt(period[:len(period)-1], 10, 32)
	if err != nil || count < 1 {
		return 0
	}

	var unit time.Duration
	switch period[len(period)-1] {
	case 's':
		unit = time.Second
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	default:
		return 0
	}
	return time.Duration(count) * unit
}
