package policy

import (
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

// modelPolicy converts one policy spec, which is the whole of a domain.
func modelPolicy(spec *v1alpha1.RateLimitPolicySpec) *model.Policy {
	if spec == nil {
		return nil
	}
	out := &model.Policy{
		Domain:   spec.Domain,
		Mappings: modelMappings(spec.Mappings),
		Groups:   modelGroups(spec.Groups),
		Blocks:   make([]model.Block, 0, len(spec.Limits)),
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
		Name:          rule.Name,
		Counters:      rule.Counters,
		Behavior:      model.Behavior(rule.Behavior),
		ReplacedRules: rule.ReplacedRules,
	}
	for i := range rule.Matches {
		predicate := &rule.Matches[i]
		out.Matches = append(out.Matches, model.Predicate{
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
			Period:    time.Duration(rate.PeriodSeconds) * time.Second,
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

func modelMappings(mappings []v1alpha1.ClaimMapping) []model.KeyMapping {
	if len(mappings) == 0 {
		return nil
	}
	out := make([]model.KeyMapping, 0, len(mappings))
	for i := range mappings {
		entry := &mappings[i]
		out = append(out, model.KeyMapping{
			Key:           entry.Key,
			Claim:         entry.Claim,
			ClaimPath:     entry.ClaimPath,
			Type:          model.ValueType(entry.Type),
			Normalization: model.Normalize(entry.Normalization),
			Fallbacks:     entry.Fallbacks,
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
