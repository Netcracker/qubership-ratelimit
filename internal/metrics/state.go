package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// StateView is one rebuild's status, distilled for the scrape-time collector.
// The collector emits only the series the current view holds, which is what
// makes label churn safe: a policy that turns ready, changes its reason, or
// disappears leaves no stale series behind — the fate a plain GaugeVec cannot
// avoid.
type StateView struct {
	Domains  []DomainView
	Policies []PolicyView
	Mappings []MappingView
}

// DomainView carries a domain's capacity facts against the reference bounds.
type DomainView struct {
	Domain string

	// Blocks and DecisionBuckets are the numbers the domain gate compares
	// with the reference bounds — the headroom before edits start being
	// rejected.
	Blocks          int
	DecisionBuckets int
}

// PolicyView is one policy's status as the compiler reported it.
type PolicyView struct {
	// Policy is the namespace/name key of the object.
	Policy string

	// Ready reports whether the latest generation is the one enforced;
	// Reason names why not, empty when ready.
	Ready  bool
	Reason string

	// Enforced reports whether anything of this policy runs at all —
	// distinguishing "an old generation keeps running" from "nothing does".
	Enforced bool

	// GenerationLag is how far the enforced generation trails the latest
	// one; zero when the latest is enforced.
	GenerationLag int64

	// RuleProblems counts the diagnostics of the latest generation.
	RuleProblems int

	// Buckets is this policy's worst-case share of the domain budget — the
	// number that says which neighbor to shrink when the gate refuses an
	// edit.
	Buckets int
}

// MappingView is one mapping's status.
type MappingView struct {
	// Mapping is the namespace/name key of the object.
	Mapping string
	Ready   bool
}

// stateView holds the latest published view; nil until the first rebuild.
var stateView atomic.Pointer[StateView]

// PublishState makes a view the one the next scrape reports. The updater
// calls it after every successful rebuild.
func PublishState(view *StateView) { stateView.Store(view) }

var (
	descPolicyReady = prometheus.NewDesc("ratelimit_policy_ready",
		"Whether the latest generation of the policy is the one enforced; reason is empty when it is.",
		[]string{"policy", "reason"}, nil)
	descPolicyEnforced = prometheus.NewDesc("ratelimit_policy_enforced",
		"Whether any generation of the policy is enforced at all.",
		[]string{"policy"}, nil)
	descPolicyGenerationLag = prometheus.NewDesc("ratelimit_policy_generation_lag",
		"How far the enforced generation trails the latest one.",
		[]string{"policy"}, nil)
	descPolicyRuleProblems = prometheus.NewDesc("ratelimit_policy_rule_problems",
		"Rule diagnostics reported for the latest generation of the policy.",
		[]string{"policy"}, nil)
	descPolicyBuckets = prometheus.NewDesc("ratelimit_policy_buckets",
		"Worst-case decision buckets this policy contributes to its domain budget.",
		[]string{"policy"}, nil)
	descDomainBlocks = prometheus.NewDesc("ratelimit_domain_blocks",
		"Compiled blocks of the domain, against the reference bound of 256.",
		[]string{"domain"}, nil)
	descDomainBuckets = prometheus.NewDesc("ratelimit_domain_decision_buckets",
		"Worst-case buckets one request can collect across the domain, against the runtime backstop of 128.",
		[]string{"domain"}, nil)
	descMappingReady = prometheus.NewDesc("ratelimit_mapping_ready",
		"Whether the latest generation of the mapping is the one enforced.",
		[]string{"mapping"}, nil)
)

// stateCollector renders the published StateView on every scrape.
type stateCollector struct{}

func (stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descPolicyReady
	ch <- descPolicyEnforced
	ch <- descPolicyGenerationLag
	ch <- descPolicyRuleProblems
	ch <- descPolicyBuckets
	ch <- descDomainBlocks
	ch <- descDomainBuckets
	ch <- descMappingReady
}

func (stateCollector) Collect(ch chan<- prometheus.Metric) {
	view := stateView.Load()
	if view == nil {
		return
	}
	for _, d := range view.Domains {
		ch <- prometheus.MustNewConstMetric(descDomainBlocks,
			prometheus.GaugeValue, float64(d.Blocks), d.Domain)
		ch <- prometheus.MustNewConstMetric(descDomainBuckets,
			prometheus.GaugeValue, float64(d.DecisionBuckets), d.Domain)
	}
	for _, p := range view.Policies {
		ch <- prometheus.MustNewConstMetric(descPolicyReady,
			prometheus.GaugeValue, boolValue(p.Ready), p.Policy, p.Reason)
		ch <- prometheus.MustNewConstMetric(descPolicyEnforced,
			prometheus.GaugeValue, boolValue(p.Enforced), p.Policy)
		ch <- prometheus.MustNewConstMetric(descPolicyGenerationLag,
			prometheus.GaugeValue, float64(p.GenerationLag), p.Policy)
		ch <- prometheus.MustNewConstMetric(descPolicyRuleProblems,
			prometheus.GaugeValue, float64(p.RuleProblems), p.Policy)
		ch <- prometheus.MustNewConstMetric(descPolicyBuckets,
			prometheus.GaugeValue, float64(p.Buckets), p.Policy)
	}
	for _, m := range view.Mappings {
		ch <- prometheus.MustNewConstMetric(descMappingReady,
			prometheus.GaugeValue, boolValue(m.Ready), m.Mapping)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
