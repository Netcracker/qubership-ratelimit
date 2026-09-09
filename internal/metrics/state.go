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
}

// DomainView carries a domain's capacity facts.
type DomainView struct {
	Domain string

	// Blocks is an observed number rather than a bounded one: the object size
	// keeps the linear target scan cheap on its own, so this series exists to
	// be watched, not to be enforced.
	Blocks int

	// DecisionBuckets is the worst case one request can collect across the
	// domain — the headroom before an edit stops compiling.
	DecisionBuckets int

	// AppliedGeneration is the generation this replica enforces for the
	// domain. Ready comes from the policy status, not from here; this series
	// is for alerting on a replica that falls behind.
	AppliedGeneration int64
}

// PolicyView is one policy's status as the compiler reported it.
type PolicyView struct {
	// Domain is the domain the policy serves, which under one policy per
	// domain is also the object's name. The series are labelled by it rather
	// than by namespace/name: the cache is scoped to one namespace, so the
	// prefix was the same on every series and carried nothing, while every
	// other series in this file already joins on the domain.
	Domain string

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

	// BlockingProblems and InfoProblems count the diagnostics of the latest
	// generation by severity. They are separate because they mean opposite
	// things to an alert: one blocking problem is a generation nobody
	// enforces, while an informational one is a note the author may have
	// meant.
	BlockingProblems int
	InfoProblems     int
}

// Severities of ratelimit_policy_rule_problems.
const (
	SeverityBlocking = "blocking"
	SeverityInfo     = "info"
)

// stateView holds the latest published view; nil until the first rebuild.
var stateView atomic.Pointer[StateView]

// PublishState makes a view the one the next scrape reports. The updater
// calls it after every successful rebuild.
func PublishState(view *StateView) { stateView.Store(view) }

var (
	descPolicyReady = prometheus.NewDesc("ratelimit_policy_ready",
		"Whether the latest generation of the policy is the one enforced; reason is empty when it is.",
		[]string{"domain", "reason"}, nil)
	descPolicyEnforced = prometheus.NewDesc("ratelimit_policy_enforced",
		"Whether any generation of the policy is enforced at all.",
		[]string{"domain"}, nil)
	descPolicyGenerationLag = prometheus.NewDesc("ratelimit_policy_generation_lag",
		"How far the enforced generation trails the latest one.",
		[]string{"domain"}, nil)
	descPolicyRuleProblems = prometheus.NewDesc("ratelimit_policy_rule_problems",
		"Rule diagnostics reported for the latest generation of the policy. "+
			"Severity blocking means the generation is not enforced; info is a note about one that is.",
		[]string{"domain", "severity"}, nil)
	descPolicyAppliedGeneration = prometheus.NewDesc("ratelimit_policy_applied_generation",
		"The generation of the domain this replica enforces.",
		[]string{"domain"}, nil)
	descDomainBlocks = prometheus.NewDesc("ratelimit_domain_blocks",
		"Compiled blocks of the domain. Observed rather than bounded: watch the target scan, do not cap it.",
		[]string{"domain"}, nil)
	descDomainBuckets = prometheus.NewDesc("ratelimit_domain_decision_buckets",
		"Worst-case buckets one request can collect across the domain, against the budget of 128.",
		[]string{"domain"}, nil)
)

// stateCollector renders the published StateView on every scrape.
type stateCollector struct{}

func (stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descPolicyReady
	ch <- descPolicyEnforced
	ch <- descPolicyGenerationLag
	ch <- descPolicyRuleProblems
	ch <- descPolicyAppliedGeneration
	ch <- descDomainBlocks
	ch <- descDomainBuckets
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
		ch <- prometheus.MustNewConstMetric(descPolicyAppliedGeneration,
			prometheus.GaugeValue, float64(d.AppliedGeneration), d.Domain)
	}
	for _, p := range view.Policies {
		ch <- prometheus.MustNewConstMetric(descPolicyReady,
			prometheus.GaugeValue, boolValue(p.Ready), p.Domain, p.Reason)
		ch <- prometheus.MustNewConstMetric(descPolicyEnforced,
			prometheus.GaugeValue, boolValue(p.Enforced), p.Domain)
		ch <- prometheus.MustNewConstMetric(descPolicyGenerationLag,
			prometheus.GaugeValue, float64(p.GenerationLag), p.Domain)
		// Both severities are reported even at zero: an alert on "no blocking
		// problems" needs the series to exist while the domain is healthy,
		// which is exactly when the count is zero.
		ch <- prometheus.MustNewConstMetric(descPolicyRuleProblems,
			prometheus.GaugeValue, float64(p.BlockingProblems), p.Domain, SeverityBlocking)
		ch <- prometheus.MustNewConstMetric(descPolicyRuleProblems,
			prometheus.GaugeValue, float64(p.InfoProblems), p.Domain, SeverityInfo)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
