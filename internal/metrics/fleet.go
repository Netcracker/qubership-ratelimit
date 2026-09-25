package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// The series in this file are the operator's, not the service replica's.
//
// The domain view in state.go is published by the service's applier, which
// runs on every replica and reports what that replica enforces. What is here
// can only be known by the operator pod holding the Lease: how many replicas
// enforce a generation, and whether a domain has been stuck long enough to
// say so. RegisterOperator alone puts them on a registry, so the service's
// scrape carries none of them, and on the operator pod that lost the
// election they read as an absent fleet and a leader of 0, which is what
// ratelimit_leader is for: it tells a query which scrape is the one carrying
// them.

// FleetSample is what the operator saw for one domain on its last reconcile.
type FleetSample struct {
	// Applied and Total are the fraction the status reports.
	Applied int32
	Total   int32

	// Stalled reports whether the domain is stuck rather than progressing,
	// and Reason names which of the two ways it is stuck. Reason is set even
	// when Stalled is false, where it is the reason of the negative condition.
	//
	// The series keeps one label set per domain: the value of reason follows
	// the condition, so a recovered domain reports Progressing at 0 and its
	// ReplicaStale series stops being emitted and goes stale. A query on
	// max(ratelimit_policy_stalled) is unaffected; one on a specific reason
	// sees that series disappear rather than drop to zero.
	Stalled bool
	Reason  string
}

var (
	fleetMu     sync.RWMutex
	fleetSample = map[string]FleetSample{}

	// leader is set once this operator pod takes the Lease. It is never
	// unset: controller-runtime ends the process when a held Lease is lost,
	// so a pod that stops holding it stops scraping too.
	leader atomic.Bool
)

// PublishFleet records what the operator saw for one domain.
func PublishFleet(domain string, sample FleetSample) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	fleetSample[domain] = sample
}

// DropFleet forgets a domain. Without it the series of a deleted policy would
// keep being scraped from this pod for as long as it held the Lease,
// and an alert on a stalled domain would fire forever on an object nobody can
// fix because it is gone.
func DropFleet(domain string) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	delete(fleetSample, domain)
}

// SetLeader records whether this operator pod holds the Lease.
func SetLeader(held bool) { leader.Store(held) }

// Replica states of ratelimit_policy_replicas.
const (
	ReplicasApplied = "applied"
	ReplicasTotal   = "total"
)

var (
	descLeader = prometheus.NewDesc("ratelimit_leader",
		"Whether this operator pod holds the Lease. The status series are only written by the pod reporting 1.",
		nil, nil)
	descPolicyStalled = prometheus.NewDesc("ratelimit_policy_stalled",
		"Whether the domain is stuck rather than progressing; reason names which way.",
		[]string{"domain", "reason"}, nil)
	descPolicyReplicas = prometheus.NewDesc("ratelimit_policy_replicas",
		"Replicas of the domain by state: total is the ready fleet, applied is how many of it enforce the active generation.",
		[]string{"domain", "state"}, nil)
)

// fleetCollector renders what the operator last saw, on every scrape.
type fleetCollector struct{}

func (fleetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descLeader
	ch <- descPolicyStalled
	ch <- descPolicyReplicas
}

func (fleetCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(descLeader,
		prometheus.GaugeValue, boolValue(leader.Load()))

	fleetMu.RLock()
	defer fleetMu.RUnlock()
	for domain, sample := range fleetSample {
		ch <- prometheus.MustNewConstMetric(descPolicyStalled,
			prometheus.GaugeValue, boolValue(sample.Stalled), domain, sample.Reason)
		ch <- prometheus.MustNewConstMetric(descPolicyReplicas,
			prometheus.GaugeValue, float64(sample.Applied), domain, ReplicasApplied)
		ch <- prometheus.MustNewConstMetric(descPolicyReplicas,
			prometheus.GaugeValue, float64(sample.Total), domain, ReplicasTotal)
	}
}
