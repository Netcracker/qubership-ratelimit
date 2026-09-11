package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// The series in this file are the leader's, not the replica's.
//
// Everything in state.go is published by the store updater, which runs on
// every replica and reports what that replica compiled. What is here can only
// be known by the pod holding the lease: how many replicas enforce a
// generation, and whether a domain has been stuck long enough to say so. On
// every other replica these series are simply absent, which is what
// ratelimit_leader is for - it tells a query which scrape is the one carrying
// them.

// FleetSample is what the leader saw for one domain on its last reconcile.
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

	// leader is set once this replica takes the lease. It is never unset:
	// controller-runtime ends the process when a held lease is lost, so a
	// replica that stops being the leader stops scraping too.
	leader atomic.Bool
)

// PublishFleet records what the leader saw for one domain.
func PublishFleet(domain string, sample FleetSample) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	fleetSample[domain] = sample
}

// DropFleet forgets a domain. Without it the series of a deleted policy would
// keep being scraped from this replica for as long as it stayed the leader,
// and an alert on a stalled domain would fire forever on an object nobody can
// fix because it is gone.
func DropFleet(domain string) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	delete(fleetSample, domain)
}

// SetLeader records whether this replica holds the lease.
func SetLeader(held bool) { leader.Store(held) }

// Replica states of ratelimit_policy_replicas.
const (
	ReplicasApplied = "applied"
	ReplicasTotal   = "total"
)

var (
	descLeader = prometheus.NewDesc("ratelimit_leader",
		"Whether this replica holds the leader lease. The status series are only written by the replica reporting 1.",
		nil, nil)
	descPolicyStalled = prometheus.NewDesc("ratelimit_policy_stalled",
		"Whether the domain is stuck rather than progressing; reason names which way.",
		[]string{"domain", "reason"}, nil)
	descPolicyReplicas = prometheus.NewDesc("ratelimit_policy_replicas",
		"Replicas of the domain by state: total is the ready fleet, applied is how many of it enforce the active generation.",
		[]string{"domain", "state"}, nil)
)

// fleetCollector renders what the leader last saw, on every scrape.
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
