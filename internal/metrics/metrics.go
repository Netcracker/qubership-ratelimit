// Package metrics defines every Prometheus series the service exposes and
// registers them with the controller-runtime registry, so they ride the
// manager's metrics endpoint.
//
// Label cardinality is bounded by configuration on purpose: domains come from
// the gateway filter config, policies and rules from the custom resources,
// keys from the mappings, and every other label is a fixed enum. Nothing
// caller-controlled becomes a label value — see UnknownDomain.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	engine "github.com/netcracker/qubership-ratelimit/engine"
)

// UnknownDomain replaces the domain label of a check no policy claims. The
// real name is caller-controlled — any string out of somebody's filter config
// — and labeling by it would let a misconfigured or hostile gateway mint
// series without bound. The name itself goes to the log instead.
const UnknownDomain = "[unknown]"

// Verdicts of one check, the topline unit Envoy sees.
const (
	VerdictOK          = "ok"
	VerdictOverLimit   = "over_limit"
	VerdictUnavailable = "unavailable"
)

// Outcomes of one applied rule.
const (
	OutcomeOK              = "ok"
	OutcomeOverLimit       = "over_limit"
	OutcomeShadowOverLimit = "shadow_over_limit"
)

// Causes of a hard refusal — a denial that is not a limit at work.
const (
	CauseTooManyBuckets     = "too_many_buckets"
	CauseTooManyDescriptors = "too_many_descriptors"
)

// durationBuckets align with the contract numbers: the 10ms decision budget
// and the gateway filter timeout land on bucket boundaries, so "p99 over the
// budget" reads exactly rather than interpolated.
var durationBuckets = []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, 1}

var (
	// Checks counts every ShouldRateLimit call by its final verdict. The
	// unavailable verdict is the fail-open exposure window: traffic that
	// passed or was cut by the gateway's failure mode, not by a limit.
	Checks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_checks_total",
		Help: "Rate limit checks by final verdict; unavailable means the gateway's failure mode decided.",
	}, []string{"domain", "verdict"})

	// CheckDuration is the full gRPC handler time — the number the gateway
	// compares with its filter timeout before failing open or closed.
	CheckDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ratelimit_check_duration_seconds",
		Help:    "Full duration of one rate limit check, the time the gateway waits for.",
		Buckets: durationBuckets,
	}, []string{"domain"})

	// Decisions counts applied rules by their own verdict. A shadow rule
	// reports what it would have done, which is what a dry run is for.
	Decisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_decisions_total",
		Help: "Applied rules by their own verdict; rule is the policy/block/rule triple.",
	}, []string{"domain", "rule", "outcome"})

	// NearLimit counts admissions of enforcing rules that landed inside the
	// configured margin of their limit — the precursor of over_limit. Shadow
	// rules stay out: their readout is the shadow_over_limit outcome, and a
	// dry run near an experimental limit is not a precursor of client-visible
	// refusals.
	NearLimit = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_near_limit_total",
		Help: "Admissions of enforcing rules within the near-limit margin of the limit.",
	}, []string{"domain", "rule"})

	// Refusals counts denials that are not a limit at work: the bucket-budget
	// backstop and the descriptor bound. Both deny regardless of the failure
	// mode, and both mean configuration, not traffic.
	Refusals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_refusals_total",
		Help: "Hard refusals by cause; these are configuration violations, not limits at work.",
	}, []string{"domain", "cause"})

	// UnknownDomainChecks counts checks for domains no policy claims — the
	// filter config and the custom resources have drifted apart, and the
	// traffic passes unlimited. The domain name is in the log, not here.
	UnknownDomainChecks = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_unknown_domain_checks_total",
		Help: "Checks for domains no policy claims; such traffic passes unlimited.",
	})

	// UnmatchedChecks counts checks of a known domain that applied no rule at
	// all and therefore charged nothing. Two roads lead here: a route pattern
	// that misses what the gateway sends, and a request whose only matching
	// rules could not apply — a broken token on per-client rules lands here
	// next to its extraction skips. Either way the traffic passed unlimited.
	UnmatchedChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_unmatched_checks_total",
		Help: "Checks that applied no rule and passed without charging anything.",
	}, []string{"domain"})

	// ExtractionSkips and Extractions are the two halves of the "key declared,
	// tokens arriving, zero extractions" detector: skips say extraction is
	// failing, a flat zero next to traffic says the claim path is dead.
	ExtractionSkips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_extraction_skips_total",
		Help: "Identity extraction anomalies by declared key and reason.",
	}, []string{"key", "reason"})
	Extractions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_extractions_total",
		Help: "Decisions whose request carried a value for the declared identity key.",
	}, []string{"key"})

	// StoreRoundtrip is the counter store's share of the check. It is labeled
	// by domain because a domain is pinned to one Redis Cluster slot: shard
	// saturation is a property of the domain, not of the process.
	StoreRoundtrip = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ratelimit_store_roundtrip_seconds",
		Help:    "Duration of one atomic counter store decision.",
		Buckets: durationBuckets,
	}, []string{"domain"})

	// StoreErrors counts failed store decisions. The reason separates what an
	// operator does about it: timeout is load or distance, server is the store
	// answering an error (a script or command problem), other is connectivity.
	StoreErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_store_errors_total",
		Help: "Failed counter store decisions by reason: timeout, server, other.",
	}, []string{"domain", "reason"})

	// SnapshotRebuilds counts rule store rebuilds. Errors mean the engines
	// keep serving the previous snapshot — stale rules, silently.
	SnapshotRebuilds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_snapshot_rebuilds_total",
		Help: "Rule store rebuilds; an error keeps the previous snapshot serving.",
	}, []string{"result"})

	// SnapshotTimestamp is when the serving snapshot was last swapped — the
	// forensic answer to "did the rules change right before the incident".
	SnapshotTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratelimit_snapshot_timestamp_seconds",
		Help: "Unix time of the last successful rule store swap.",
	})

	// StatePersistErrors counts failed operations on the persisted last-good
	// state. Nothing degrades immediately — the snapshot still serves — but
	// a failing write means the fallback a restart would need is not being
	// saved, and a failing delete means a retired domain's state lingers and
	// retries forever. A delayed-fuse alert either way.
	StatePersistErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_state_persist_errors_total",
		Help: "Failed last-good state operations by reason: overflow, delete, other.",
	}, []string{"reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		Checks, CheckDuration, Decisions, NearLimit, Refusals,
		UnknownDomainChecks, UnmatchedChecks, ExtractionSkips, Extractions,
		StoreRoundtrip, StoreErrors,
		SnapshotRebuilds, SnapshotTimestamp, StatePersistErrors,
		stateCollector{},
	)
}

// CacheStatsCollectors turns the engine's shared token-cache counters into
// Prometheus counters. They are built on demand — the stats value exists only
// once the engines are wired — and registered by RegisterCacheStats.
func CacheStatsCollectors(stats *engine.CacheStats) []prometheus.Collector {
	hits := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "ratelimit_token_cache_hits_total",
		Help: "Token-cache lookups that avoided an identity extraction.",
	}, func() float64 { return float64(stats.Hits()) })
	misses := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "ratelimit_token_cache_misses_total",
		Help: "Identity extractions performed for cache-eligible tokens.",
	}, func() float64 { return float64(stats.Misses()) })
	return []prometheus.Collector{hits, misses}
}

// RegisterCacheStats registers the token-cache counters; call it once, at
// wiring time.
func RegisterCacheStats(stats *engine.CacheStats) {
	ctrlmetrics.Registry.MustRegister(CacheStatsCollectors(stats)...)
}
