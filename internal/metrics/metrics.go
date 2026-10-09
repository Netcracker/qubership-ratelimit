// Package metrics defines every Prometheus series the two binaries expose.
// The collectors are package values; Register puts them on the registry a
// binary serves, the manager's for the operator and a plain one for the
// service, which is why nothing here registers itself at init.
//
// Label cardinality is bounded by configuration on purpose: domains come from
// the gateway filter config, policies and rules from the custom resources,
// keys from the mappings, and every other label is a fixed enum. Nothing
// caller-controlled becomes a label value — see UnknownDomain.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

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
	VerdictExempt      = "exempt"
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
	CauseInvalidCost        = "invalid_cost"
)

// durationBuckets align with the contract numbers: the 10ms decision budget
// and the gateway filter timeout land on bucket boundaries, so "p99 over the
// budget" reads exactly rather than interpolated.
var durationBuckets = []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, 1}

// The reasons of a failed write of the configuration ConfigMap: size, a state
// the object cannot hold even after the fit; api, an answer of the API
// server; read, a reconcile that could not read the policies or the ConfigMap
// it writes from, and so wrote nothing; other, the rest.
const (
	ConfigErrorSize  = "size"
	ConfigErrorAPI   = "api"
	ConfigErrorRead  = "read"
	ConfigErrorOther = "other"
)

// configErrorReasons are every reason of a failed write, the series created at
// zero when the operator registers them.
var configErrorReasons = []string{ConfigErrorSize, ConfigErrorAPI, ConfigErrorRead, ConfigErrorOther}

// RecordConfigWrite records one attempt to write the configuration ConfigMap:
// a failure counts in ConfigWriteErrors under reason and sets
// ConfigWriteFailing to 1 for that reason alone; an empty reason is a write
// that succeeded and sets every reason of ConfigWriteFailing to 0.
func RecordConfigWrite(reason string) {
	for _, r := range configErrorReasons {
		ConfigWriteFailing.WithLabelValues(r).Set(0)
	}
	if reason == "" {
		return
	}
	ConfigWriteErrors.WithLabelValues(reason).Inc()
	ConfigWriteFailing.WithLabelValues(reason).Set(1)
}

var (
	// Checks counts every ShouldRateLimit call by its final verdict. The
	// unavailable verdict is the fail-open exposure window: traffic that
	// passed or was cut by the gateway's failure mode, not by a limit. The
	// exempt verdict counts the checks admitted without a decision, which
	// the service does for requests to its own management API.
	Checks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_checks_total",
		Help: "Rate limit checks by final verdict; unavailable means the gateway's failure mode decided, " +
			"exempt means the service admitted the check without a decision.",
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
		Help: "Applied rules by their own verdict; rule is the block/rule identity.",
	}, []string{"domain", "rule", "outcome"})

	// NearLimit counts admissions of enforcing rules that landed inside the
	// configured margin of their window's capacity — the precursor of
	// over_limit. The capacity is the burst of a GCRA window or the requests
	// of a fixed one. Shadow rules stay out: their readout is the
	// shadow_over_limit outcome, and a dry run near an experimental limit is
	// not a precursor of client-visible refusals.
	NearLimit = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_near_limit_total",
		Help: "Admissions of enforcing rules within the near-limit margin of the window's capacity.",
	}, []string{"domain", "rule"})

	// Refusals counts denials that are not a limit at work: the bucket-budget
	// backstop and the descriptor bound, which mean configuration, and an
	// invalid cost, which is a caller breaking the protocol. All three deny
	// regardless of the failure mode, and none is traffic over a limit.
	Refusals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_refusals_total",
		Help: "Hard refusals by cause: configuration or protocol violations, not limits at work.",
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
	// failing, a flat zero next to traffic says the claim path is dead. Both
	// carry the domain: a key is declared per domain, and two domains can map
	// the same name to different claims, so a dead claim path is a fact about
	// one domain's mapping, and the alert names the domain to fix.
	ExtractionSkips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_extraction_skips_total",
		Help: "Identity extraction anomalies by domain, declared key, and reason.",
	}, []string{"domain", "key", "reason"})
	Extractions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_extractions_total",
		Help: "Decisions whose request carried a value for the declared identity key, by domain.",
	}, []string{"domain", "key"})

	// TokensSeen is the traffic half of the detector: a key whose extraction
	// series sits at zero while this one grows has a dead claim path. It
	// counts the requests a block targeted, the ones whose token the engine
	// reads, as the extraction series does. It
	// carries the domain because the detector's other half does: joined
	// namespace-wide, one domain's traffic would judge another domain's
	// idle keys and report a dead claim path on a mapping nobody used.
	TokensSeen = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_tokens_seen_total",
		Help: "Decisions on a known domain whose request carried a token that a block targeted, by domain.",
	}, []string{"domain"})

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

	// ConfigWriteErrors counts failed writes of the configuration ConfigMap by
	// the operator, by reason: size, the namespace's state does not fit the
	// object even after the fit; api, the API server refused the write; read,
	// the reconcile could not read the policies or the ConfigMap it writes
	// from, so it wrote nothing; other.
	// Nothing degrades at once, the replicas keep the configuration they
	// mounted, but the change is not reaching them, and the last-good
	// fallback a restart would need is not being saved. A delayed-fuse alert,
	// and the one the status reports 90 s later as ReplicaStale.
	ConfigWriteErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_config_write_errors_total",
		Help: "Failed writes of the configuration ConfigMap by reason: size, api, read, other.",
	}, []string{"reason"})

	// ConfigWriteFailing is 1 under the reason of the last attempt to write
	// the configuration ConfigMap while that attempt failed, and 0 once a
	// write succeeds. A write that fails once and succeeds on its retry
	// returns it to 0 within milliseconds; one that keeps failing holds it at
	// 1 between the retries of the controller's backoff.
	ConfigWriteFailing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratelimit_config_write_failing",
		Help: "1 while the last write of the configuration ConfigMap failed, under its reason; 0 once a write succeeds.",
	}, []string{"reason"})

	// ConfigAbsent is 1 while the mounted configuration directory holds no
	// manifest: the ConfigMap is gone, and the replica keeps serving a
	// snapshot nothing will rebuild, or has none and stays NotReady.
	ConfigAbsent = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratelimit_config_absent",
		Help: "1 while the mounted configuration directory holds no manifest; the replica keeps what it applied.",
	})

	// SnapshotTimestamp is when the rules this replica enforces last changed
	// while it ran — the forensic answer to "did the rules change right before
	// the incident". It stays 0 until the first change after the process
	// starts: a restart applies the rules it finds, which is not a change.
	SnapshotTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratelimit_snapshot_timestamp_seconds",
		Help: "Unix time the enforced rules last changed while this replica ran; 0 until the first change.",
	})
)

// RegisterService puts the data plane's series on the service's registry:
// the checks, the decisions, the extraction detector, the store, the
// snapshot swaps, the domain view, and the build's version. It is called
// once per process, at wiring time; a second call on the same registry is a
// no-op rather than the panic prometheus raises for a duplicate, so that a
// test which builds a process twice does not need to know.
func RegisterService(registry prometheus.Registerer, version string) {
	register(registry,
		Checks, CheckDuration, Decisions, NearLimit, Refusals,
		UnknownDomainChecks, UnmatchedChecks, ExtractionSkips, Extractions, TokensSeen,
		StoreRoundtrip, StoreErrors,
		SnapshotRebuilds, SnapshotTimestamp, ConfigAbsent,
		stateCollector{},
		buildInfo(ComponentService, version))
}

// RegisterOperator puts the control plane's series on the operator's
// registry: the policy status, the fleet, the ConfigMap writer's errors, and
// the build's version. Nothing of the data plane is on it, so a scrape of the
// operator carries no check counter at zero for a query to exclude. Idempotent
// like RegisterService.
func RegisterOperator(registry prometheus.Registerer, version string) {
	for _, reason := range configErrorReasons {
		// Created at zero, so the first failure of a reason is an increase a
		// rule can see rather than the start of a series.
		ConfigWriteErrors.WithLabelValues(reason).Add(0)
		ConfigWriteFailing.WithLabelValues(reason).Set(0)
	}
	register(registry,
		ConfigWriteErrors, ConfigWriteFailing,
		stateCollector{},
		fleetCollector{},
		buildInfo(ComponentOperator, version))
}

func register(registry prometheus.Registerer, collectors ...prometheus.Collector) {
	for _, collector := range collectors {
		var already prometheus.AlreadyRegisteredError
		if err := registry.Register(collector); err != nil && !errors.As(err, &already) {
			panic(err)
		}
	}
}

// SeedExtractions creates a zero-valued extraction series for every declared
// key of every domain of the new snapshot. Counter series appear on their
// first increment, and a dead claim path never increments, so without
// seeding the one key the detector exists for is exactly the one with no
// series to alert on. Seeding an existing series is a no-op, and the pruner
// keeps seeded keys alive: declared keys are part of its active set.
func SeedExtractions(keys map[string][]string) {
	for domain, names := range keys {
		for _, key := range names {
			Extractions.WithLabelValues(domain, key)
		}
	}
}

// Components of ratelimit_build_info.
const (
	ComponentOperator = "operator"
	ComponentService  = "service"
)

// buildInfo is the version of the binary as a constant 1, so that the
// version reads as a label. The operator stamps the same value into the
// manifest as operatorVersion; the service carries the release its image was
// tagged with. Next to each other on one dashboard the two show a rollout in
// progress, and next to the manifest's version a replica reading a manifest
// written by a newer operator.
func buildInfo(component, version string) prometheus.Collector {
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratelimit_build_info",
		Help: "The version of the binary serving this scrape; the value is always 1.",
	}, []string{"component", "version"})
	info.WithLabelValues(component, version).Set(1)
	return info
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
func RegisterCacheStats(registry prometheus.Registerer, stats *engine.CacheStats) {
	registry.MustRegister(CacheStatsCollectors(stats)...)
}
