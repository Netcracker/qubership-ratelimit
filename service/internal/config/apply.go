package config

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/convert"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// Applier turns a reading into the rule set the gRPC server decides with,
// and keeps the record of what this replica enforces.
//
// It is the Ready gate of the replica. A replica that has never applied a
// manifest is NotReady, without a timeout: a service started before its
// operator wrote anything would otherwise join the endpoints and pass every
// request. An explicitly empty manifest is a configuration and makes the
// replica Ready with every request an unknown domain. After the first apply
// the replica stays Ready on what it applied, through vanished files and
// refused manifests alike.
type Applier struct {
	// Namespace is the component's own, a segment of every counter key.
	Namespace string

	// Store is the rule store the server reads; Counters is where every
	// engine counts, and CacheStats, when set, is shared by every engine so
	// the token-cache counters survive swaps.
	Store      *store.Store
	Counters   counters.Store
	CacheStats *engine.CacheStats

	Log logr.Logger

	mu sync.Mutex

	// domains and hashes are the previous apply, reused whole for a domain
	// whose payload hash did not move: the snapshot is a pure function of
	// the spec, and a reused domain keeps its engine's warm token cache.
	domains map[string]store.Domain
	hashes  map[string]string

	// ready flips once and stays: the first apply.
	ready atomic.Bool
}

// Ready reports whether this replica has applied a manifest.
func (a *Applier) Ready() bool { return a.ready.Load() }

// Report is what this replica enforces, for the operator's probe. It is
// derived from the current rule set in one load, the domains and the
// refusal alike, so the report and the snapshot endpoint describe the same
// configuration, and a report read during an apply or a refusal is the
// whole of one state or the other.
func (a *Applier) Report() applied.Report {
	return ReportOf(a.Store.Load())
}

// ReportOf is the applied report of one rule set.
func ReportOf(set *store.RuleSet) applied.Report {
	report := applied.Report{
		Domains:        make(map[string]applied.Domain, set.Len()),
		FormatVersions: manifest.SupportedVersions(),
		Refusal:        set.Refusal(),
	}
	for _, domain := range set.Domains() {
		d, _ := set.Domain(domain)
		report.Domains[domain] = applied.Domain{Generation: d.Generation, UID: d.UID, AppliedAt: d.AppliedAt}
	}
	return report
}

// Apply compiles every domain of the reading and swaps the rule set.
//
// A spec that does not compile here is a spec the operator validated under
// rules this build does not share, a version skew inside the compiler rather
// than the format. The rule for a generation that does not compile is that
// last-good stays enforced, and last-good is the engine of the previous
// apply: the domain keeps it and reports the generation it came from, so the
// operator sees this replica behind on that one domain and the others of
// the namespace move on. Only a domain this replica has never applied has
// nothing to keep; it is claimed and enforces nothing, at generation zero.
func (a *Applier) Apply(cfg Configuration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now().UTC()
	domains := make(map[string]store.Domain, len(cfg.Specs))
	hashes := make(map[string]string, len(cfg.Specs))
	snapshots := make(map[string]*enginecompile.Snapshot, len(cfg.Specs))
	views := make([]metrics.DomainView, 0, len(cfg.Specs))

	for _, domain := range sortedDomains(cfg.Manifest) {
		entry := cfg.Manifest.Domains[domain]
		spec := cfg.Specs[domain]
		generation := entry.Generation

		uid := entry.UID
		built, kept := a.domains[domain]
		switch {
		case kept && a.hashes[domain] == entry.Hash:
			// Same payload, same engine, warm cache kept.
		default:
			snapshot, problems := enginecompile.Compile(a.Namespace, domain, convert.Policy(&spec))
			if !blocking(problems) {
				built = a.build(domain, snapshot)
				break
			}
			if kept {
				generation, uid = built.Generation, built.UID
				a.Log.Error(nil, "the validated spec of a domain does not compile in this build; keeping the last-good engine",
					"domain", domain, "generation", entry.Generation, "enforcing", generation, "problems", len(problems))
				// The hash recorded is the previous one: the engine belongs
				// to that payload, and the next manifest is compared to it.
				entry.Hash = a.hashes[domain]
				break
			}
			a.Log.Error(nil, "the validated spec of a domain does not compile in this build; the domain enforces nothing",
				"domain", domain, "generation", entry.Generation, "problems", len(problems))
			snapshot, _ = enginecompile.Compile(a.Namespace, domain, convert.Policy(&v1alpha1.RateLimitPolicySpec{Domain: domain}))
			built = a.build(domain, snapshot)
			generation = 0
		}
		built.Generation, built.UID, built.AppliedAt = generation, uid, now
		domains[domain] = built
		hashes[domain] = entry.Hash
		snapshots[domain] = built.Snapshot
		views = append(views, metrics.DomainView{
			Domain:            domain,
			Blocks:            len(built.Snapshot.Blocks),
			Rules:             ruleview.Summary(built.Snapshot, built.Version).Rules,
			DecisionBuckets:   built.Snapshot.DecisionBuckets,
			AppliedGeneration: generation,
		})
	}

	a.domains = domains
	a.hashes = hashes
	// One publication: the set carries the rules, the generations, the swap
	// time, and no refusal, so a reader of the report or the snapshot
	// endpoint gets one configuration whole, never the new set with the
	// refusal of the reading before it.
	a.Store.Replace(store.NewRuleSet(domains))
	a.ready.Store(true)

	metrics.SnapshotRebuilds.WithLabelValues("ok").Inc()
	metrics.SnapshotTimestamp.SetToCurrentTime()
	metrics.PublishState(&metrics.StateView{Domains: views})
	metrics.PruneStale(metrics.ActiveSetOf(snapshots))
	metrics.SeedExtractions(metrics.ExtractionKeysOf(snapshots))

	a.Log.Info("configuration applied",
		"formatVersion", cfg.Manifest.FormatVersion,
		"operatorVersion", cfg.Manifest.OperatorVersion,
		"domains", len(domains))
}

// Refuse records a reading this replica will not apply. The rules and the
// domains stay as they are; the refusal is published on the set that stays
// current, and the next apply's set carries none.
func (a *Applier) Refuse(refusal *Refusal) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.Store.Refuse(&applied.Refusal{FormatVersion: refusal.FormatVersion, Reason: refusal.Err.Error()})
	metrics.SnapshotRebuilds.WithLabelValues("refused").Inc()
	a.Log.Error(refusal.Err, "configuration refused, keeping the applied snapshot",
		"formatVersion", refusal.FormatVersion, "reads", manifest.SupportedVersions())
}

// build binds a compiled domain to the shared counter store. The store is
// wrapped per domain so the roundtrip series carries the domain label
// without parsing bucket keys on the hot path.
func (a *Applier) build(domain string, snapshot *enginecompile.Snapshot) store.Domain {
	opts := []engine.Option{}
	if a.CacheStats != nil {
		opts = append(opts, engine.WithCacheStats(a.CacheStats))
	}
	return store.Domain{
		Engine:   engine.New(snapshot, metrics.InstrumentStore(domain, a.Counters), opts...),
		Snapshot: snapshot,
		// Hashed here, once per apply, and read as a string everywhere after:
		// the management API quotes it on every listing.
		Version: ruleview.Version(snapshot),
	}
}

// Handler serves the report on contract.AppliedPath. The operator reads it
// from every ready endpoint of the Service, which is what makes Ready on a
// policy a statement about the fleet.
func (a *Applier) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(a.Report()); err != nil {
			// The status is already written by then; the operator treats a
			// truncated body as an unreachable replica.
			a.Log.V(1).Info("failed to write the applied report", "error", err)
		}
	})
}

func blocking(problems []enginecompile.Problem) bool {
	for _, problem := range problems {
		if problem.Blocking {
			return true
		}
	}
	return false
}
