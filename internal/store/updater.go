package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// DefaultDebounce is how long the updater waits after the first event of a burst
// before rebuilding. The informer replays one event per existing object at
// startup, so without it a namespace with N objects would rebuild N times.
const DefaultDebounce = 200 * time.Millisecond

// InformerSource is the part of cache.Cache the updater uses: informers to
// subscribe to, and a reader to rebuild from. The cache of the manager satisfies
// it.
type InformerSource interface {
	client.Reader
	GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error)
}

// StateStore persists the last-good spec of every object of a domain. It is
// optional: without it the operator still works, and only loses the last-good
// specs across a restart.
type StateStore interface {
	Load(ctx context.Context, domains []string) (map[string]policy.Bundle, error)
	Save(ctx context.Context, domain string, bundle policy.Bundle) error
	Delete(ctx context.Context, domain string) error

	// ListDomains names every domain with persisted state, so a new leader can
	// drop the state of domains retired while somebody else held the lease.
	ListDomains(ctx context.Context) ([]string, error)
}

// Updater keeps the Store in sync with the objects in the cache.
//
// It runs on every replica and subscribes to the informers directly instead of
// living inside Reconcile: Reconcile only runs on the leader, so a store filled
// there would leave non-leader replicas answering checks from an empty store — a
// failure that shows up as limits that apply on some pods and not others.
type Updater struct {
	Cache    InformerSource
	Store    *Store
	Debounce time.Duration
	Log      logr.Logger

	// Counters is the store the engines count in, shared by every domain.
	Counters counters.Store

	// CacheStats, when set, is shared by every engine this updater builds, so
	// the token-cache counters survive snapshot swaps.
	CacheStats *engine.CacheStats

	// State persists what is being enforced. Every replica reads it once, at
	// startup, so a replica that comes up while an edit is rejected enforces the
	// same last-good specs as its siblings.
	State StateStore

	// Elected is closed once this replica holds the lease. Only the leader
	// writes the state: several writers would fight over one ConfigMap for no
	// gain, since they all compute the same bundles.
	Elected <-chan struct{}

	// bundles is the last-good state this replica compiles from. It starts as
	// whatever State holds and is carried forward by each rebuild.
	bundles map[string]policy.Bundle
	loaded  bool

	// persisted is what the store is known to hold, which is not the same thing
	// as what was computed: a write skipped because this replica did not hold the
	// lease, or one that failed, must not be remembered as done or it would never
	// be retried.
	persisted map[string]policy.Bundle

	// domains are the compiled domains of the previous rebuild, reused whole for
	// domains whose bundle did not change. Engine and snapshot travel together
	// because the engine was built from that snapshot, and the management API
	// reports the snapshot as what is being enforced.
	domains map[string]Domain

	// reconciledStale is set once this leader has swept the persisted state for
	// domains that retired before it took the lease.
	reconciledStale bool

	// built reports whether the store has been filled at least once.
	built atomic.Bool
}

// Ready reports whether this replica has rules to decide with.
//
// It gates readiness, because the gRPC listener comes up before the first
// rebuild finishes: for the half second in between, the replica is reachable
// and its store is empty, and an empty store admits everything. A replica that
// joined the Service endpoints in that state would turn every limit off for a
// share of the traffic on each rollout — silently, since admitting is what an
// unclaimed domain is supposed to do.
func (u *Updater) Ready() bool { return u.built.Load() }

// NeedLeaderElection reports false: every replica serves rate limit checks, so
// every replica needs a populated store.
func (u *Updater) NeedLeaderElection() bool { return false }

// Start subscribes to policy and mapping events and rebuilds the store on each
// burst. It returns when ctx is cancelled.
func (u *Updater) Start(ctx context.Context) error {
	debounce := u.Debounce
	if debounce <= 0 {
		debounce = DefaultDebounce
	}

	// Buffered by one: a pending trigger already covers any event that arrives
	// before the rebuild runs, because the rebuild always reads the full list.
	trigger := make(chan struct{}, 1)
	notify := func(any) {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	handler := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { notify(obj) },
		UpdateFunc: func(_, obj any) { notify(obj) },
		DeleteFunc: func(obj any) { notify(obj) },
	}

	// A mapping is watched for the same reason a policy is: it decides how
	// identity is read, and a rule that references a mapped key comes alive on
	// the rebuild that first sees the mapping.
	watched := []client.Object{
		&v1alpha1.RateLimitPolicy{},
		&v1alpha1.RateLimitMapping{},
	}
	for _, object := range watched {
		informer, err := u.Cache.GetInformer(ctx, object)
		if err != nil {
			return fmt.Errorf("get %T informer: %w", object, err)
		}
		registration, err := informer.AddEventHandler(handler)
		if err != nil {
			return fmt.Errorf("add %T event handler: %w", object, err)
		}
		defer func() {
			if err := informer.RemoveEventHandler(registration); err != nil {
				u.Log.Error(err, "failed to remove event handler")
			}
		}()
	}

	// The cache is synced before this runnable starts, so the first rebuild
	// already sees every existing object; the replayed Add events then collapse
	// into a single extra rebuild.
	u.rebuild(ctx)

	timer := time.NewTimer(debounce)
	if !timer.Stop() {
		<-timer.C
	}
	// Becoming leader is a trigger of its own. This runnable is not leader-gated,
	// so it starts before the lease is acquired and the first rebuild writes no
	// state; without this the state of a quiet namespace would stay unwritten
	// until something happened to change it.
	elected := u.Elected

	// A nil channel blocks forever, which is how "no rebuild is scheduled" and
	// "leadership already handled" are both expressed here. The timer is armed by
	// the first event of a burst and not re-armed by the rest, so a steady stream
	// of events cannot starve the rebuild the way a reset-on-every-event debounce
	// would.
	var pending <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-elected:
			elected = nil
			u.rebuild(ctx)
		case <-trigger:
			if pending == nil {
				timer.Reset(debounce)
				pending = timer.C
			}
		case <-pending:
			pending = nil
			u.rebuild(ctx)
		}
	}
}

func (u *Updater) rebuild(ctx context.Context) {
	input, err := policy.Load(ctx, u.Cache)
	if err != nil {
		// Keep the previous snapshot: stale rules are better than none, and the
		// next event triggers another attempt.
		metrics.SnapshotRebuilds.WithLabelValues("error").Inc()
		u.Log.Error(err, "failed to rebuild the rate limit store, keeping the previous snapshot")
		return
	}
	input.State = u.lastGood(ctx, input)

	result := policy.Compile(input)

	for domain, warnings := range result.Warnings {
		for _, warning := range warnings {
			u.Log.Info("domain over its reference bounds", "domain", domain, "warning", warning)
		}
	}

	// Write-ahead: the state describes what the snapshot about to be installed
	// enforces, so persisting it first makes a crash in between recoverable — the
	// next start converges to a state that was valid when it was written.
	u.persist(ctx, result.State)
	previous := u.bundles
	u.bundles = result.State

	u.Store.Replace(u.ruleSet(result, previous))
	u.built.Store(true)
	metrics.SnapshotRebuilds.WithLabelValues("ok").Inc()
	metrics.SnapshotTimestamp.SetToCurrentTime()
	metrics.PublishState(stateView(result))
	metrics.PruneStale(activeSet(result))

	blocks, rules, problems := 0, 0, 0
	for _, snapshot := range result.Snapshots {
		blocks += len(snapshot.Blocks)
		for i := range snapshot.Blocks {
			rules += len(snapshot.Blocks[i].Rules)
		}
	}
	notReady, onLastGood := 0, 0
	for _, outcome := range result.Policies {
		problems += len(outcome.Problems)
		if !outcome.Ready() {
			notReady++
			if outcome.ActiveGeneration != 0 {
				onLastGood++
			}
		}
	}
	vetoed := 0
	for _, outcome := range result.Mappings {
		if len(outcome.RejectedBy) > 0 {
			vetoed++
		}
	}

	u.Log.Info("rate limit store rebuilt",
		"domains", len(result.Snapshots),
		"blocks", blocks,
		"rules", rules,
		"ruleProblems", problems,
		"policiesNotReady", notReady,
		"policiesOnLastGood", onLastGood,
		"mappingsVetoed", vetoed,
	)
}

// ruleSet binds each compiled domain to the shared counter store, reusing the
// engine of any domain whose bundle did not change.
//
// The snapshot is a pure function of the bundle, so an unchanged bundle means
// unchanged rules — and a reused domain keeps its engine's warm token cache. The
// cache holds extraction results, themselves a pure function of the token and
// the snapshot's extraction plan, so nothing stale survives the reuse; a domain
// whose rules did change gets a fresh engine, and the old cache retires with the
// old one.
//
// The pair is reused rather than just the engine, so the snapshot the management
// API reports is always the one the engine beside it was built from.
func (u *Updater) ruleSet(result *policy.Result, previous map[string]policy.Bundle) *RuleSet {
	domains := make(map[string]Domain, len(result.Snapshots))
	for domain, snapshot := range result.Snapshots {
		if prev, ok := u.domains[domain]; ok && unchanged(previous[domain], result.State[domain]) {
			domains[domain] = prev
			continue
		}
		opts := []engine.Option{}
		if u.CacheStats != nil {
			opts = append(opts, engine.WithCacheStats(u.CacheStats))
		}
		// The store is wrapped per domain so the roundtrip series carries the
		// domain label without parsing bucket keys on the hot path.
		instrumented := metrics.InstrumentStore(domain, u.Counters)
		domains[domain] = Domain{Engine: engine.New(snapshot, instrumented, opts...), Snapshot: snapshot}
	}
	u.domains = domains
	return NewRuleSet(domains)
}

// activeSet lists the label values the new snapshot can produce, for the
// series pruner: domains, rule triples, and identity keys. Whatever is not
// here belongs to a renamed or deleted object and its series are leftovers.
func activeSet(result *policy.Result) *metrics.ActiveSet {
	active := &metrics.ActiveSet{
		Domains: make(map[string]struct{}, len(result.Snapshots)),
		Rules:   map[string]struct{}{},
		Keys:    map[string]struct{}{},
	}
	for domain, snapshot := range result.Snapshots {
		active.Domains[domain] = struct{}{}
		for _, key := range snapshot.EffectiveKeys {
			active.Keys[key] = struct{}{}
		}
		for i := range snapshot.Blocks {
			block := &snapshot.Blocks[i]
			for _, rule := range block.Rules {
				active.Rules[metrics.RuleID(block.Policy, block.Name, rule.Name)] = struct{}{}
			}
		}
	}
	return active
}

// stateView distills a compilation into the scrape-time status series: who is
// ready and why not, what is enforced, and how much of the domain budgets is
// spent.
func stateView(result *policy.Result) *metrics.StateView {
	view := &metrics.StateView{}

	buckets := map[string]int{}
	for _, snapshot := range result.Snapshots {
		view.Domains = append(view.Domains, metrics.DomainView{
			Domain:          snapshot.Domain,
			Blocks:          len(snapshot.Blocks),
			DecisionBuckets: snapshot.DecisionBuckets,
		})
		// Policy names are unique within the namespace, so one map serves
		// every domain.
		maps.Copy(buckets, snapshot.PolicyBuckets)
	}

	for key, outcome := range result.Policies {
		lag := outcome.Generation
		if outcome.ActiveGeneration > 0 {
			lag = outcome.Generation - outcome.ActiveGeneration
		}
		view.Policies = append(view.Policies, metrics.PolicyView{
			Policy:        key.String(),
			Ready:         outcome.Ready(),
			Reason:        outcome.Reason,
			Enforced:      outcome.ActiveGeneration != 0,
			GenerationLag: lag,
			RuleProblems:  len(outcome.Problems),
			Buckets:       buckets[key.Name],
		})
	}
	for key, outcome := range result.Mappings {
		view.Mappings = append(view.Mappings, metrics.MappingView{
			Mapping: key.String(),
			Ready:   outcome.Ready(),
		})
	}
	return view
}

// lastGood returns the state this rebuild starts from: whatever was persisted on
// the first rebuild of the process, and the result of the previous rebuild after
// that.
func (u *Updater) lastGood(ctx context.Context, input policy.Input) map[string]policy.Bundle {
	if u.loaded || u.State == nil {
		return u.bundles
	}
	u.loaded = true

	bundles, err := u.State.Load(ctx, domainsOf(input))
	if err != nil {
		// A cold start is a valid state: the latest specs are validated and there
		// is nothing to fall back to. Refusing to serve over an unreadable cache
		// would turn a recoverable state into an outage.
		u.Log.Error(err, "failed to read the persisted rate limit state, starting without last-good specs")
		return nil
	}
	u.bundles = bundles
	u.Log.Info("persisted rate limit state loaded", "domains", len(bundles))
	return bundles
}

// persist writes the state of every domain whose bundle differs from what the
// store holds, and drops the state of domains that no longer have objects.
//
// It compares against what was actually written rather than against what was last
// computed. A replica that is not the leader computes bundles all the same, and
// remembering those as written would mean the state was never stored at all.
func (u *Updater) persist(ctx context.Context, bundles map[string]policy.Bundle) {
	if u.State == nil || !u.leading() {
		return
	}
	if u.persisted == nil {
		u.persisted = make(map[string]policy.Bundle, len(bundles))
	}
	u.sweepStale(ctx, bundles)

	for domain, bundle := range bundles {
		if unchanged(u.persisted[domain], bundle) {
			continue
		}
		if err := u.State.Save(ctx, domain, bundle); err != nil {
			// The snapshot still goes in. Losing the last-good spec of a domain
			// costs a restart its fallback; refusing to apply the rules costs the
			// gateway its limits. The domain stays out of the persisted set, so
			// the next rebuild tries again.
			reason := "other"
			if errors.Is(err, policy.ErrBundleOverflow) {
				reason = "overflow"
			}
			metrics.StatePersistErrors.WithLabelValues(reason).Inc()
			u.Log.Error(err, "failed to persist the rate limit state of a domain", "domain", domain)
			continue
		}
		u.persisted[domain] = bundle
	}

	for domain := range u.persisted {
		if _, alive := bundles[domain]; alive {
			continue
		}
		if err := u.State.Delete(ctx, domain); err != nil {
			metrics.StatePersistErrors.WithLabelValues("delete").Inc()
			u.Log.Error(err, "failed to drop the rate limit state of a retired domain", "domain", domain)
			continue
		}
		delete(u.persisted, domain)
	}
}

// sweepStale drops the persisted state of domains that retired before this
// replica took the lease. The regular delete loop only sees what this process
// persisted itself, so without the sweep a leader handover would leave the
// ConfigMap of an already retired domain behind forever.
func (u *Updater) sweepStale(ctx context.Context, bundles map[string]policy.Bundle) {
	if u.reconciledStale {
		return
	}
	known, err := u.State.ListDomains(ctx)
	if err != nil {
		// Leaving the flag unset retries the sweep on the next rebuild.
		u.Log.Error(err, "failed to list the persisted rate limit state")
		return
	}
	u.reconciledStale = true
	for _, domain := range known {
		if _, alive := bundles[domain]; alive {
			continue
		}
		if err := u.State.Delete(ctx, domain); err != nil {
			metrics.StatePersistErrors.WithLabelValues("delete").Inc()
			u.Log.Error(err, "failed to drop the rate limit state of a retired domain", "domain", domain)
			u.reconciledStale = false
			continue
		}
	}
}

// leading reports whether this replica holds the lease. With leader election
// disabled the channel is closed at startup, so a single-replica install writes
// its own state.
func (u *Updater) leading() bool {
	if u.Elected == nil {
		return true
	}
	select {
	case <-u.Elected:
		return true
	default:
		return false
	}
}

// unchanged compares two bundles by their encoding, which is what actually gets
// written. Comparing the structs would report a difference for two encodings that
// are byte for byte the same.
func unchanged(before, after policy.Bundle) bool {
	first, firstErr := policy.EncodeBundle(before)
	second, secondErr := policy.EncodeBundle(after)
	if firstErr != nil || secondErr != nil {
		return false
	}
	return bytes.Equal(first, second)
}

func domainsOf(input policy.Input) []string {
	seen := make(map[string]struct{}, len(input.Policies)+len(input.Mappings))
	for i := range input.Policies {
		seen[input.Policies[i].Spec.Domain] = struct{}{}
	}
	for i := range input.Mappings {
		seen[input.Mappings[i].Spec.Domain] = struct{}{}
	}
	domains := make([]string, 0, len(seen))
	for domain := range seen {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}
