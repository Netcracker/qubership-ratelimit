package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// RuleID is the rule label value: the block/rule pair, the same identity the
// counter key carries. The adapter writes it and the pruner matches against
// it, so the format lives in one place.
func RuleID(block, rule string) string {
	return block + "/" + rule
}

// ActiveSet lists the label values the current snapshot can produce. Series
// outside it are leftovers of renamed or deleted objects.
type ActiveSet struct {
	Domains map[string]struct{}
	Rules   map[string]struct{}
	Keys    map[string]struct{}
}

// PruneGrace is how long after a snapshot swap the pruner sweeps again. A
// check in flight on the retiring engine can recreate a just-deleted series;
// by the time the grace period ends, no such check is left — the gateway
// timeout bounds them to a fraction of it.
const PruneGrace = 5 * time.Second

// pruneMu orders set publication with the sweeps. A sweep judging by set N
// must never overlap a publication of set N+1: it could delete a series the
// newer snapshot brought back, and nothing recreates a wrongly deleted
// series until traffic does. Loading the set once and sweeping lock-free
// would leave exactly that window, so publication waits for an in-flight
// sweep instead. The hot path never takes this lock.
var (
	pruneMu      sync.Mutex
	activeLabels *ActiveSet
)

// PruneStale drops the series of label values that left the snapshot.
// Renaming a rule or retiring a domain would otherwise leave its counters in
// the vectors until the process restarts: with regular edits over a long pod
// lifetime, memory and scrape size would grow without bound while the active
// rule set stays small. Deleting a counter series is a normal counter reset
// to rate() if the value ever comes back.
func PruneStale(active *ActiveSet) {
	pruneMu.Lock()
	activeLabels = active
	sweep()
	pruneMu.Unlock()
	time.AfterFunc(PruneGrace, pruneOnce)
}

// pruneOnce is one locked sweep against the current set — the delayed pass
// behind PruneGrace.
func pruneOnce() {
	pruneMu.Lock()
	defer pruneMu.Unlock()
	sweep()
}

// sweep runs under pruneMu; see PruneStale.
func sweep() {
	active := activeLabels
	if active == nil {
		return
	}
	domainAlive := func(labels prometheus.Labels) bool {
		domain := labels["domain"]
		if domain == UnknownDomain {
			return true
		}
		_, ok := active.Domains[domain]
		return ok
	}
	for _, vec := range []deletableVec{Checks, CheckDuration, UnmatchedChecks, Refusals, StoreRoundtrip, StoreErrors} {
		pruneVec(vec, domainAlive)
	}
	for _, vec := range []deletableVec{Decisions, NearLimit} {
		pruneVec(vec, func(labels prometheus.Labels) bool {
			if !domainAlive(labels) {
				return false
			}
			_, ok := active.Rules[labels["rule"]]
			return ok
		})
	}
	for _, vec := range []deletableVec{ExtractionSkips, Extractions} {
		pruneVec(vec, func(labels prometheus.Labels) bool {
			_, ok := active.Keys[labels["key"]]
			return ok
		})
	}
}

// deletableVec is the part of a metric vector the pruner needs; counter and
// histogram vectors both provide it.
type deletableVec interface {
	prometheus.Collector
	Delete(prometheus.Labels) bool
}

// pruneVec enumerates the vector's live series and deletes those the keep
// predicate rejects. Enumeration goes through Collect — the vectors expose
// no listing — which is fine off the hot path: pruning runs per rebuild,
// and rebuilds are debounced resource events.
func pruneVec(vec deletableVec, keep func(prometheus.Labels) bool) {
	ch := make(chan prometheus.Metric)
	go func() {
		vec.Collect(ch)
		close(ch)
	}()
	var stale []prometheus.Labels
	for metric := range ch {
		var out dto.Metric
		if metric.Write(&out) != nil {
			continue
		}
		labels := make(prometheus.Labels, len(out.GetLabel()))
		for _, pair := range out.GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		if !keep(labels) {
			stale = append(stale, labels)
		}
	}
	for _, labels := range stale {
		vec.Delete(labels)
	}
}
