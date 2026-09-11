package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func pruneTestSet() *ActiveSet {
	return &ActiveSet{
		Domains: map[string]struct{}{"prune.alive": {}},
		Rules:   map[string]struct{}{"b/kept": {}},
		Keys:    map[string]struct{}{"tenant": {}},
	}
}

func TestPruneStale_dropsTheSeriesOfRenamedObjects(t *testing.T) {
	// A renamed rule or a retired domain must not leave its counters behind:
	// with regular edits over a long pod lifetime the leftovers would grow
	// without bound while the active set stays small.
	keptBefore := testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK))
	Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK).Inc()
	Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK).Inc()
	Checks.WithLabelValues("prune.retired", VerdictOK).Inc()
	Checks.WithLabelValues(UnknownDomain, VerdictOK).Inc()
	Extractions.WithLabelValues("dropped-key").Inc()

	PruneStale(pruneTestSet())

	assert.Equal(t, keptBefore+1, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK)),
		"a live series keeps its value")
	assert.Zero(t, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK)),
		"the renamed rule's series is gone")
	assert.Zero(t, testutil.ToFloat64(Checks.WithLabelValues("prune.retired", VerdictOK)),
		"the retired domain's series is gone")
	assert.GreaterOrEqual(t, testutil.ToFloat64(Checks.WithLabelValues(UnknownDomain, VerdictOK)), 1.0,
		"the unknown-domain placeholder is never pruned")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("dropped-key")),
		"the removed identity key's series is gone")
}

func TestPruneOnce_sweepsASeriesRecreatedByAnInFlightCheck(t *testing.T) {
	// A check in flight on the retiring engine can recreate a just-deleted
	// series; the delayed sweep runs against the latest active set and takes
	// it out again.
	PruneStale(pruneTestSet())
	Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK).Inc()

	pruneOnce()

	assert.Zero(t, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK)))
}

func TestPruneVec_alsoCoversHistograms(t *testing.T) {
	CheckDuration.WithLabelValues("prune.retired").Observe(0.001)
	CheckDuration.WithLabelValues("prune.alive").Observe(0.001)
	before := testutil.CollectAndCount(CheckDuration)

	PruneStale(pruneTestSet())

	assert.Equal(t, before-1, testutil.CollectAndCount(CheckDuration),
		"exactly the retired domain's histogram series disappears")
}

func TestPruneStale_aRepublishedSetRevivesTheJudgment(t *testing.T) {
	// A rule removed by one snapshot and brought back by the next must be
	// judged by the newest set: publication and sweeps share one lock, so a
	// sweep can never delete by a set that is no longer the latest.
	Decisions.WithLabelValues("prune.alive", "b/comeback", OutcomeOK).Inc()
	PruneStale(pruneTestSet())

	restored := pruneTestSet()
	restored.Rules["b/comeback"] = struct{}{}
	PruneStale(restored)
	Decisions.WithLabelValues("prune.alive", "b/comeback", OutcomeOK).Inc()

	pruneOnce()
	assert.Equal(t, 1.0, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/comeback", OutcomeOK)),
		"the delayed sweep judges by the restored set")
}

func TestPruneStale_isSafeUnderConcurrentPublication(t *testing.T) {
	// A race-detector exercise: concurrent publications, sweeps, and hot-path
	// increments must not trip the detector or panic. The label values are
	// this test's own, so the churn cannot skew any other test's series.
	churn := &ActiveSet{
		Domains: map[string]struct{}{"prune.churn": {}},
		Rules:   map[string]struct{}{"b/churn": {}},
		Keys:    map[string]struct{}{},
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 25 {
				PruneStale(churn)
				Decisions.WithLabelValues("prune.churn", "b/churn", OutcomeOK).Inc()
				pruneOnce()
			}
		})
	}
	wg.Wait()
}
