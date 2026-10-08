package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// pruneTestSet is the active set of the prune tests: the domain prune.alive,
// its rule b/kept, and its key tenant.
func pruneTestSet() *ActiveSet {
	return &ActiveSet{
		Domains: map[string]struct{}{"prune.alive": {}},
		Rules:   map[string]struct{}{"b/kept": {}},
		Keys:    map[string]map[string]struct{}{"prune.alive": {"tenant": {}}},
	}
}

// A renamed rule, a retired domain, or a removed key must not leave its
// series behind: with regular edits over a long pod lifetime the leftovers
// would grow without bound while the active set stays small. Every series is a
// case of its own, named by the message of its assertion, and the series the
// set still holds are the controls.
func TestPruneStale_dropsOnlyTheSeriesWhoseLabelsLeftTheActiveSet(t *testing.T) {
	keptBefore := testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK))
	tokensBefore := testutil.ToFloat64(TokensSeen.WithLabelValues("prune.alive"))
	unknownBefore := testutil.ToFloat64(Checks.WithLabelValues(UnknownDomain, VerdictOK))
	Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK).Inc()
	Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK).Inc()
	Checks.WithLabelValues("prune.retired", VerdictOK).Inc()
	TokensSeen.WithLabelValues("prune.alive").Inc()
	TokensSeen.WithLabelValues("prune.retired").Inc()
	Checks.WithLabelValues(UnknownDomain, VerdictOK).Inc()
	Extractions.WithLabelValues("prune.alive", "dropped-key").Inc()
	Extractions.WithLabelValues("prune.retired", "tenant").Inc()

	PruneStale(pruneTestSet())

	assert.Equal(t, keptBefore+1, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/kept", OutcomeOK)),
		"a live series keeps its value")
	assert.Zero(t, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK)),
		"the renamed rule's series is gone")
	assert.Zero(t, testutil.ToFloat64(Checks.WithLabelValues("prune.retired", VerdictOK)),
		"the retired domain's series is gone")
	assert.Equal(t, tokensBefore+1, testutil.ToFloat64(TokensSeen.WithLabelValues("prune.alive")),
		"the live domain keeps the traffic half of the extraction detector")
	assert.Zero(t, testutil.ToFloat64(TokensSeen.WithLabelValues("prune.retired")),
		"the retired domain's token counter is gone")
	assert.Equal(t, unknownBefore+1, testutil.ToFloat64(Checks.WithLabelValues(UnknownDomain, VerdictOK)),
		"the unknown-domain placeholder is never pruned")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("prune.alive", "dropped-key")),
		"the removed identity key's series is gone")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("prune.retired", "tenant")),
		"a key another domain still declares is pruned with the domain that dropped it")
}

// The histogram vectors are swept like the counter vectors.
func TestPruneStale_dropsTheHistogramSeriesOfARetiredDomain(t *testing.T) {
	CheckDuration.WithLabelValues("prune.retired").Observe(0.001)
	CheckDuration.WithLabelValues("prune.alive").Observe(0.001)
	aliveBefore := sampleCount(t, CheckDuration, "prune.alive")

	PruneStale(pruneTestSet())

	assert.Equal(t, 0, sampleCount(t, CheckDuration, "prune.retired"),
		"observations of the retired domain")
	assert.Equal(t, aliveBefore, sampleCount(t, CheckDuration, "prune.alive"),
		"observations of the live domain")
}

// A check in flight on the retiring engine can recreate a just-deleted
// series; the delayed sweep runs against the latest active set and takes it
// out again. The test runs the delayed sweep at once rather than waiting out
// PruneGrace.
func TestPruneOnce_sweepsASeriesRecreatedByAnInFlightCheck(t *testing.T) {
	PruneStale(pruneTestSet())
	Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK).Inc()

	pruneOnce()

	assert.Zero(t, testutil.ToFloat64(Decisions.WithLabelValues("prune.alive", "b/renamed", OutcomeOK)),
		"the recreated series of the renamed rule")
}

// A rule removed by one snapshot and brought back by the next is judged by the
// newest set: publication and sweeps share one lock, so a sweep never deletes
// by a set that is no longer the latest.
func TestPruneOnce_judgesByTheLatestPublishedSet(t *testing.T) {
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

// Concurrent publications, sweeps, and hot-path increments must not trip the
// race detector, and a series the active set holds is never swept, so every
// increment is still counted afterwards. The label values are this test's
// own, so the churn cannot skew any other test's series.
func TestPruneStale_keepsAnActiveSeriesUnderConcurrentPublication(t *testing.T) {
	churn := &ActiveSet{
		Domains: map[string]struct{}{"prune.churn": {}},
		Rules:   map[string]struct{}{"b/churn": {}},
		Keys:    map[string]map[string]struct{}{},
	}
	before := testutil.ToFloat64(Decisions.WithLabelValues("prune.churn", "b/churn", OutcomeOK))

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

	assert.Equal(t, before+100, testutil.ToFloat64(Decisions.WithLabelValues("prune.churn", "b/churn", OutcomeOK)),
		"four goroutines of 25 increments each")
}
