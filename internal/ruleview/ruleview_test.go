package ruleview_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
)

const domain = "gateway.public"

func policy(requests int64) model.Policy {
	return model.Policy{
		Name:   "quote-api",
		Domain: domain,
		Blocks: []model.Block{{
			Name: "cascade",
			Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/quotes/"},
			}}},
			Rules: []model.Rule{{
				Name: "everyone",
				When: []model.Condition{{
					Key: model.KeyClient, Operator: model.OperatorIn, Values: []string{"bob", "alice"},
				}},
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{{Requests: requests, Period: time.Minute}},
			}},
		}},
	}
}

func snapshotOf(t *testing.T, policies ...model.Policy) *compile.Snapshot {
	t.Helper()
	snapshot, problems := compile.Compile(domain, policies, nil)
	for _, problem := range problems {
		require.False(t, problem.Blocking, "blocking compile problem: %+v", problem)
	}
	return snapshot
}

// The version is the identity of an enforced set, so the property that matters
// is an equivalence: the same rendering means the same version, and a different
// rendering means a different one. Everything else — replicas agreeing,
// restarts not churning the value, a pinned reset staying valid across an
// unrelated domain's rollout — follows from it.

func TestVersion_isTheSameForTheSameRenderedSet(t *testing.T) {
	first := snapshotOf(t, policy(100))
	second := snapshotOf(t, policy(100))

	require.Equal(t, ruleview.Render(first), ruleview.Render(second))
	require.Equal(t, ruleview.Version(first), ruleview.Version(second))
}

func TestVersion_changesWithTheEnforcedSet(t *testing.T) {
	require.NotEqual(t, ruleview.Version(snapshotOf(t, policy(100))),
		ruleview.Version(snapshotOf(t, policy(101))))
}

func TestVersion_doesNotDependOnTheOrderObjectsArrivedIn(t *testing.T) {
	other := policy(50)
	other.Name = "other-api"

	forward := snapshotOf(t, policy(100), other)
	backward := snapshotOf(t, other, policy(100))

	require.Equal(t, ruleview.Version(forward), ruleview.Version(backward))
}

func TestVersion_isTwelveHexCharacters(t *testing.T) {
	version := ruleview.Version(snapshotOf(t, policy(100)))
	require.Len(t, version, 12)
	require.Regexp(t, `^[0-9a-f]{12}$`, version)
}

// A condition's value set is a map in the compiled form, and a hash over map
// iteration order would give two replicas two versions for one rule set.
func TestRender_sortsConditionValueSets(t *testing.T) {
	view := ruleview.Render(snapshotOf(t, policy(100)))
	condition := view.Blocks[0].Rules[0].When[0]

	require.Equal(t, "In", condition.Operator)
	require.Equal(t, []string{"alice", "bob"}, condition.Values)
}

// Applicability is a property of the question a caller asked, not of the set
// being enforced, so an annotated view must not be able to change the version.
func TestRender_carriesNoApplicabilityAnnotations(t *testing.T) {
	view := ruleview.Render(snapshotOf(t, policy(100)))
	require.Empty(t, view.Blocks[0].Rules[0].Applicability)
	require.Empty(t, view.Blocks[0].Rules[0].ConditionalOn)
	require.Empty(t, view.RuleSetVersion)
}

// Summary counts what the domain index shows without rendering a rule set.
func TestSummary_countsTheEnforcedSet(t *testing.T) {
	other := policy(50)
	other.Name = "other-api"
	snapshot := snapshotOf(t, policy(100), other)

	summary := ruleview.Summary(snapshot, "7c31a9f4e0d2")

	require.Equal(t, domain, summary.Domain)
	require.Equal(t, "7c31a9f4e0d2", summary.RuleSetVersion)
	require.Equal(t, 2, summary.Policies)
	require.Equal(t, 2, summary.Blocks)
	require.Equal(t, 2, summary.Rules)
	require.Equal(t, []string{"client", "method", "path"}, summary.EffectiveKeys)
	require.Empty(t, summary.ListValuedKeys, "this domain declares no array claim")
}

func TestMode_rendersTheRuntimeVocabulary(t *testing.T) {
	require.Equal(t, "enforce", ruleview.Mode(""))
	require.Equal(t, "enforce", ruleview.Mode(model.BehaviorEnforce))
	require.Equal(t, "shadow", ruleview.Mode(model.BehaviorShadow))
	require.Equal(t, "bypass", ruleview.Mode(model.BehaviorBypass))
}

func TestSplitID_acceptsOnlyTheFullTriple(t *testing.T) {
	policy, block, rule, ok := ruleview.SplitID("quote-api/cascade/everyone")
	require.True(t, ok)
	require.Equal(t, "quote-api", policy)
	require.Equal(t, "cascade", block)
	require.Equal(t, "everyone", rule)

	for _, id := range []string{"quote-api", "quote-api/cascade", "quote-api//everyone", ""} {
		_, _, _, ok := ruleview.SplitID(id)
		require.False(t, ok, "id %q", id)
	}
}
