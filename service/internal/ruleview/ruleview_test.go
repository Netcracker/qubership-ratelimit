package ruleview_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
)

const (
	domain    = "gateway.public"
	namespace = "core-1-core"
)

// policy is one FirstMatch block with one rule that counts by sub, limited to
// requests a minute, for subjects in the set {bob, alice}.
func policy(requests int64) model.Policy {
	return model.Policy{
		Domain: domain,
		Blocks: []model.Block{{
			Name: "cascade",
			Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/invoices/"},
			}}},
			Rules: []model.Rule{{
				Name: "everyone",
				Matches: []model.Predicate{{
					Key: model.KeySub, Operator: model.OperatorIn, Values: []string{"bob", "alice"},
				}},
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{{Requests: requests, Period: time.Minute}},
			}},
		}},
	}
}

func snapshotOf(t *testing.T, p model.Policy) *compile.Snapshot {
	t.Helper()
	snapshot, problems := compile.Compile(namespace, domain, &p)
	for _, problem := range problems {
		require.False(t, problem.Blocking, "blocking compile problem: %+v", problem)
	}
	return snapshot
}

// The version is the identity of an enforced set, so the property that matters
// is an equivalence: the same rendering means the same version, and a different
// rendering means a different one. Everything else follows from it: replicas
// agree, a restart keeps the value, and a pinned reset stays valid across an
// unrelated domain's rollout.

func TestVersion_isTheSameForTheSameRenderedSet(t *testing.T) {
	first := snapshotOf(t, policy(100))
	second := snapshotOf(t, policy(100))
	require.Equal(t, ruleview.Render(first), ruleview.Render(second), "the two snapshots render the same")

	assert.Equal(t, ruleview.Version(first), ruleview.Version(second))
}

// A changed limit changes the version. This is the control of
// TestVersion_isTheSameForTheSameRenderedSet.
func TestVersion_changesWithTheEnforcedSet(t *testing.T) {
	assert.NotEqual(t, ruleview.Version(snapshotOf(t, policy(100))),
		ruleview.Version(snapshotOf(t, policy(101))))
}

func TestVersion_isTwelveHexCharacters(t *testing.T) {
	assert.Regexp(t, `^[0-9a-f]{12}$`, ruleview.Version(snapshotOf(t, policy(100))))
}

// A condition's value set is a map in the compiled form, and a hash over map
// iteration order would give two replicas two versions for one rule set.
func TestRender_sortsConditionValueSets(t *testing.T) {
	view := ruleview.Render(snapshotOf(t, policy(100)))

	require.Len(t, view.Blocks, 1)
	require.Len(t, view.Blocks[0].Rules, 1)
	assert.Equal(t, []ruleview.PredicateView{{Key: model.KeySub, Operator: "In", Values: []string{"alice", "bob"}}},
		view.Blocks[0].Rules[0].Matches)
}

// Applicability is a property of the question a caller asked, not of the set
// being enforced, so an annotated view must not be able to change the version.
func TestRender_carriesNoApplicabilityAnnotations(t *testing.T) {
	view := ruleview.Render(snapshotOf(t, policy(100)))

	require.Len(t, view.Blocks, 1)
	require.Len(t, view.Blocks[0].Rules, 1)
	assert.Empty(t, view.Blocks[0].Rules[0].Applicability)
	assert.Empty(t, view.Blocks[0].Rules[0].ConditionalOn)
	assert.Empty(t, view.RuleSetVersion)
}

// Summary counts what the domain index shows without rendering a rule set.
// The domain declares no array claim, so it lists no list-valued key.
func TestSummary_countsTheEnforcedSet(t *testing.T) {
	p := policy(100)
	second := p.Blocks[0]
	second.Name = "second"
	p.Blocks = append(p.Blocks, second)
	snapshot := snapshotOf(t, p)

	summary := ruleview.Summary(snapshot, "7c31a9f4e0d2")

	assert.Equal(t, ruleview.DomainSummary{
		Domain:         domain,
		RuleSetVersion: "7c31a9f4e0d2",
		Blocks:         2,
		Rules:          2,
		EffectiveKeys:  []string{"method", "path", "sub"},
	}, summary)
}

func TestMode_rendersTheRuntimeVocabulary(t *testing.T) {
	cases := []struct {
		name     string
		behavior model.Behavior
		want     string
	}{
		{"an unset behavior is enforce", "", "enforce"},
		{"Enforce is enforce", model.BehaviorEnforce, "enforce"},
		{"Shadow is shadow", model.BehaviorShadow, "shadow"},
		{"Bypass is bypass", model.BehaviorBypass, "bypass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ruleview.Mode(c.behavior), "Mode(%q)", c.behavior)
		})
	}
}

func TestSplitID_splitsABlockRulePair(t *testing.T) {
	block, rule, ok := ruleview.SplitID("cascade/everyone")

	require.True(t, ok)
	assert.Equal(t, "cascade", block)
	assert.Equal(t, "everyone", rule)
}

// A form with a policy segment addresses nothing, because a domain has one
// policy; accepting it would resolve to a block named after the policy. The
// pair that splits is TestSplitID_splitsABlockRulePair.
func TestSplitID_refusesAnIDThatIsNotOneBlockRulePair(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"a block alone", "cascade"},
		{"a policy segment before the pair", "invoices-api/cascade/everyone"},
		{"an empty block", "/everyone"},
		{"an empty rule", "cascade/"},
		{"an empty id", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, ok := ruleview.SplitID(c.id)
			assert.False(t, ok, "SplitID(%q)", c.id)
		})
	}
}

// A window renders its algorithm as the counter key spells it, its period in
// seconds and as a Go duration, and its burst, which a gcra window carries
// whether the rule declares it or not and a fixedwindow window never does.
func TestRender_rendersEachWindowWithItsPeriodAndBurst(t *testing.T) {
	for _, tc := range []struct {
		name string
		rate model.Rate
		want ruleview.RateView
	}{
		{"a gcra window with a declared burst",
			model.Rate{Requests: 100, Period: time.Minute, Burst: 150, Algorithm: "GCRA"},
			ruleview.RateView{Algorithm: "gcra", Requests: 100, PeriodSeconds: 60, Period: "1m0s", Burst: 150}},
		{"a gcra window without a burst carries its requests",
			model.Rate{Requests: 100, Period: time.Minute, Algorithm: "GCRA"},
			ruleview.RateView{Algorithm: "gcra", Requests: 100, PeriodSeconds: 60, Period: "1m0s", Burst: 100}},
		{"a fixedwindow window of a day",
			model.Rate{Requests: 10, Period: 24 * time.Hour, Algorithm: "FixedWindow"},
			ruleview.RateView{Algorithm: "fixedwindow", Requests: 10, PeriodSeconds: 86400, Period: "24h0m0s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy(100)
			p.Blocks[0].Rules[0].Rates = []model.Rate{tc.rate}

			view := ruleview.Render(snapshotOf(t, p))

			require.Len(t, view.Blocks, 1)
			require.Len(t, view.Blocks[0].Rules, 1)
			assert.Equal(t, []ruleview.RateView{tc.want}, view.Blocks[0].Rules[0].Rates, "the rates of %+v", tc.rate)
		})
	}
}

// A block renders its name, its mode, its routes, and the placeholders its
// template routes capture. A block that declares no mode renders as All, the
// mode the custom resource defaults to.
func TestRender_rendersABlockWithItsRoutesAndCaptures(t *testing.T) {
	p := policy(100)
	p.Blocks[0].Mode = ""
	p.Blocks[0].Target.Routes = []model.Route{
		{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/invoices/{invoiceId}"}},
		{Path: model.PathMatch{Type: model.PathExact, Value: "/api/invoices"}},
	}

	view := ruleview.Render(snapshotOf(t, p))

	require.Len(t, view.Blocks, 1)
	block := view.Blocks[0]
	assert.Equal(t, "cascade", block.Block, "the block name")
	assert.Equal(t, "All", block.Mode, "the mode")
	assert.Equal(t, []ruleview.RouteView{
		{Type: "Template", Value: "/api/invoices/{invoiceId}"},
		{Type: "Exact", Value: "/api/invoices"},
	}, block.Routes, "the routes")
	assert.Equal(t, []string{"invoiceId"}, block.Captures, "the captures")
}

// A route that reads a cost renders its entry spelled as the custom resource
// spells it, with an absent default resolved to one; a route that reads none
// renders no entry.
func TestRender_rendersTheCostEntryOfARoute(t *testing.T) {
	p := policy(1000)
	p.Blocks[0].Target.Routes = []model.Route{
		{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/invoices"},
			Cost: &model.RouteCost{Source: model.CostQueryParameter, Name: "limit", Default: 20}},
		{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"},
			Cost: &model.RouteCost{Source: model.CostQueryParameter, Name: "page_size"}},
		{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}},
	}

	view := ruleview.Render(snapshotOf(t, p))

	require.Len(t, view.Blocks, 1)
	assert.Equal(t, []ruleview.RouteView{
		{Type: "Prefix", Value: "/api/invoices",
			Cost: &ruleview.CostView{Source: "QueryParameter", Name: "limit", Default: 20}},
		{Type: "Prefix", Value: "/api/orders",
			Cost: &ruleview.CostView{Source: "QueryParameter", Name: "page_size", Default: 1}},
		{Type: "Prefix", Value: "/api/"},
	}, view.Blocks[0].Routes, "the routes")
}

// A route's methods are a set in the compiled form, and they render sorted, so
// that two replicas hash the same rendering into the same version.
func TestRender_sortsTheMethodsOfARoute(t *testing.T) {
	p := policy(100)
	p.Blocks[0].Target.Routes[0].Methods = []string{"PUT", "GET", "POST", "DELETE", "PATCH"}

	view := ruleview.Render(snapshotOf(t, p))

	require.Len(t, view.Blocks, 1)
	require.Len(t, view.Blocks[0].Routes, 1)
	assert.Equal(t, []string{"DELETE", "GET", "PATCH", "POST", "PUT"}, view.Blocks[0].Routes[0].Methods)
}

// Each operator renders in its own form: Equals and Contains carry one value,
// and the unary Exists and DoesNotExist carry none. The In form is in
// TestRender_sortsConditionValueSets.
func TestRender_rendersEachConditionInTheFormOfItsOperator(t *testing.T) {
	for _, tc := range []struct {
		name      string
		predicate model.Predicate
		want      ruleview.PredicateView
	}{
		{"Equals", model.Predicate{Key: "tenant", Operator: model.OperatorEquals, Value: "acme"},
			ruleview.PredicateView{Key: "tenant", Operator: "Equals", Value: "acme"}},
		{"Contains", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			ruleview.PredicateView{Key: "roles", Operator: "Contains", Value: "admin"}},
		{"Exists", model.Predicate{Key: "tenant", Operator: model.OperatorExists},
			ruleview.PredicateView{Key: "tenant", Operator: "Exists"}},
		{"DoesNotExist", model.Predicate{Key: "tenant", Operator: model.OperatorDoesNotExist},
			ruleview.PredicateView{Key: "tenant", Operator: "DoesNotExist"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy(100)
			p.Mappings = []model.KeyMapping{
				{Key: "tenant", Claim: "org_id"},
				{Key: "roles", Claim: "roles", Type: model.ValueStringArray},
			}
			p.Blocks[0].Rules[0].Matches = []model.Predicate{tc.predicate}

			view := ruleview.Render(snapshotOf(t, p))

			require.Len(t, view.Blocks, 1)
			require.Len(t, view.Blocks[0].Rules, 1)
			assert.Equal(t, []ruleview.PredicateView{tc.want}, view.Blocks[0].Rules[0].Matches,
				"the matches of %+v", tc.predicate)
		})
	}
}

// The keys whose value is a set, the array claims, are listed sorted, and no
// string key is among them.
func TestRender_listsTheArrayValuedKeysSorted(t *testing.T) {
	p := policy(100)
	p.Mappings = []model.KeyMapping{
		{Key: "roles", Claim: "roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org_id"},
		{Key: "entitlements", Claim: "entitlements", Type: model.ValueStringArray},
	}

	view := ruleview.Render(snapshotOf(t, p))

	assert.Equal(t, []string{"entitlements", "roles"}, view.ListValuedKeys)
}
