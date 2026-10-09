package management

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
)

func TestDomains_summarizesTheEnforcedDomain(t *testing.T) {
	h := newTestAPI(t)

	var list DomainList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil), http.StatusOK, &list)

	require.Len(t, list.Items, 1, "GET /domains over a rule set of one domain")
	summary := list.Items[0]
	assert.Equal(t, testDomain, summary.Domain)
	assert.Equal(t, h.version, summary.RuleSetVersion)
	assert.Equal(t, 3, summary.Blocks)
	assert.Equal(t, 6, summary.Rules)
	assert.Subset(t, summary.EffectiveKeys, []string{"plan", "roles"}, "the keys the policy maps")
	assert.Equal(t, []string{"roles"}, summary.ListValuedKeys)
}

// blockNames returns the names of the listed blocks, in listing order.
func blockNames(view ruleview.RuleSetView) []string {
	out := make([]string, 0, len(view.Blocks))
	for _, block := range view.Blocks {
		out = append(out, block.Block)
	}
	return out
}

func TestRules_reportsTheCompiledSet(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules", listedCaller, nil),
		http.StatusOK, &view)

	assert.Equal(t, testDomain, view.Domain)
	assert.Equal(t, h.version, view.RuleSetVersion)
	// Blocks come in the order the one policy authored them; there is no
	// second object to order against.
	require.Equal(t, []string{"cascade", "orders", "by-order"}, blockNames(view))

	cascade := view.Blocks[0]
	require.Len(t, cascade.Rules, 3, "rules of the cascade block")
	assert.Equal(t, "FirstMatch", cascade.Mode, "block mode mirrors the custom resource")
	assert.Equal(t, "bypass", cascade.Rules[0].Mode, "rule mode is the runtime vocabulary")
	everyone := cascade.Rules[2]
	assert.Equal(t, []string{"sub"}, everyone.Axes, "axes of %s", everyone.ID)
	require.Len(t, everyone.Rates, 1, "rates of %s", everyone.ID)
	assert.Equal(t, int64(60), everyone.Rates[0].PeriodSeconds, "the rate of %s", everyone.ID)
	assert.Equal(t, "1m0s", everyone.Rates[0].Period, "the rate of %s", everyone.ID)
}

// Unscoped, no rule is annotated: an annotation without a question would be an
// assertion about every possible client.
func TestRules_annotatesNoRuleWithoutAnIdentityScope(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules", listedCaller, nil),
		http.StatusOK, &view)

	assert.Equal(t, map[string]annotation{
		"cascade/internal":  {},
		"cascade/premium":   {},
		"cascade/everyone":  {},
		"orders/per-client": {},
		"orders/support":    {},
		"by-order/each":     {},
	}, annotationsByID(view))
}

func TestRules_filtersByTheEnginesOwnRouteMatcher(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?path=/api/orders&method=GET", listedCaller, nil),
		http.StatusOK, &view)

	assert.Equal(t, []string{"orders"}, blockNames(view), "GET /rules?path=/api/orders&method=GET")
}

func TestRules_refusesAMethodWithoutAPath(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?method=GET", listedCaller, nil)

	body := requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"method"}, body.Meta.Fields)
}

func TestRules_annotatesAScopedListing(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?axis.sub=prometheus", listedCaller, nil),
		http.StatusOK, &view)

	annotations := annotationsByID(view)
	assert.Equal(t, ruleview.ApplicabilityAlways, annotations["cascade/internal"].Applicability, "cascade/internal")
	assert.Equal(t, ruleview.ApplicabilityNever, annotations["cascade/everyone"].Applicability, "cascade/everyone")
}

// annotation is the part of a rule view the applicability tests compare.
type annotation struct {
	Applicability string
	ConditionalOn []ruleview.ApplicabilityGate
}

func annotationsByID(view ruleview.RuleSetView) map[string]annotation {
	out := map[string]annotation{}
	for _, block := range view.Blocks {
		for _, rule := range block.Rules {
			out[rule.ID] = annotation{Applicability: rule.Applicability, ConditionalOn: rule.ConditionalOn}
		}
	}
	return out
}

// The route the path matches decides a capture: through the prefix route no
// order_id reaches the cascade, so items-per-order never applies and
// orders-per-client always does; through the template route it is the
// reverse. Without a path the capture is open, and absent=order_id decides it
// the way the prefix route does; without a method it stays open where the
// routes disagree. The listing used to report items-per-order as always for
// every path, against what the simulation of the same request decided.
func TestRules_judgesACaptureKeyedRuleTheWayADecisionWould(t *testing.T) {
	h := newTestAPI(t, orderCascadeBlocks()...)
	const items, perClient = "order-ops/items-per-order", "order-ops/orders-per-client"
	always := annotation{Applicability: ruleview.ApplicabilityAlways}
	never := annotation{Applicability: ruleview.ApplicabilityNever}
	open := map[string]annotation{
		items: {
			Applicability: ruleview.ApplicabilityConditional,
			ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "order_id"}},
		},
		perClient: {
			Applicability: ruleview.ApplicabilityConditional,
			ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: items}},
		},
	}

	cases := map[string]struct {
		query string
		want  map[string]annotation
	}{
		"the prefix route carries no capture": {
			query: "path=/api/orders&method=POST&axis.sub=dave",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"the template route carries the capture": {
			query: "path=/api/orders/42/items&method=GET&axis.sub=dave",
			want:  map[string]annotation{items: always, perClient: never},
		},
		"the caller repeats what the route decided": {
			query: "path=/api/orders/42/items&method=GET&axis.sub=dave&axis.order_id=42",
			want:  map[string]annotation{items: always, perClient: never},
		},
		"no path leaves the capture open": {
			query: "axis.sub=dave",
			want:  open,
		},
		"known-absent decides it without a path": {
			query: "axis.sub=dave&absent=order_id",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"known-absent agreeing with the prefix route": {
			query: "path=/api/orders&method=POST&axis.sub=dave&absent=order_id",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"no method leaves a capture the routes disagree on open": {
			query: "path=/api/orders/42/items&axis.sub=dave",
			want:  open,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, listedCaller, nil), http.StatusOK, &view)
			assert.Equal(t, tc.want, annotationsByID(view), "GET /rules?%s", tc.query)
		})
	}
}

// A capture the caller declares has to agree with what the route decides; a
// contradiction is refused with the parameter named, because one of the two
// is a typo.
func TestRules_refusesACaptureThatContradictsThePath(t *testing.T) {
	h := newTestAPI(t, orderCascadeBlocks()...)

	cases := map[string]struct{ query, field string }{
		"a value on a route that produces none": {
			query: "path=/api/orders&method=POST&axis.sub=dave&axis.order_id=42", field: "axis.order_id",
		},
		"a value other than the one the route produced": {
			query: "path=/api/orders/42/items&method=GET&axis.sub=dave&axis.order_id=7", field: "axis.order_id",
		},
		"known-absent on a route that produces it": {
			query: "path=/api/orders/42/items&method=GET&axis.sub=dave&absent=order_id", field: "absent",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, listedCaller, nil),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields, "GET /rules?%s", tc.query)
		})
	}
}

// A capture that shadows a mapped key is judged as in a decision: on the
// prefix route the identity's plan applies and is not refused as a
// contradiction, on the template route the route's plan replaces it, and
// where the method picks the route the plan is open.
func TestRules_judgesAShadowedKeyByTheRouteThatProducesIt(t *testing.T) {
	h := newTestAPI(t, planCascadeBlocks()...)
	const silverOnly, perClient = "plan-ops/silver-only", "plan-ops/per-client"
	always := annotation{Applicability: ruleview.ApplicabilityAlways}
	never := annotation{Applicability: ruleview.ApplicabilityNever}
	open := map[string]annotation{
		silverOnly: {
			Applicability: ruleview.ApplicabilityConditional,
			ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "plan"}},
		},
		perClient: {
			Applicability: ruleview.ApplicabilityConditional,
			ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: silverOnly}},
		},
	}

	cases := map[string]struct {
		query string
		want  map[string]annotation
	}{
		"the identity's plan applies on the prefix route": {
			query: "path=/plans&method=POST&axis.sub=dave&axis.plan=gold",
			want:  map[string]annotation{silverOnly: never, perClient: always},
		},
		"no plan from either side leaves the rule open": {
			query: "path=/plans&method=POST&axis.sub=dave",
			want:  open,
		},
		"the route's plan replaces the identity's on the template route": {
			query: "path=/plans/silver/items&method=GET&axis.sub=dave&axis.plan=gold",
			want:  map[string]annotation{silverOnly: always, perClient: never},
		},
		"the method picks the route, so the plan is open": {
			query: "path=/plans/silver/items&axis.sub=dave&axis.plan=gold",
			want:  open,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, listedCaller, nil), http.StatusOK, &view)
			assert.Equal(t, tc.want, annotationsByID(view), "GET /rules?%s", tc.query)
		})
	}
}

// A listing scoped by a complete identity and a simulation of the same request
// agree on which rules apply: the rules the listing marks always are the rules
// the simulation applies, whichever route the request takes into the cascade.
func TestRules_alwaysAgreesWithTheSimulation(t *testing.T) {
	h := newTestAPI(t, orderCascadeBlocks()...)

	cases := map[string]struct {
		path, method string
		want         []string
	}{
		"through the prefix route": {
			path: "/api/orders", method: http.MethodPost, want: []string{"order-ops/orders-per-client"},
		},
		"through the template route": {
			path: "/api/orders/42/items", method: http.MethodGet, want: []string{"order-ops/items-per-order"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules?path="+tc.path+
				"&method="+tc.method+"&axis.sub=dave", listedCaller, nil), http.StatusOK, &view)
			var simulation SimulationResponse
			decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
				Domain: testDomain, Path: tc.path, Method: tc.method,
				Keys: map[string][]string{"sub": {"dave"}},
			}), http.StatusOK, &simulation)

			assert.Equal(t, tc.want, alwaysRuleIDs(view), "the rules the listing marks always for %s %s",
				tc.method, tc.path)
			assert.Equal(t, tc.want, appliedRuleIDs(simulation), "the rules the simulation applies to %s %s",
				tc.method, tc.path)
		})
	}
}

func alwaysRuleIDs(view ruleview.RuleSetView) []string {
	annotations := annotationsByID(view)
	out := make([]string, 0, len(annotations))
	for id, rule := range annotations {
		if rule.Applicability == ruleview.ApplicabilityAlways {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func appliedRuleIDs(simulation SimulationResponse) []string {
	out := make([]string, 0, len(simulation.Rules))
	for _, rule := range simulation.Rules {
		out = append(out, rule.ID)
	}
	sort.Strings(out)
	return out
}

func TestRules_reportsAnUnknownDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/gateway.typo/rules", listedCaller, nil),
		http.StatusNotFound, CodeNotFound)
}

// counterState is the part of a listed counter that says whose counter it is
// and what it would do to the next request.
type counterState struct {
	RuleID    string
	Axes      map[string]string
	Mode      string
	Limit     int64
	Remaining int64
	Limited   bool
}

func statesOf(items []CounterView) []counterState {
	out := make([]counterState, 0, len(items))
	for _, item := range items {
		out = append(out, counterState{
			RuleID: item.RuleID, Axes: item.Axes, Mode: item.Mode,
			Limit: item.Limit, Remaining: item.Remaining, Limited: item.Limited,
		})
	}
	return out
}

func TestCounters_reportsWhatTheNextRequestWouldMeet(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {"alice"}}, 4)
	h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {"bob"}}, 1)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=cascade/everyone", listedCaller, nil),
		http.StatusOK, &list)

	assert.ElementsMatch(t, []counterState{
		{
			RuleID: "cascade/everyone", Axes: map[string]string{"sub": "alice"}, Mode: "enforce",
			Limit: 100, Remaining: 96, Limited: false,
		},
		{
			RuleID: "cascade/everyone", Axes: map[string]string{"sub": "bob"}, Mode: "enforce",
			Limit: 100, Remaining: 99, Limited: false,
		},
	}, statesOf(list.Items))
	assert.Equal(t, 2, list.Scanned)
	assert.Empty(t, list.NextCursor, "a listing that reached the end")
}

// Reading must not spend anyone's budget: the listing goes through Peek, so two
// listings in a row report the budget the one request left.
func TestCounters_aListingChargesNothing(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {"alice"}}, 1)

	target := BasePath + "/domains/" + testDomain + "/counters?ruleId=cascade/everyone"
	var first, second CounterList
	decode(t, h.call(t, http.MethodGet, target, listedCaller, nil), http.StatusOK, &first)
	decode(t, h.call(t, http.MethodGet, target, listedCaller, nil), http.StatusOK, &second)

	require.Len(t, first.Items, 1, "the first listing")
	require.Len(t, second.Items, 1, "the second listing")
	assert.Equal(t, int64(99), first.Items[0].Remaining, "remaining in the first listing")
	assert.Equal(t, int64(99), second.Items[0].Remaining, "remaining in the second listing")
}

func TestCounters_limitedListsOnlyTheRefusingCounters(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&limited=true",
		listedCaller, nil), http.StatusOK, &list)

	require.Len(t, list.Items, 1, "counters listed with limited=true")
	assert.Equal(t, map[string]string{"sub": "crawler"}, list.Items[0].Axes)
	assert.True(t, list.Items[0].Limited, "limited of the counter of crawler")
	assert.Positive(t, list.Items[0].RetryAfterSeconds, "retryAfterSeconds of the counter of crawler")
}

func TestCounters_refusesAFalseThatPretendsToNarrow(t *testing.T) {
	h := newTestAPI(t)
	body := requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?limited=false", listedCaller, nil),
		http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"limited"}, body.Meta.Fields)
}

func TestCounters_repeatedValuesOfOneAxisSelectEitherValue(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {client}}, 1)
	}

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?axis.sub=alice&axis.sub=carol",
		listedCaller, nil), http.StatusOK, &list)

	assert.ElementsMatch(t, []string{"alice", "carol"}, subsOf(list.Items))
}

// A counter whose rule does not declare the named axis never matches.
func TestCounters_anAxisTheRuleLacksMatchesNothing(t *testing.T) {
	h := newTestAPI(t, wholeDomainBlocks()...)
	h.spend(t, "/anything", nil, 1)

	var all, filtered CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		listedCaller, nil), http.StatusOK, &all)
	require.Len(t, all.Items, 1, "the unfiltered listing of a rule without axes")
	require.Empty(t, all.Items[0].Axes, "the unfiltered listing of a rule without axes")

	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters?axis.sub=alice",
		listedCaller, nil), http.StatusOK, &filtered)
	assert.Empty(t, filtered.Items, "the listing with axis.sub=alice")
}

// Two pages of two hold the four counters of a rule, each once, in whatever
// order the store walks them.
func TestCounters_pagesThroughTheCountersOfARuleWithACursor(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol", "dave"} {
		h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {client}}, 1)
	}

	pages := h.listPages(t, BasePath+"/domains/"+testDomain+"/counters?ruleId=cascade/everyone&pageSize=2")

	require.Len(t, pages, 2, "pages of 2 over 4 counters")
	assert.Len(t, pages[0].Items, 2, "items on the first page")
	assert.True(t, pages[0].Truncated, "truncated of the first page")
	assert.Len(t, pages[1].Items, 2, "items on the last page")
	assert.ElementsMatch(t, []string{"alice", "bob", "carol", "dave"},
		append(subsOf(pages[0].Items), subsOf(pages[1].Items)...))
}

// The same cursor under a different selection is refused rather than silently
// answered with another listing.
func TestCounters_refusesACursorPresentedUnderAnotherSelection(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol", "dave"} {
		h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {client}}, 1)
	}
	var first CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=cascade/everyone&pageSize=2", listedCaller, nil),
		http.StatusOK, &first)
	require.NotEmpty(t, first.NextCursor, "the first page of 2 over 4 counters")

	body := requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?pageSize=2&cursor="+url.QueryEscape(first.NextCursor),
		listedCaller, nil), http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"cursor"}, body.Meta.Fields)
}

func TestCounters_refusesAPageSizeOverTheCeiling(t *testing.T) {
	h := newTestAPI(t)
	body := requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?pageSize=5000", listedCaller, nil),
		http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"pageSize"}, body.Meta.Fields)
}

func TestSimulation_reportsTheDecisionOfTheMatchingRule(t *testing.T) {
	h := newTestAPI(t)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain,
		Path:   "/api/invoices/1",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeySub: {"alice"}},
	}), http.StatusOK, &response)

	assert.True(t, response.Allowed, "allowed of a request under every limit")
	assert.Empty(t, response.RefusalReason)
	assert.Equal(t, []string{"sub"}, response.ExtractedKeys)
	require.NotNil(t, response.Headers, "the answer names the binding window")
	assert.Equal(t, "cascade", response.Headers.Block)
	assert.Equal(t, "everyone", response.Headers.Rule)
	assert.Equal(t, "gcra", response.Headers.Algorithm)
	assert.Equal(t, int64(60), response.Headers.PeriodSeconds)
	assert.Nil(t, response.Headers.EffectiveWindowSeconds,
		"the simulation judges the untouched window before the charge, at its whole capacity")

	require.Len(t, response.Rules, 1, "the rules the simulation applies")
	assert.Equal(t, "cascade/everyone", response.Rules[0].ID)
	assert.Equal(t, "enforce", response.Rules[0].Mode)
	assert.True(t, response.Rules[0].Allowed, "allowed of cascade/everyone")
}

// Nothing a simulation judges is reserved: a listing after it sees no counter.
func TestSimulation_chargesNothing(t *testing.T) {
	h := newTestAPI(t)

	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain,
		Path:   "/api/invoices/1",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeySub: {"alice"}},
	}), http.StatusOK, nil)

	var list CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		listedCaller, nil), http.StatusOK, &list)
	assert.Empty(t, list.Items, "counters listed after the simulation")
}

// A window the request has touched before holds less than its capacity, so
// the simulation reports the effective window, the t of the ratelimit field:
// the seconds until the window admits one request more than remaining, never
// longer than the reset.
func TestSimulation_reportsTheEffectiveWindowOfATouchedWindow(t *testing.T) {
	h := newTestAPI(t)
	keys := map[string][]string{model.KeySub: {"alice"}}
	h.spend(t, "/api/invoices/1", keys, 1)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain,
		Path:   "/api/invoices/1",
		Method: http.MethodGet,
		Keys:   keys,
	}), http.StatusOK, &response)

	assert.True(t, response.Allowed, "allowed of a request under every limit")
	require.NotNil(t, response.Headers, "the answer names the binding window")
	require.NotNil(t, response.Headers.EffectiveWindowSeconds, "a touched window has a next request to wait for")
	require.NotNil(t, response.Headers.ResetAfterSeconds, "a touched window resets")
	assert.Positive(t, *response.Headers.EffectiveWindowSeconds)
	assert.LessOrEqual(t, *response.Headers.EffectiveWindowSeconds, *response.Headers.ResetAfterSeconds,
		"the effective window outlasts the reset")
}

func TestSimulation_namesTheBindingWindowOnARefusal(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain,
		Path:   "/api/orders",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeySub: {"crawler"}},
	}), http.StatusOK, &response)

	assert.False(t, response.Allowed, "allowed of a request over its limit")
	assert.Equal(t, ReasonRateLimited, response.RefusalReason)
	require.NotNil(t, response.Headers, "the answer names the binding window")
	assert.Equal(t, "orders", response.Headers.Block)
	assert.Equal(t, "per-client", response.Headers.Rule)
	require.NotNil(t, response.Headers.RetryAfterSeconds, "a refusal that waiting cures carries a retry hint")
	require.NotNil(t, response.Headers.EffectiveWindowSeconds, "a refused window has a next request to wait for")
	assert.Positive(t, *response.Headers.RetryAfterSeconds)
	assert.Equal(t, *response.Headers.RetryAfterSeconds, *response.Headers.EffectiveWindowSeconds,
		"a refusal of cost 1 waits one effective window")
	require.Len(t, response.Rules, 1, "the rules the simulation applies")
	assert.Equal(t, "orders/per-client", response.Rules[0].ID)
	assert.Equal(t, ReasonRateLimited, response.Rules[0].RefusalReason)
}

// A cost no window can ever hold is refused permanently, and no retry hint may
// be offered for it.
func TestSimulation_reportsCapacityExceededWithoutARetryHint(t *testing.T) {
	h := newTestAPI(t)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain,
		Path:   "/api/orders",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeySub: {"alice"}},
		Cost:   1_000_000,
	}), http.StatusOK, &response)

	assert.False(t, response.Allowed, "allowed of a cost over every window's capacity")
	assert.Equal(t, ReasonCapacityExceeded, response.RefusalReason)
	require.NotNil(t, response.Headers, "the answer names the binding window")
	assert.Equal(t, "orders", response.Headers.Block)
	assert.Equal(t, "per-client", response.Headers.Rule)
	assert.Nil(t, response.Headers.RetryAfterSeconds, "retryAfterSeconds of the headers")
	assert.Nil(t, response.Headers.EffectiveWindowSeconds, "a window at its full capacity has no next request")
	require.Len(t, response.Rules, 1, "the rules the simulation applies")
	assert.Equal(t, "orders/per-client", response.Rules[0].ID)
	assert.Equal(t, ReasonCapacityExceeded, response.Rules[0].RefusalReason)
	assert.Nil(t, response.Rules[0].RetryAfterSeconds, "retryAfterSeconds of orders/per-client")
}

func TestSimulation_refusesTheCombinationsTheFormsForbid(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]struct {
		request SimulationRequest
		field   string
	}{
		"no domain": {request: SimulationRequest{Path: "/api/orders", Method: http.MethodGet}, field: "domain"},
		"no path":   {request: SimulationRequest{Domain: testDomain, Method: http.MethodGet}, field: "path"},
		"no method": {request: SimulationRequest{Domain: testDomain, Path: "/api/orders"}, field: "method"},
		"the token form carrying keys": {
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
				IdentitySource: identityToken, Token: "t",
				Keys: map[string][]string{model.KeySub: {"alice"}},
			},
			field: "keys",
		},
		"the keys form carrying a token": {
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
				IdentitySource: identityKeys, Token: "t",
				Keys: map[string][]string{model.KeySub: {"alice"}},
			},
			field: "token",
		},
		"an unknown identity source": {
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
				IdentitySource: "guess",
			},
			field: "identitySource",
		},
		"a token one byte over the limit": {
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
				Token: strings.Repeat("x", maxSimulationToken+1),
			},
			field: "token",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, tc.request),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields)
		})
	}
}

// The token is write-only: it must not come back in the answer, and it must not
// be quoted in a refusal either.
func TestSimulation_neverEchoesTheToken(t *testing.T) {
	h := newTestAPI(t)
	const secret = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXBheWxvYWQ.sig"

	cases := []struct {
		name   string
		domain string
		status int
	}{
		{name: "an answer", domain: testDomain, status: http.StatusOK},
		{name: "a refusal", domain: "gateway.typo", status: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
				Domain: tc.domain, Path: "/api/orders", Method: http.MethodGet,
				IdentitySource: identityToken, Token: secret,
			})

			require.Equal(t, tc.status, recorder.Code, "body: %s", recorder.Body.String())
			assert.NotContains(t, recorder.Body.String(), secret)
		})
	}
}

func TestSimulation_refusesAnUnknownField(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, map[string]any{
		"domain": testDomain, "path": "/api", "method": "GET", "identity": "alice",
	})

	requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

func TestAPI_reportsAnUnknownRouteAsNotFound(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet, BasePath+"/nothing", listedCaller, nil),
		http.StatusNotFound, CodeNotFound)
}

// A path filter with no method means "any method". Reading it as the engine
// does, where a request always carries one, drops every block whose routes
// name their methods, and an operator asking which rules guard /api/orders is
// told the path is unlimited while two rules count it.
func TestRules_aPathWithoutAMethodKeepsMethodRestrictedBlocks(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?path=/api/orders", listedCaller, nil),
		http.StatusOK, &view)

	assert.Equal(t, []string{"orders"}, blockNames(view),
		"the orders block targets this prefix for GET and POST; a listing without a method must show it")
}

// Reading parameters by name and ignoring the rest is safe only where every
// parameter narrows. dryRun, expectedRuleSetVersion and limited widen, so a
// typo in one of them has to be an error rather than a silently wider command.
func TestReset_refusesAMisspelledSafetyParameter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	body := requireError(t, h.reset(t, "ruleId=orders/per-client&axis.sub=alice&dryrun=true",
		"key-1", listedCaller), http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"dryrun"}, body.Meta.Fields,
		"the answer names the parameter, because the caller cannot see the whitelist")

	remaining, found := h.remaining(t, "alice")
	assert.True(t, found, "a refused command deleted the counter")
	assert.Equal(t, int64(2), remaining, "the remaining budget of alice")
}

// The whitelist is checked ahead of the replay, so a retry carrying an unknown
// parameter is refused exactly as the first call would have been. Answering it
// from the record instead would make the same query legal or illegal depending
// on whether the key had been seen.
func TestReset_refusesAMisspelledSafetyParameterOnARetry(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	const selector = "ruleId=orders/per-client&axis.sub=alice"
	decode(t, h.reset(t, selector, "key-1", listedCaller), http.StatusOK, nil)

	body := requireError(t, h.reset(t, selector+"&dryrun=true", "key-1", listedCaller),
		http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"dryrun"}, body.Meta.Fields)
}

func TestQueryNames_areWhitelistedOnEveryReadEndpoint(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]struct{ target, field string }{
		"the rule listing":    {target: "/rules?path=/api/orders&methods=GET", field: "methods"},
		"the counter listing": {target: "/counters?ruleId=orders/per-client&pagesize=10", field: "pagesize"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+tc.target, listedCaller, nil),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields, "GET %s", tc.target)
		})
	}
}

// The whitelist admits the axis family whole: those names come from the keys of
// the domain, not from this package.
func TestQueryNames_admitTheAxisFamily(t *testing.T) {
	h := newTestAPI(t)

	response := h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?axis.sub=alice&axis.order_id=4711", listedCaller, nil)
	assert.Equal(t, http.StatusOK, response.Code, "body: %s", response.Body.String())
}

// axesOf returns the axes of each listed counter, in listing order.
func axesOf(items []CounterView) []map[string]string {
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Axes)
	}
	return out
}

// Axis filters of two names select a counter only when it carries a selected
// value of each. by-order/each counts by sub and order_id, so of the three
// identities spent here only alice's order 4711 is listed, once for each of
// the rule's two windows; alice's other order and bob's same order match one
// name each.
func TestCounters_axesOfTwoNamesSelectOnlyTheCountersMatchingBoth(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.spend(t, "/api/orders/4712", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"bob"}}, 1)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=by-order/each&axis.sub=alice&axis.order_id=4711",
		listedCaller, nil), http.StatusOK, &list)

	assert.ElementsMatch(t, []map[string]string{
		{"sub": "alice", "order_id": "4711"},
		{"sub": "alice", "order_id": "4711"},
	}, axesOf(list.Items))
}

// pageSize admits 1 to 500, both ends included.
// TestCounters_refusesAPageSizeOutsideItsRange holds the sizes past either end.
func TestCounters_acceptsAPageSizeAtEitherEndOfItsRange(t *testing.T) {
	for _, tc := range []struct{ name, pageSize string }{
		{name: "the floor", pageSize: "1"},
		{name: "the ceiling", pageSize: "500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {"alice"}}, 1)

			var list CounterList
			decode(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/counters?pageSize="+tc.pageSize, listedCaller, nil),
				http.StatusOK, &list)

			assert.Equal(t, []string{"alice"}, subsOf(list.Items), "GET counters?pageSize=%s", tc.pageSize)
		})
	}
}

// A page size outside 1 to 500, or not a whole number, is refused and the
// refusal names the parameter. TestCounters_refusesAPageSizeOverTheCeiling holds
// a size far past the ceiling.
func TestCounters_refusesAPageSizeOutsideItsRange(t *testing.T) {
	for _, tc := range []struct{ name, pageSize string }{
		{name: "one over the ceiling", pageSize: "501"},
		{name: "zero", pageSize: "0"},
		{name: "a negative size", pageSize: "-1"},
		{name: "not a number", pageSize: "ten"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)

			body := requireError(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/counters?pageSize="+tc.pageSize, listedCaller, nil),
				http.StatusBadRequest, CodeInvalidRequest)

			assert.Equal(t, []string{"pageSize"}, body.Meta.Fields, "GET counters?pageSize=%s", tc.pageSize)
		})
	}
}

// A shadow counter counts and never refuses: once crawler has spent the 3
// requests an hour of a shadow per-client rule, its next request is still
// admitted, and the listing reports the counter in mode shadow, limited, with
// nothing left.
func TestCounters_listsAShadowCounterAsLimitedWhileItsRequestsAreAdmitted(t *testing.T) {
	blocks := orderBlocks()
	blocks[0].Rules[0].Behavior = model.BehaviorShadow
	h := newTestAPI(t, blocks...)
	crawler := map[string][]string{model.KeySub: {"crawler"}}
	h.spend(t, "/api/orders", crawler, 3)

	fourth, err := h.engine.Decide(context.Background(), engine.Request{
		Path: "/api/orders", Method: http.MethodGet, Keys: crawler,
	})
	require.NoError(t, err, "the decision on the fourth request of crawler")
	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client", listedCaller, nil),
		http.StatusOK, &list)

	assert.True(t, fourth.Allowed, "allowed of the fourth request of crawler, past the shadow limit of 3")
	assert.Equal(t, []counterState{{
		RuleID: "orders/per-client", Axes: map[string]string{"sub": "crawler"}, Mode: "shadow",
		Limit: 3, Remaining: 0, Limited: true,
	}}, statesOf(list.Items))
}

// The token may be as long as 8 KiB (8192 bytes): a token of exactly that
// length is judged. The token one byte longer is a row of
// TestSimulation_refusesTheCombinationsTheFormsForbid.
func TestSimulation_acceptsATokenOfExactlyTheLimit(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, SimulationRequest{
		Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
		Token: strings.Repeat("x", 8192),
	})

	assert.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
}

// A negative cost, an identity key without values, and a pure form without
// its one source are refused, and the refusal names the field at fault.
func TestSimulation_refusesAMissingIdentityOrANegativeCost(t *testing.T) {
	h := newTestAPI(t)

	cases := []struct {
		name    string
		request SimulationRequest
		field   string
	}{
		{
			name: "a negative cost",
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet, Cost: -1,
			},
			field: "cost",
		},
		{
			name: "a key without values",
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
				Keys: map[string][]string{model.KeySub: {}},
			},
			field: "keys",
		},
		{
			name: "the keys form without keys",
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet, IdentitySource: identityKeys,
			},
			field: "keys",
		},
		{
			name: "the token form without a token",
			request: SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: http.MethodGet, IdentitySource: identityToken,
			},
			field: "token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := requireError(t, h.call(t, http.MethodPost, BasePath+"/simulations", listedCaller, tc.request),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields, "POST simulations %+v", tc.request)
		})
	}
}
