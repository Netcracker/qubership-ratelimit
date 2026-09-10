package management

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
)

func TestDomains_reportsTheEnforcedSetAndItsVersion(t *testing.T) {
	h := newTestAPI(t)

	var list DomainList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil), http.StatusOK, &list)

	require.Len(t, list.Items, 1)
	summary := list.Items[0]
	require.Equal(t, testDomain, summary.Domain)
	require.Equal(t, h.version, summary.RuleSetVersion)
	require.Equal(t, 3, summary.Blocks)
	require.Equal(t, 6, summary.Rules)
	require.Contains(t, summary.EffectiveKeys, "plan")
	require.Equal(t, []string{"roles"}, summary.ListValuedKeys)
}

func TestRules_reportsTheCompiledSet(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules", viewerRoles(), nil),
		http.StatusOK, &view)

	require.Equal(t, testDomain, view.Domain)
	require.Equal(t, h.version, view.RuleSetVersion)
	require.Len(t, view.Blocks, 3)

	// Blocks come in the order the one policy authored them; there is no
	// second object to order against.
	require.Equal(t, []string{"cascade", "orders", "by-order"},
		[]string{view.Blocks[0].Block, view.Blocks[1].Block, view.Blocks[2].Block})

	cascade := view.Blocks[0]
	require.Equal(t, "FirstMatch", cascade.Mode, "block mode mirrors the custom resource")
	require.Equal(t, "bypass", cascade.Rules[0].Mode, "rule mode is the runtime vocabulary")
	require.Equal(t, []string{"client"}, cascade.Rules[2].Axes)
	require.Equal(t, int64(60), cascade.Rules[2].Rates[0].PeriodSeconds)
	require.Equal(t, "1m0s", cascade.Rules[2].Rates[0].Period)

	// Unscoped, no rule is annotated: an annotation without a question would be
	// an assertion about every possible client.
	for _, block := range view.Blocks {
		for _, rule := range block.Rules {
			require.Empty(t, rule.Applicability)
		}
	}
}

func TestRules_filtersByTheEnginesOwnRouteMatcher(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?path=/api/orders&method=GET", viewerRoles(), nil),
		http.StatusOK, &view)

	require.Len(t, view.Blocks, 1)
	require.Equal(t, "orders", view.Blocks[0].Block)
}

func TestRules_refusesAMethodWithoutAPath(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?method=GET", viewerRoles(), nil)

	body := requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	require.Equal(t, []string{"method"}, body.Meta.Fields)
}

func TestRules_annotatesAScopedListing(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?axis.client=prometheus", viewerRoles(), nil),
		http.StatusOK, &view)

	byID := map[string]ruleview.RuleView{}
	for _, block := range view.Blocks {
		for _, rule := range block.Rules {
			byID[rule.ID] = rule
		}
	}
	require.Equal(t, ruleview.ApplicabilityAlways, byID["cascade/internal"].Applicability)
	require.Equal(t, ruleview.ApplicabilityNever, byID["cascade/everyone"].Applicability)
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

	cases := map[string]struct {
		query string
		want  map[string]annotation
	}{
		"the prefix route carries no capture": {
			query: "path=/api/orders&method=POST&axis.client=dave",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"the template route carries the capture": {
			query: "path=/api/orders/42/items&method=GET&axis.client=dave",
			want:  map[string]annotation{items: always, perClient: never},
		},
		"the caller repeats what the route decided": {
			query: "path=/api/orders/42/items&method=GET&axis.client=dave&axis.order_id=42",
			want:  map[string]annotation{items: always, perClient: never},
		},
		"no path leaves the capture open": {
			query: "axis.client=dave",
			want: map[string]annotation{
				items: {
					Applicability: ruleview.ApplicabilityConditional,
					ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "order_id"}},
				},
				perClient: {
					Applicability: ruleview.ApplicabilityConditional,
					ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: items}},
				},
			},
		},
		"known-absent decides it without a path": {
			query: "axis.client=dave&absent=order_id",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"known-absent agreeing with the prefix route": {
			query: "path=/api/orders&method=POST&axis.client=dave&absent=order_id",
			want:  map[string]annotation{items: never, perClient: always},
		},
		"no method leaves a capture the routes disagree on open": {
			query: "path=/api/orders/42/items&axis.client=dave",
			want: map[string]annotation{
				items: {
					Applicability: ruleview.ApplicabilityConditional,
					ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "order_id"}},
				},
				perClient: {
					Applicability: ruleview.ApplicabilityConditional,
					ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: items}},
				},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, viewerRoles(), nil), http.StatusOK, &view)
			require.Equal(t, tc.want, annotationsByID(view), "GET /rules?%s", tc.query)
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
			query: "path=/api/orders&method=POST&axis.client=dave&axis.order_id=42", field: "axis.order_id",
		},
		"a value other than the one the route produced": {
			query: "path=/api/orders/42/items&method=GET&axis.client=dave&axis.order_id=7", field: "axis.order_id",
		},
		"known-absent on a route that produces it": {
			query: "path=/api/orders/42/items&method=GET&axis.client=dave&absent=order_id", field: "absent",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, viewerRoles(), nil),
				http.StatusBadRequest, CodeInvalidRequest)
			require.Equal(t, []string{tc.field}, body.Meta.Fields, "GET /rules?%s", tc.query)
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
			query: "path=/plans&method=POST&axis.client=dave&axis.plan=gold",
			want:  map[string]annotation{silverOnly: never, perClient: always},
		},
		"no plan from either side leaves the rule open": {
			query: "path=/plans&method=POST&axis.client=dave",
			want:  open,
		},
		"the route's plan replaces the identity's on the template route": {
			query: "path=/plans/silver/items&method=GET&axis.client=dave&axis.plan=gold",
			want:  map[string]annotation{silverOnly: always, perClient: never},
		},
		"the method picks the route, so the plan is open": {
			query: "path=/plans/silver/items&axis.client=dave&axis.plan=gold",
			want:  open,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+"/rules?"+tc.query, viewerRoles(), nil), http.StatusOK, &view)
			require.Equal(t, tc.want, annotationsByID(view), "GET /rules?%s", tc.query)
		})
	}
}

// A listing scoped by a complete identity and a simulation of the same request
// agree on which rules apply: the rules the listing marks always are the rules
// the simulation applies, whichever route the request takes into the cascade.
func TestRules_alwaysAgreesWithTheSimulation(t *testing.T) {
	h := newTestAPI(t, orderCascadeBlocks()...)

	cases := map[string]struct{ path, method string }{
		"through the prefix route":   {path: "/api/orders", method: http.MethodPost},
		"through the template route": {path: "/api/orders/42/items", method: http.MethodGet},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var view ruleview.RuleSetView
			decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules?path="+tc.path+
				"&method="+tc.method+"&axis.client=dave", viewerRoles(), nil), http.StatusOK, &view)
			var simulation SimulationResponse
			decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
				Domain: testDomain, Path: tc.path, Method: tc.method,
				Keys: map[string][]string{"client": {"dave"}},
			}), http.StatusOK, &simulation)

			require.Equal(t, appliedRuleIDs(simulation), alwaysRuleIDs(view), "%s %s", tc.method, tc.path)
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
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/gateway.typo/rules", viewerRoles(), nil),
		http.StatusNotFound, CodeNotFound)
}

func TestCounters_reportsWhatTheNextRequestWouldMeet(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {"alice"}}, 4)
	h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {"bob"}}, 1)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=cascade/everyone", viewerRoles(), nil),
		http.StatusOK, &list)

	require.Len(t, list.Items, 2)
	require.Equal(t, 2, list.Scanned)
	require.Empty(t, list.NextCursor)

	alice := list.Items[0]
	require.Equal(t, "cascade/everyone", alice.RuleID)
	require.Equal(t, map[string]string{"client": "alice"}, alice.Axes)
	require.Equal(t, "enforce", alice.Mode)
	require.Equal(t, int64(100), alice.Limit)
	require.Equal(t, int64(96), alice.Remaining)
	require.False(t, alice.Limited)
}

// Reading must not spend anyone's budget: the listing goes through Peek.
func TestCounters_doNotChargeWhatTheyReport(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {"alice"}}, 1)

	target := BasePath + "/domains/" + testDomain + "/counters?ruleId=cascade/everyone"
	var first, second CounterList
	decode(t, h.call(t, http.MethodGet, target, viewerRoles(), nil), http.StatusOK, &first)
	decode(t, h.call(t, http.MethodGet, target, viewerRoles(), nil), http.StatusOK, &second)

	require.Equal(t, first.Items[0].Remaining, second.Items[0].Remaining)
}

func TestCounters_limitedSelectsOnlyTheRefusingOnes(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&limited=true",
		viewerRoles(), nil), http.StatusOK, &list)

	require.Len(t, list.Items, 1)
	require.Equal(t, map[string]string{"client": "crawler"}, list.Items[0].Axes)
	require.True(t, list.Items[0].Limited)
	require.Positive(t, list.Items[0].RetryAfterSeconds)
}

func TestCounters_refusesAFalseThatPretendsToNarrow(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?limited=false", viewerRoles(), nil),
		http.StatusBadRequest, CodeInvalidRequest)
}

func TestCounters_axisFiltersAreOrWithinANameAndAndBetweenNames(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {client}}, 1)
	}

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?axis.client=alice&axis.client=carol",
		viewerRoles(), nil), http.StatusOK, &list)

	require.Len(t, list.Items, 2)
	for _, item := range list.Items {
		require.Contains(t, []string{"alice", "carol"}, item.Axes["client"])
	}
}

// A counter whose rule does not declare the named axis never matches.
func TestCounters_anAxisTheRuleLacksMatchesNothing(t *testing.T) {
	h := newTestAPI(t, wholeDomainBlocks()...)
	h.spend(t, "/anything", nil, 1)

	var all, filtered CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		viewerRoles(), nil), http.StatusOK, &all)
	require.Len(t, all.Items, 1)
	require.Empty(t, all.Items[0].Axes)

	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters?axis.client=alice",
		viewerRoles(), nil), http.StatusOK, &filtered)
	require.Empty(t, filtered.Items)
}

func TestCounters_pagesWithACursorBoundToItsSelection(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol", "dave"} {
		h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {client}}, 1)
	}
	base := BasePath + "/domains/" + testDomain + "/counters?ruleId=cascade/everyone"

	var first CounterList
	decode(t, h.call(t, http.MethodGet, base+"&pageSize=2", viewerRoles(), nil), http.StatusOK, &first)
	require.Len(t, first.Items, 2)
	require.NotEmpty(t, first.NextCursor)
	require.True(t, first.Truncated)

	var second CounterList
	decode(t, h.call(t, http.MethodGet,
		base+"&pageSize=2&cursor="+url.QueryEscape(first.NextCursor), viewerRoles(), nil),
		http.StatusOK, &second)
	require.Len(t, second.Items, 2)
	require.Empty(t, second.NextCursor)

	// The two pages are disjoint and in key order.
	require.Less(t, first.Items[1].Key, second.Items[0].Key)

	// The same cursor under a different selection is refused rather than
	// silently answered with another listing.
	requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?pageSize=2&cursor="+url.QueryEscape(first.NextCursor),
		viewerRoles(), nil), http.StatusBadRequest, CodeInvalidRequest)
}

func TestCounters_refusesAPageSizeOverTheCeiling(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?pageSize=5000", viewerRoles(), nil),
		http.StatusBadRequest, CodeInvalidRequest)
}

func TestSimulation_reportsTheDecisionWithoutCharging(t *testing.T) {
	h := newTestAPI(t)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
		Domain: testDomain,
		Path:   "/api/quotes/1",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeyClient: {"alice"}},
	}), http.StatusOK, &response)

	require.True(t, response.Allowed)
	require.Empty(t, response.RefusalReason)
	require.NotNil(t, response.Headers)
	require.Equal(t, "gcra", response.Headers.Algorithm)
	require.Equal(t, int64(60), response.Headers.PeriodSeconds)
	require.Equal(t, []string{"client"}, response.ExtractedKeys)

	require.Len(t, response.Rules, 1)
	require.Equal(t, "cascade/everyone", response.Rules[0].ID)
	require.Equal(t, "enforce", response.Rules[0].Mode)
	require.True(t, response.Rules[0].Allowed)

	// Nothing was reserved: a listing sees an untouched counter.
	var list CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		viewerRoles(), nil), http.StatusOK, &list)
	require.Empty(t, list.Items)
}

func TestSimulation_namesTheBindingWindowOnARefusal(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
		Domain: testDomain,
		Path:   "/api/orders",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeyClient: {"crawler"}},
	}), http.StatusOK, &response)

	require.False(t, response.Allowed)
	require.Equal(t, ReasonRateLimited, response.RefusalReason)
	require.NotNil(t, response.Headers.RetryAfterSeconds)
	require.Positive(t, *response.Headers.RetryAfterSeconds)
	require.Equal(t, ReasonRateLimited, response.Rules[0].RefusalReason)
}

// A cost no window can ever hold is refused permanently, and no retry hint may
// be offered for it.
func TestSimulation_reportsCapacityExceededWithoutARetryHint(t *testing.T) {
	h := newTestAPI(t)

	var response SimulationResponse
	decode(t, h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
		Domain: testDomain,
		Path:   "/api/orders",
		Method: http.MethodGet,
		Keys:   map[string][]string{model.KeyClient: {"alice"}},
		Cost:   1_000_000,
	}), http.StatusOK, &response)

	require.False(t, response.Allowed)
	require.Equal(t, ReasonCapacityExceeded, response.RefusalReason)
	require.Nil(t, response.Headers.RetryAfterSeconds)
	require.Equal(t, ReasonCapacityExceeded, response.Rules[0].RefusalReason)
	require.Nil(t, response.Rules[0].RetryAfterSeconds)
}

func TestSimulation_refusesTheCombinationsTheFormsForbid(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]SimulationRequest{
		"no domain": {Path: "/api/orders", Method: http.MethodGet},
		"no path":   {Domain: testDomain, Method: http.MethodGet},
		"no method": {Domain: testDomain, Path: "/api/orders"},
		"the token form carrying keys": {
			Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
			IdentitySource: identityToken, Token: "t",
			Keys: map[string][]string{model.KeyClient: {"alice"}},
		},
		"the keys form carrying a token": {
			Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
			IdentitySource: identityKeys, Token: "t",
			Keys: map[string][]string{model.KeyClient: {"alice"}},
		},
		"an unknown identity source": {
			Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
			IdentitySource: "guess",
		},
		"an oversized token": {
			Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
			Token: strings.Repeat("x", maxSimulationToken+1),
		},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			requireError(t, h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), request),
				http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

// The token is write-only: it must not come back in the answer, and it must not
// be quoted in a refusal either.
func TestSimulation_neverEchoesTheToken(t *testing.T) {
	h := newTestAPI(t)
	secret := "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXBheWxvYWQ.sig"

	recorder := h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
		Domain: testDomain, Path: "/api/orders", Method: http.MethodGet,
		IdentitySource: identityToken, Token: secret,
	})
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NotContains(t, recorder.Body.String(), secret)

	refusal := h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
		Domain: "gateway.typo", Path: "/api/orders", Method: http.MethodGet,
		IdentitySource: identityToken, Token: secret,
	})
	require.Equal(t, http.StatusNotFound, refusal.Code)
	require.NotContains(t, refusal.Body.String(), secret)
}

func TestSimulation_refusesAnUnknownField(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodPost, BasePath+"/simulations",
		strings.NewReader(`{"domain":"gateway.public","path":"/api","method":"GET","identity":"alice"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", viewerRoles()))

	recorder := h.send(t, request)
	requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

func TestHandler_answersAnUnknownRouteInTheSameShape(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet, BasePath+"/nothing", viewerRoles(), nil),
		http.StatusNotFound, CodeNotFound)
}

// A path filter with no method means "any method". Reading it as the engine
// does - where a request always carries one - drops every block whose routes
// name their methods, and an operator asking which rules guard /api/orders is
// told the path is unlimited while two rules count it.
func TestRules_aPathWithoutAMethodKeepsMethodRestrictedBlocks(t *testing.T) {
	h := newTestAPI(t)

	var view ruleview.RuleSetView
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/rules?path=/api/orders", viewerRoles(), nil),
		http.StatusOK, &view)

	blocks := make([]string, 0, len(view.Blocks))
	for _, block := range view.Blocks {
		blocks = append(blocks, block.Block)
	}
	require.Contains(t, blocks, "orders",
		"the orders block targets this prefix for GET and POST; a listing without a method must show it")
}

// Reading parameters by name and ignoring the rest is safe only where every
// parameter narrows. dryRun, expectedRuleSetVersion and limited widen, so a
// typo in one of them has to be an error rather than a silently wider command.
func TestReset_refusesAMisspelledSafetyParameter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	body := requireError(t, h.reset(t, "ruleId=orders/per-client&axis.client=alice&dryrun=true",
		"key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
	require.Equal(t, []string{"dryrun"}, body.Meta.Fields,
		"the answer names the parameter, because the caller cannot see the whitelist")

	remaining, found := h.remaining(t, "alice")
	require.True(t, found, "a refused command must not have deleted the counter")
	require.Equal(t, int64(2), remaining)
}

// The whitelist is checked ahead of the replay, so a retry carrying an unknown
// parameter is refused exactly as the first call would have been. Answering it
// from the record instead would make the same query legal or illegal depending
// on whether the key had been seen.
func TestReset_refusesAMisspelledSafetyParameterOnARetryToo(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	const selector = "ruleId=orders/per-client&axis.client=alice"
	var first ResetResponse
	decode(t, h.reset(t, selector, "key-1", operatorRoles()), http.StatusOK, &first)

	body := requireError(t, h.reset(t, selector+"&dryrun=true", "key-1", operatorRoles()),
		http.StatusBadRequest, CodeInvalidRequest)
	require.Equal(t, []string{"dryrun"}, body.Meta.Fields)
}

func TestQueryNames_areWhitelistedOnEveryReadEndpoint(t *testing.T) {
	h := newTestAPI(t)

	for name, target := range map[string]string{
		"the rule listing":    "/rules?path=/api/orders&methods=GET",
		"the counter listing": "/counters?ruleId=orders/per-client&pagesize=10",
	} {
		t.Run(name, func(t *testing.T) {
			requireError(t, h.call(t, http.MethodGet,
				BasePath+"/domains/"+testDomain+target, viewerRoles(), nil),
				http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

// The whitelist admits the axis family whole: those names come from the keys of
// the domain, not from this package.
func TestQueryNames_admitTheAxisFamily(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?axis.client=alice&axis.order_id=4711",
		viewerRoles(), nil).Code)
}
