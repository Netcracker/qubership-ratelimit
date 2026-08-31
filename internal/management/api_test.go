package management

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
	require.Equal(t, 2, summary.Policies)
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

	// Blocks come in compiled order: by policy name, then authored position.
	require.Equal(t, []string{"orders", "by-order", "cascade"},
		[]string{view.Blocks[0].Block, view.Blocks[1].Block, view.Blocks[2].Block})

	cascade := view.Blocks[2]
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
	require.Equal(t, ruleview.ApplicabilityAlways, byID["quote-api/cascade/internal"].Applicability)
	require.Equal(t, ruleview.ApplicabilityNever, byID["quote-api/cascade/everyone"].Applicability)
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
		BasePath+"/domains/"+testDomain+"/counters?ruleId=quote-api/cascade/everyone", viewerRoles(), nil),
		http.StatusOK, &list)

	require.Len(t, list.Items, 2)
	require.Equal(t, 2, list.Scanned)
	require.Empty(t, list.NextCursor)

	alice := list.Items[0]
	require.Equal(t, "quote-api/cascade/everyone", alice.RuleID)
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

	target := BasePath + "/domains/" + testDomain + "/counters?ruleId=quote-api/cascade/everyone"
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
		BasePath+"/domains/"+testDomain+"/counters?ruleId=api/orders/per-client&limited=true",
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
	h := newTestAPI(t, wholeDomainPolicy())
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
	base := BasePath + "/domains/" + testDomain + "/counters?ruleId=quote-api/cascade/everyone"

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
	require.Equal(t, "quote-api/cascade/everyone", response.Rules[0].ID)
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
