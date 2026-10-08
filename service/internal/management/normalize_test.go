package management

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The sub key is the sub claim in lower case, so traffic counts Alice under
// alice. An identity value in another case addresses no counter any request
// writes: the listing would come back empty, a reset would reset nothing, and
// the applicability analysis and a simulation would judge an identity no token
// carries, each without a word.
// Every endpoint that takes identity values refuses one the normalization would
// change, and names the form that does address the identity; the normalized
// form itself lists the counter.
func TestManagement_refusesAnIdentityValueTheNormalizationWouldChange(t *testing.T) {
	counters := BasePath + "/domains/" + testDomain + "/counters"
	rules := BasePath + "/domains/" + testDomain + "/rules"
	cases := []struct {
		name  string
		send  func(t *testing.T, h *testAPI) *testResponse
		field string
	}{
		{name: "the listing", field: "axis.sub", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodGet, counters+"?axis.sub=Alice", viewerRoles(), nil)
		}},
		{name: "the applicability analysis", field: "axis.sub", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodGet, rules+"?axis.sub=Alice", viewerRoles(), nil)
		}},
		{name: "the addressed reset", field: "axis.sub", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.reset(t, "ruleId=orders/per-client&axis.sub=Alice", "key-reset", operatorRoles())
		}},
		{name: "the bulk reset", field: "selector.axes", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.bulk(t, map[string]any{
				"selector": map[string]any{"axes": map[string][]string{model.KeySub: {"Alice"}}}, "dryRun": true,
			}, "key-bulk", operatorRoles())
		}},
		{name: "the simulation", field: "keys", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
				Domain: testDomain, Path: "/api/orders", Method: "GET",
				Keys: map[string][]string{model.KeySub: {"Alice"}},
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 2)

			body := requireError(t, tc.send(t, h), http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields)
			assert.Contains(t, body.Message, `"alice"`, "the refusal does not name the normalized form")
		})
	}

	t.Run("the normalized value lists the counter", func(t *testing.T) {
		h := newTestAPI(t)
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 2)

		var list CounterList
		decode(t, h.call(t, http.MethodGet, counters+"?axis.sub=alice", viewerRoles(), nil), http.StatusOK, &list)
		assert.Equal(t, []string{"alice"}, subsOf(list.Items), "GET %s?axis.sub=alice", counters)
	})
}

// A path capture counts the segment as sent, so a counter of a block that
// captures plan can hold Gold although the domain lowercases the mapped plan.
// An endpoint addressing that block, or every block, compares the value as
// given; one addressing only blocks where plan comes from the mapping still
// refuses it, and a simulation's keys never come from a path.

// capturedPlanAPI serves the block plans, which captures plan from the path,
// beside the block other, which counts by the mapped plan, with the counter of
// plans spent under the plan Gold as the path sent it.
func capturedPlanAPI(t *testing.T) *testAPI {
	t.Helper()

	captured := model.Block{
		Name: "plans",
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathTemplate, Value: "/plans/{plan}"},
		}}},
		Rules: []model.Rule{{
			Name: "per-plan", Counters: []string{"plan"}, Rates: []model.Rate{{Requests: 10, Period: time.Minute}},
		}},
	}
	mapped := model.Block{
		Name: "other",
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/other"},
		}}},
		Rules: []model.Rule{{
			Name: "per-plan", Counters: []string{"plan"}, Rates: []model.Rate{{Requests: 10, Period: time.Minute}},
		}},
	}
	h := newTestAPI(t, captured, mapped)
	h.spend(t, "/plans/Gold", nil, 3)
	return h
}

func TestManagement_acceptsACapturedValueAsGiven(t *testing.T) {
	counters := BasePath + "/domains/" + testDomain + "/counters"
	rules := BasePath + "/domains/" + testDomain + "/rules"
	cases := []struct {
		name string
		send func(t *testing.T, h *testAPI) *testResponse
	}{
		{name: "the listing", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodGet, counters+"?axis.plan=Gold", viewerRoles(), nil)
		}},
		{name: "the listing by the capturing rule", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodGet, counters+"?ruleId=plans/per-plan&axis.plan=Gold", viewerRoles(), nil)
		}},
		{name: "the applicability analysis", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodGet, rules+"?axis.plan=Gold", viewerRoles(), nil)
		}},
		{name: "the bulk reset preview", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.bulk(t, map[string]any{
				"selector": map[string]any{"axes": map[string][]string{"plan": {"Gold"}}}, "dryRun": true,
			}, "key-bulk", operatorRoles())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := tc.send(t, capturedPlanAPI(t))
			assert.Equal(t, http.StatusOK, response.Code, "body: %s", response.Body.String())
		})
	}
}

func TestCounters_listsACapturedCounterUnderTheValueAsSent(t *testing.T) {
	h := capturedPlanAPI(t)

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=plans/per-plan&axis.plan=Gold", viewerRoles(), nil),
		http.StatusOK, &list)

	require.Len(t, list.Items, 1, "the captured counter is not listed")
	assert.Equal(t, "plans/per-plan", list.Items[0].RuleID)
	assert.Equal(t, map[string]string{"plan": "Gold"}, list.Items[0].Axes)
}

func TestReset_resetsACapturedCounterUnderTheValueAsSent(t *testing.T) {
	h := capturedPlanAPI(t)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=plans/per-plan&axis.plan=Gold", "key-reset", operatorRoles()),
		http.StatusOK, &response)

	require.NotNil(t, response.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *response.ResetCount)
}

func TestManagement_refusesTheValueWhereTheMappingSuppliesTheKey(t *testing.T) {
	counters := BasePath + "/domains/" + testDomain + "/counters"
	cases := []struct {
		name  string
		send  func(t *testing.T, h *testAPI) *testResponse
		field string
	}{
		{name: "the listing by the mapped rule", field: "axis.plan",
			send: func(t *testing.T, h *testAPI) *testResponse {
				return h.call(t, http.MethodGet, counters+"?ruleId=other/per-plan&axis.plan=Gold", viewerRoles(), nil)
			}},
		{name: "the reset of the mapped rule", field: "axis.plan", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.reset(t, "ruleId=other/per-plan&axis.plan=Gold", "key-reset-other", operatorRoles())
		}},
		{name: "the bulk reset of the mapped rule", field: "selector.axes",
			send: func(t *testing.T, h *testAPI) *testResponse {
				return h.bulk(t, map[string]any{"selector": map[string]any{
					"ruleIds": []string{"other/per-plan"}, "axes": map[string][]string{"plan": {"Gold"}},
				}, "dryRun": true}, "key-bulk-other", operatorRoles())
			}},
		{name: "the simulation", field: "keys", send: func(t *testing.T, h *testAPI) *testResponse {
			return h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
				Domain: testDomain, Path: "/other", Method: "GET", Keys: map[string][]string{"plan": {"Gold"}},
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := requireError(t, tc.send(t, capturedPlanAPI(t)), http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{tc.field}, body.Meta.Fields)
		})
	}
}
