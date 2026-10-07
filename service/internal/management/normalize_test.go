package management

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The sub key is the sub claim in lower case, so traffic counts Alice under
// alice. An identity value in another case addresses no counter any request
// writes: the listing would come back empty, a reset would reset nothing, and
// the applicability analysis and a simulation would judge an identity no token
// carries, each without a word.
// Every endpoint that takes identity values refuses one the normalization would
// change, and names the form that does address the identity.
func TestManagement_refusesAnIdentityValueTheNormalizationWouldChange(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 2)
	counters := BasePath + "/domains/" + testDomain + "/counters"

	for name, tc := range map[string]struct {
		response *testResponse
		field    string
	}{
		"listing": {h.call(t, http.MethodGet, counters+"?axis.sub=Alice", viewerRoles(), nil), "axis.sub"},
		"applicability": {h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules?axis.sub=Alice",
			viewerRoles(), nil), "axis.sub"},
		"reset": {h.reset(t, "ruleId=orders/per-client&axis.sub=Alice", "key-reset", operatorRoles()),
			"axis.sub"},
		"bulk reset": {h.bulk(t, map[string]any{
			"selector": map[string]any{"axes": map[string][]string{model.KeySub: {"Alice"}}}, "dryRun": true,
		}, "key-bulk", operatorRoles()), "selector.axes"},
		"simulation": {h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
			Domain: testDomain, Path: "/api/orders", Method: "GET",
			Keys: map[string][]string{model.KeySub: {"Alice"}},
		}), "keys"},
	} {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, tc.response, http.StatusBadRequest, CodeInvalidRequest)
			require.Equal(t, []string{tc.field}, body.Meta.Fields)
			require.Contains(t, body.Message, `"alice"`, "the refusal does not name the normalized form")
		})
	}

	// The normalized form still addresses the identity.
	listing := h.call(t, http.MethodGet, counters+"?axis.sub=alice", viewerRoles(), nil)
	require.Equal(t, http.StatusOK, listing.Code)
	require.Contains(t, listing.Body.String(), "alice")
}

// A path capture counts the segment as sent, so a counter of a block that
// captures plan can hold Gold although the domain lowercases the mapped plan.
// An endpoint addressing that block, or every block, compares the value as
// given; one addressing only blocks where plan comes from the mapping still
// refuses it, and a simulation's keys never come from a path.
func TestManagement_comparesACapturedValueAsGiven(t *testing.T) {
	captured := model.Block{
		Name:   "plans",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathTemplate, Value: "/plans/{plan}"}}}},
		Rules:  []model.Rule{{Name: "per-plan", Counters: []string{"plan"}, Rates: []model.Rate{{Requests: 10, Period: time.Minute}}}},
	}
	mapped := model.Block{
		Name:   "other",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/other"}}}},
		Rules:  []model.Rule{{Name: "per-plan", Counters: []string{"plan"}, Rates: []model.Rate{{Requests: 10, Period: time.Minute}}}},
	}
	h := newTestAPI(t, captured, mapped)
	h.spend(t, "/plans/Gold", nil, 3)
	counters := BasePath + "/domains/" + testDomain + "/counters"

	for name, response := range map[string]*testResponse{
		"listing":            h.call(t, http.MethodGet, counters+"?axis.plan=Gold", viewerRoles(), nil),
		"listing by rule":    h.call(t, http.MethodGet, counters+"?ruleId=plans/per-plan&axis.plan=Gold", viewerRoles(), nil),
		"applicability":      h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules?axis.plan=Gold", viewerRoles(), nil),
		"bulk reset preview": h.bulk(t, map[string]any{"selector": map[string]any{"axes": map[string][]string{"plan": {"Gold"}}}, "dryRun": true}, "key-bulk", operatorRoles()),
	} {
		require.Equal(t, http.StatusOK, response.Code, "%s: %s", name, response.Body.String())
	}
	listing := h.call(t, http.MethodGet, counters+"?ruleId=plans/per-plan&axis.plan=Gold", viewerRoles(), nil)
	require.Contains(t, listing.Body.String(), `"Gold"`, "the captured counter is not listed")
	reset := h.reset(t, "ruleId=plans/per-plan&axis.plan=Gold", "key-reset", operatorRoles())
	require.Less(t, reset.Code, 300, "the single reset of the captured counter: %s", reset.Body.String())

	for name, tc := range map[string]struct {
		response *testResponse
		field    string
	}{
		"listing by a mapped rule": {h.call(t, http.MethodGet, counters+"?ruleId=other/per-plan&axis.plan=Gold",
			viewerRoles(), nil), "axis.plan"},
		"reset of a mapped rule": {h.reset(t, "ruleId=other/per-plan&axis.plan=Gold", "key-reset-other",
			operatorRoles()), "axis.plan"},
		"bulk reset of a mapped rule": {h.bulk(t, map[string]any{"selector": map[string]any{
			"ruleIds": []string{"other/per-plan"}, "axes": map[string][]string{"plan": {"Gold"}}}, "dryRun": true},
			"key-bulk-other", operatorRoles()), "selector.axes"},
		"simulation": {h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
			Domain: testDomain, Path: "/other", Method: "GET", Keys: map[string][]string{"plan": {"Gold"}},
		}), "keys"},
	} {
		body := requireError(t, tc.response, http.StatusBadRequest, CodeInvalidRequest)
		require.Equal(t, []string{tc.field}, body.Meta.Fields, name)
	}
}
