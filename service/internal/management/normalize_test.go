package management

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The client key is the sub claim in lower case, so traffic counts Alice under
// alice. An identity value in another case addresses no counter any request
// writes: the listing would come back empty, a reset would reset nothing, and
// the applicability analysis and a simulation would judge an identity no token
// carries, each without a word.
// Every endpoint that takes identity values refuses one the normalization would
// change, and names the form that does address the identity.
func TestManagement_refusesAnIdentityValueTheNormalizationWouldChange(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 2)
	counters := BasePath + "/domains/" + testDomain + "/counters"

	for name, tc := range map[string]struct {
		response *testResponse
		field    string
	}{
		"listing": {h.call(t, http.MethodGet, counters+"?axis.client=Alice", viewerRoles(), nil), "axis.client"},
		"applicability": {h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules?axis.client=Alice",
			viewerRoles(), nil), "axis.client"},
		"reset": {h.reset(t, "ruleId=orders/per-client&axis.client=Alice", "key-reset", operatorRoles()),
			"axis.client"},
		"bulk reset": {h.bulk(t, map[string]any{
			"selector": map[string]any{"axes": map[string][]string{model.KeyClient: {"Alice"}}}, "dryRun": true,
		}, "key-bulk", operatorRoles()), "selector.axes"},
		"simulation": {h.call(t, http.MethodPost, BasePath+"/simulations", viewerRoles(), SimulationRequest{
			Domain: testDomain, Path: "/api/orders", Method: "GET",
			Keys: map[string][]string{model.KeyClient: {"Alice"}},
		}), "keys"},
	} {
		t.Run(name, func(t *testing.T) {
			body := requireError(t, tc.response, http.StatusBadRequest, CodeInvalidRequest)
			require.Equal(t, []string{tc.field}, body.Meta.Fields)
			require.Contains(t, body.Message, `"alice"`, "the refusal does not name the normalized form")
		})
	}

	// The normalized form still addresses the identity.
	listing := h.call(t, http.MethodGet, counters+"?axis.client=alice", viewerRoles(), nil)
	require.Equal(t, http.StatusOK, listing.Code)
	require.Contains(t, listing.Body.String(), "alice")
}
