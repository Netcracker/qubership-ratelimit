package management

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// A page that spends its whole budget without matching anything still has to
// say where it stopped. The contract makes a missing nextCursor the end of the
// listing, so minting the cursor only when a candidate was kept would report a
// counter that exists as absent - and a narrow filter over a busy domain is the
// ordinary support query, not a corner.
func TestSelectCandidates_carriesACursorWhenTheBudgetFillsWithNoMatch(t *testing.T) {
	h := newTestAPI(t)

	// More keys than the budget, none of which the selection admits.
	keys := make([]string, 0, scanBudget+50)
	for i := range scanBudget + 50 {
		keys = append(keys, fmt.Sprintf("rl:v1:{%s/%s}:orders/per-client:gcra:3600:client-%06d:",
			testNamespace, testDomain, i))
	}
	sel, apiErr := parseSelector(url.Values{"axis.client": {"nobody"}})
	require.Nil(t, apiErr)

	page := h.api.selectCandidates(t.Context(), h.snapshot, keys, sel, 100, "")

	require.Empty(t, page.candidates, "the fixture selects nothing on purpose")
	require.Equal(t, scanBudget, page.scanned)
	require.True(t, page.more, "the walk stopped at the budget with keys left")
	require.Equal(t, keys[scanBudget-1], page.lastScanned,
		"the cursor resumes from the last key looked at, not the last one kept")
}

// Resuming from the last candidate would rescan every key between it and the
// point the walk actually stopped.
func TestSelectCandidates_resumesAfterTheLastKeyLookedAt(t *testing.T) {
	h := newTestAPI(t)

	keys := make([]string, 0, 10)
	for i := range 10 {
		keys = append(keys, fmt.Sprintf("rl:v1:{%s/%s}:orders/per-client:gcra:3600:client-%02d:",
			testNamespace, testDomain, i))
	}
	sel, apiErr := parseSelector(url.Values{"axis.client": {"client-00"}})
	require.Nil(t, apiErr)

	page := h.api.selectCandidates(t.Context(), h.snapshot, keys, sel, 1, "")

	require.Len(t, page.candidates, 1)
	require.True(t, page.more)
	require.Equal(t, keys[0], page.lastScanned)
}

// Paging end to end: each page carries a cursor, and following it reaches the
// counters the earlier pages did not return.
//
// The budget case - a page that fills scanBudget without keeping anything, and
// still has to carry a cursor - is not reachable from here: pageSize stops the
// walk only after a candidate, so producing an empty page needs 12,000 keys.
// The two selectCandidates tests above cover it directly.
func TestCounters_pagesThroughEveryCounterOfARule(t *testing.T) {
	h := newTestAPI(t)
	clients := []string{"alpha", "bravo", "zulu"}
	for _, client := range clients {
		h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {client}}, 1)
	}

	base := BasePath + "/domains/" + testDomain + "/counters?ruleId=orders/per-client&pageSize=1"

	seen := []string{}
	target := base
	for range len(clients) + 1 {
		var page CounterList
		decode(t, h.call(t, http.MethodGet, target, viewerRoles(), nil), http.StatusOK, &page)
		for _, item := range page.Items {
			seen = append(seen, item.Axes["client"])
		}
		if page.NextCursor == "" {
			break
		}
		require.True(t, page.Truncated, "a page that carries a cursor stopped early")
		target = base + "&cursor=" + url.QueryEscape(page.NextCursor)
	}
	require.ElementsMatch(t, clients, seen, "paging skipped or repeated a counter")
}

// A scan that cannot narrow walks the whole domain, and on a busy one that is
// every key on every page. The layout puts the rule segment first, so a lone
// block name is a real prefix of its rules' keys.
func TestScanPrefix_narrowsToWhatTheSelectionNames(t *testing.T) {
	domainWide := key.DomainPrefix(testNamespace, testDomain)

	cases := map[string]struct {
		ids  []string
		want string
	}{
		"a whole rule id": {
			ids: []string{"orders/per-client"},
			want: key.RulePrefix(key.Ident{
				Namespace: testNamespace, Domain: testDomain, Block: "orders", Rule: "per-client"}),
		},
		"a block":              {ids: []string{"orders"}, want: key.BlockPrefix(testNamespace, testDomain, "orders")},
		"no id at all":         {ids: nil, want: domainWide},
		"more than one id":     {ids: []string{"orders", "cascade"}, want: domainWide},
		"two ids of one block": {ids: []string{"orders/per-client", "orders/support"}, want: domainWide},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := scanPrefix(testNamespace, testDomain, selector{RuleIDs: tc.ids})
			require.Equal(t, tc.want, got)
			require.True(t, strings.HasPrefix(got, domainWide),
				"every scan stays inside the domain it was asked about")
		})
	}
}
