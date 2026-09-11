package management

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
)

// A page that spends its whole budget without matching anything still has to
// say where it stopped. The contract makes a missing nextCursor the end of the
// listing, so minting the cursor only when a candidate was kept would report a
// counter that exists as absent - and a narrow filter over a busy domain is the
// ordinary support query, not a corner. The cursor resumes after the last key
// looked at rather than after the last one kept, so the next page examines the
// keys the first one did not and no others.
func TestSelectCandidates_carriesACursorWhenTheBudgetFillsWithNoMatch(t *testing.T) {
	h := newTestAPI(t)

	// More keys than the budget, none of which the selection admits.
	keys := make([]string, 0, scanBudget+50)
	for i := range scanBudget + 50 {
		keys = append(keys, fmt.Sprintf("rl:v1:{%s/%s}:orders/per-client:gcra:3600:client-%06d:",
			testNamespace, testDomain, i))
	}
	seedCounters(t, h.counters, keys)
	sel, apiErr := parseSelector(url.Values{"axis.client": {"nobody"}})
	require.Nil(t, apiErr)
	inspector := h.counters.(counters.Inspector)

	page, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 100, scanPos{})
	require.NoError(t, err)

	require.Empty(t, page.candidates, "the fixture selects nothing on purpose")
	require.Equal(t, scanBudget, page.scanned)
	require.True(t, page.more, "the walk stopped at the budget with keys left")
	require.Equal(t, keys[scanBudget-1], page.resume.after,
		"the cursor resumes after the last key looked at, not the last one kept")

	rest, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 100, page.resume)
	require.NoError(t, err)
	require.Equal(t, 50, rest.scanned, "keys examined by the page after the budget")
	require.False(t, rest.more, "the second page reached the end")
}

// Resuming from the last candidate would rescan every key between it and the
// point the walk actually stopped: the next page examines the nine keys the
// first one did not, and finds no further candidate.
func TestSelectCandidates_resumesAfterTheLastKeyLookedAt(t *testing.T) {
	h := newTestAPI(t)

	keys := make([]string, 0, 10)
	for i := range 10 {
		keys = append(keys, fmt.Sprintf("rl:v1:{%s/%s}:orders/per-client:gcra:3600:client-%02d:",
			testNamespace, testDomain, i))
	}
	seedCounters(t, h.counters, keys)
	sel, apiErr := parseSelector(url.Values{"axis.client": {"client-00"}})
	require.Nil(t, apiErr)
	inspector := h.counters.(counters.Inspector)

	page, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 1, scanPos{})
	require.NoError(t, err)

	require.Len(t, page.candidates, 1)
	require.True(t, page.more)
	require.Equal(t, keys[0], page.resume.after)

	rest, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 1, page.resume)
	require.NoError(t, err)
	require.Empty(t, rest.candidates, "client-00 was returned by the first page")
	require.Equal(t, 9, rest.scanned, "keys examined by the second page")
	require.False(t, rest.more)
}

// A page ends inside a store step whenever pageSize is not a multiple of the
// step, and the keys of that step behind the page must reach the next one:
// 1300 counters are three pages of 500, and every counter is listed once.
func TestCounters_pagesAcrossStoreStepsWithoutLosingOrRepeatingACounter(t *testing.T) {
	h := newTestAPI(t)
	const clients = 1300
	want := make([]string, 0, clients)
	for i := range clients {
		client := fmt.Sprintf("client-%04d", i)
		h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {client}}, 1)
		want = append(want, client)
	}

	base := BasePath + "/domains/" + testDomain + "/counters?ruleId=orders/per-client&pageSize=500"
	seen := make([]string, 0, clients)
	pages := 0
	target := base
	for {
		var page CounterList
		decode(t, h.call(t, http.MethodGet, target, viewerRoles(), nil), http.StatusOK, &page)
		pages++
		for _, item := range page.Items {
			seen = append(seen, item.Axes["client"])
		}
		if page.NextCursor == "" {
			break
		}
		require.LessOrEqual(t, pages, 10, "the listing did not end")
		target = base + "&cursor=" + url.QueryEscape(page.NextCursor)
	}

	require.Equal(t, 3, pages, "pages of 500 over 1300 counters")
	require.ElementsMatch(t, want, seen, "paging skipped or repeated a counter")
}

// The budget counts keys the store returned, so a stretch of steps that return
// none would never fill it. The step cap ends such a page: no item, a cursor,
// and a bounded number of store round trips.
func TestCounters_aStretchOfEmptyStepsEndsThePageWithACursor(t *testing.T) {
	h := newTestAPI(t)
	stub := &emptySteps{Store: h.counters}
	h.api.Counters = stub

	var page CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", viewerRoles(), nil),
		http.StatusOK, &page)

	require.Empty(t, page.Items)
	require.Equal(t, 0, page.Scanned)
	require.True(t, page.Truncated)
	require.NotEmpty(t, page.NextCursor, "a page that stopped short of the end says where")
	require.Equal(t, maxScanSteps, stub.calls, "store round trips of one page")
}

// The listing vouches for the fingerprint and the age of a cursor; the store
// cursor inside it is the store's to check, and its refusal is the caller's
// error rather than an outage: RLS-0400 naming the cursor, never RLS-0503.
func TestCounters_aCursorTheStoreRefusesIsABadRequest(t *testing.T) {
	h := newTestAPI(t)
	h.api.Counters = refusingSteps{Store: h.counters}
	sel, apiErr := parseSelector(url.Values{"ruleId": {"orders/per-client"}})
	require.Nil(t, apiErr)
	stale := encodeCursor(scanPos{step: "a-node-that-left@7"}, sel, time.Now())

	body := requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&cursor="+url.QueryEscape(stale),
		viewerRoles(), nil), http.StatusBadRequest, CodeInvalidRequest)

	require.Contains(t, body.Message, "cannot resume the cursor")
}

// A store that fails the scan for any other reason is an outage, and the
// answer stays RLS-0503: only the store's refusal of a cursor is the caller's.
func TestCounters_aFailedScanIsAnOutageNotABadRequest(t *testing.T) {
	h := newTestAPI(t)
	h.api.Counters = failingSteps{Store: h.counters}

	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", viewerRoles(), nil),
		http.StatusServiceUnavailable, CodeStoreDown)
}

// emptySteps is a store whose walk returns no key: the shape of a prefix
// whose keys are sparse in a keyspace shared with other data. The walk ends
// after until steps, or never when until is zero.
type emptySteps struct {
	counters.Store
	calls int
	until int
}

func (s *emptySteps) Scan(_ context.Context, _, _ string, _ int) ([]string, string, error) {
	s.calls++
	if s.until > 0 && s.calls >= s.until {
		return nil, "", nil
	}
	return nil, fmt.Sprintf("step-%d", s.calls), nil
}

// failingSteps is a store whose walk fails outright, the way an unreachable
// Redis does.
type failingSteps struct{ counters.Store }

func (failingSteps) Scan(_ context.Context, _, _ string, _ int) ([]string, string, error) {
	return nil, "", errors.New("stub: the store did not answer")
}

// refusingSteps is a store that rejects every cursor it is handed, the way
// the Redis store refuses one minted for a node it no longer has.
type refusingSteps struct{ counters.Store }

func (refusingSteps) Scan(_ context.Context, _, cursor string, _ int) ([]string, string, error) {
	if cursor != "" {
		return nil, "", fmt.Errorf("stub: %w", counters.ErrBadCursor)
	}
	return nil, "", nil
}

// seedCounters writes one live counter per key straight into the store. The
// keys of these tests are chosen for their order and their number, and a
// decision per key would only slow the fixture down.
func seedCounters(t *testing.T, s counters.Store, keys []string) {
	t.Helper()
	for _, k := range keys {
		_, err := s.Decide(t.Context(), []counters.Bucket{{Key: k, Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 3, Period: time.Hour, Burst: 3}}}, 1)
		require.NoError(t, err, "Decide(%q)", k)
	}
}

// Paging end to end: each page carries a cursor, and following it reaches the
// counters the earlier pages did not return.
//
// The budget case - a page that fills scanBudget without keeping anything, and
// still has to carry a cursor - is not reachable from here: pageSize stops the
// walk only after a candidate, so producing an empty page needs 12000 keys.
// TestSelectCandidates_carriesACursorWhenTheBudgetFillsWithNoMatch and
// TestSelectCandidates_resumesAfterTheLastKeyLookedAt cover it directly.
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
