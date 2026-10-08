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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
)

// orderCounterKeys returns count keys of orders/per-client, one per client,
// numbered from client-000000 in the order the store walks them.
func orderCounterKeys(count int) []string {
	keys := make([]string, 0, count)
	for i := range count {
		keys = append(keys, fmt.Sprintf("rl:v1:{%s/%s}:orders/per-client:gcra:3600:client-%06d:",
			testNamespace, testDomain, i))
	}
	return keys
}

// A page that spends its whole budget without matching anything still has to
// say where it stopped. The contract makes a missing nextCursor the end of the
// listing, so minting the cursor only when a candidate was kept would report a
// counter that exists as absent, and a narrow filter over a busy domain is the
// ordinary support query, not a corner. The cursor is the store's cursor after
// the last step examined, so the next page examines the keys the first one did
// not and no others.
func TestSelectCandidates_carriesACursorWhenTheBudgetFillsWithNoMatch(t *testing.T) {
	h := newTestAPI(t)
	// More keys than the budget, none of which the selection admits.
	seedCounters(t, h.counters, orderCounterKeys(scanBudget+50))
	sel := mustSelector(t, "axis.sub=nobody")
	inspector := h.counters.(counters.Inspector)

	page, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 100, "")
	require.NoError(t, err, "the first page")
	require.Empty(t, page.candidates, "the fixture selects nothing on purpose")
	assert.Equal(t, scanBudget, page.scanned, "keys examined by the first page")
	assert.True(t, page.more, "the walk stopped at the budget with keys left")
	require.NotEmpty(t, page.resume, "the cursor of the next step")

	rest, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 100, page.resume)
	require.NoError(t, err, "the page after the budget")
	assert.Equal(t, 50, rest.scanned, "keys examined by the page after the budget")
	assert.False(t, rest.more, "the second page reached the end")
}

// The budget binds the last step of a page as the page size binds the others:
// a page of 499 over 12050 keys that match nothing reads 24 steps of 499 and
// one of 24, and examines the budget of 12000 keys exactly, not all 12050.
func TestSelectCandidates_theBudgetBindsTheLastStepOfThePage(t *testing.T) {
	h := newTestAPI(t)
	seedCounters(t, h.counters, orderCounterKeys(scanBudget+50))
	sel := mustSelector(t, "axis.sub=nobody")

	page, err := h.api.selectCandidates(t.Context(), h.snapshot, h.counters.(counters.Inspector), sel, 499, "")
	require.NoError(t, err)

	assert.Equal(t, scanBudget, page.scanned, "keys examined by a page of 499")
	assert.True(t, page.more, "50 keys remain")
}

// A page of one over ten keys reads one step of one key, and the next page
// resumes at the cursor of that step: it examines the nine keys the first one
// did not, and finds no further candidate.
func TestSelectCandidates_resumesAtTheCursorOfTheLastStep(t *testing.T) {
	h := newTestAPI(t)
	seedCounters(t, h.counters, orderCounterKeys(10))
	sel := mustSelector(t, "axis.sub=client-000000")
	inspector := h.counters.(counters.Inspector)

	page, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 1, "")
	require.NoError(t, err, "the first page")
	assert.Len(t, page.candidates, 1, "candidates of the first page")
	assert.Equal(t, 1, page.scanned, "the first step is one key, the room on a page of one")
	require.True(t, page.more, "the first page of one over ten keys ended the walk")

	rest, err := h.api.selectCandidates(t.Context(), h.snapshot, inspector, sel, 1, page.resume)
	require.NoError(t, err, "the second page")
	assert.Empty(t, rest.candidates, "client-000000 was returned by the first page")
	assert.Equal(t, 9, rest.scanned, "keys examined by the second page")
	assert.False(t, rest.more, "the second page reached the end")
}

// A page holds whole steps sized to the room left on it, and the next page
// continues where the store's cursor points: 1300 counters are three pages
// of 500, and every counter is listed once.
func TestCounters_pagesAcrossStoreStepsWithoutLosingOrRepeatingACounter(t *testing.T) {
	h := newTestAPI(t)
	const clients = 1300
	want := make([]string, 0, clients)
	for i := range clients {
		client := fmt.Sprintf("client-%04d", i)
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
		want = append(want, client)
	}

	pages := h.listPages(t, BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&pageSize=500")

	assert.Len(t, pages, 3, "pages of 500 over 1300 counters")
	seen := make([]string, 0, clients)
	for _, page := range pages {
		seen = append(seen, subsOf(page.Items)...)
	}
	assert.ElementsMatch(t, want, seen, "paging skipped or repeated a counter")
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

	assert.Empty(t, page.Items)
	assert.Equal(t, 0, page.Scanned)
	assert.True(t, page.Truncated, "truncated of a page cut by the step cap")
	assert.NotEmpty(t, page.NextCursor, "a page that stopped short of the end says where")
	assert.Equal(t, maxScanSteps, stub.calls, "store round trips of one page")
}

// The listing vouches for the fingerprint and the age of a cursor; the store
// cursor inside it is the store's to check, and its refusal is the caller's
// error rather than an outage: RLS-0400 naming the cursor, never RLS-0503.
func TestCounters_aCursorTheStoreRefusesIsABadRequest(t *testing.T) {
	h := newTestAPI(t)
	store := &refusingSteps{Store: h.counters}
	h.api.Counters = store
	stale := encodeCursor("a-node-that-left@7", mustSelector(t, "ruleId=orders/per-client"), time.Now())

	body := requireError(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&cursor="+url.QueryEscape(stale),
		viewerRoles(), nil), http.StatusBadRequest, CodeInvalidRequest)

	assert.Equal(t, []string{"cursor"}, body.Meta.Fields)
	assert.Equal(t, []string{"a-node-that-left@7"}, store.presented,
		"the store cursors the listing presented; the refusal came before the store")
}

// A store that fails the scan for any other reason is an outage, and the
// answer stays RLS-0503: only the store's refusal of a cursor is the caller's.
func TestCounters_reportsAFailedScanAsAnOutage(t *testing.T) {
	h := newTestAPI(t)
	h.api.Counters = failingSteps{Store: h.counters}

	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", viewerRoles(), nil),
		http.StatusServiceUnavailable, CodeStoreDown)
}

// A page ends on a step boundary and the next page presents the cursor the
// store returned for the step after it: the store returns every key only to
// a walk along that chain, so no cursor is presented twice and none is
// skipped. The store's steps are capped at three keys for a page of four, so
// that every page spans a step boundary; with steps as large as the page, a
// page that reread its last step would present the same cursors.
func TestCounters_pagesFollowTheStoreCursorChain(t *testing.T) {
	h := newTestAPI(t)
	for i := range 10 {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {fmt.Sprintf("client-%02d", i)}}, 1)
	}
	chain := &cursorChain{Store: h.counters, step: 3}
	h.api.Counters = chain

	pages := h.listPages(t, BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&pageSize=4")

	assert.Len(t, pages, 3, "pages of 4 over 10 counters")
	require.NotEmpty(t, chain.presented, "the listing never asked the store for a step")
	assert.Equal(t, "", chain.presented[0], "the first page starts the walk")
	assert.Equal(t, chain.returned[:len(chain.returned)-1], chain.presented[1:],
		"every later step presents the cursor the store returned for it")
}

// A step asks for the room left on the page, not for a whole page: of ten
// counters with six selected, a page of four reads a step of four keys that
// keeps two, then a step of two keys that keeps both, and holds exactly the
// four smallest selected clients. A step that asked for a whole page would
// keep four from the second step and hand back six.
func TestCounters_aStepAsksForTheRoomLeftOnThePage(t *testing.T) {
	h := newTestAPI(t)
	for i := range 10 {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {fmt.Sprintf("client-%02d", i)}}, 1)
	}

	var page CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client"+
		"&pageSize=4&axis.sub=client-01&axis.sub=client-03&axis.sub=client-04"+
		"&axis.sub=client-05&axis.sub=client-06&axis.sub=client-07", viewerRoles(), nil),
		http.StatusOK, &page)

	assert.Equal(t, []string{"client-01", "client-03", "client-04", "client-05"}, subsOf(page.Items))
	assert.NotEmpty(t, page.NextCursor, "two selected clients remain")
}

// A store whose step is a hint may return more keys than the step asked for,
// and the page keeps them rather than lose them: ten counters through a
// store that returns two keys over the ask come back as pages of six and
// four, every counter once.
func TestCounters_aStepOverTheAskOverfillsThePageByThatMuch(t *testing.T) {
	h := newTestAPI(t)
	want := make([]string, 0, 10)
	for i := range 10 {
		client := fmt.Sprintf("client-%02d", i)
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
		want = append(want, client)
	}
	h.api.Counters = &cursorChain{Store: h.counters, over: 2}

	pages := h.listPages(t, BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&pageSize=4")

	sizes := make([]int, 0, len(pages))
	seen := make([]string, 0, 10)
	for _, page := range pages {
		sizes = append(sizes, len(page.Items))
		seen = append(seen, subsOf(page.Items)...)
	}
	assert.Equal(t, []int{6, 4}, sizes, "items per page")
	assert.ElementsMatch(t, want, seen, "paging skipped or repeated a counter")
}

// cursorChain wraps the in-process store, records the cursors a listing
// presents and the ones the store returns in call order, and reshapes the
// steps: step caps how many keys a step asks for, and over adds that many to
// the ask, the way a store whose step is a hint returns more than asked.
type cursorChain struct {
	counters.Store
	step      int
	over      int
	presented []string
	returned  []string
}

func (c *cursorChain) Scan(ctx context.Context, prefix, cursor string, limit int) ([]string, string, error) {
	if c.step > 0 {
		limit = min(limit, c.step)
	}
	keys, next, err := c.Store.(counters.Inspector).Scan(ctx, prefix, cursor, limit+c.over)
	c.presented = append(c.presented, cursor)
	c.returned = append(c.returned, next)
	return keys, next, err
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
// the Redis store refuses one minted for a node it no longer has, and records
// the cursors it was presented in call order.
type refusingSteps struct {
	counters.Store
	presented []string
}

func (s *refusingSteps) Scan(_ context.Context, _, cursor string, _ int) ([]string, string, error) {
	s.presented = append(s.presented, cursor)
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
// The budget case, a page that fills scanBudget without keeping anything and
// still has to carry a cursor, is not reachable from here: pageSize stops the
// walk only after a candidate, so producing an empty page needs 12000 keys
// that match nothing, or 128 of them at a pageSize of 1, the step cap.
// TestSelectCandidates_carriesACursorWhenTheBudgetFillsWithNoMatch and
// TestSelectCandidates_resumesAtTheCursorOfTheLastStep cover it directly.
func TestCounters_pagesThroughEveryCounterOfARule(t *testing.T) {
	h := newTestAPI(t)
	clients := []string{"alpha", "bravo", "zulu"}
	for _, client := range clients {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
	}

	pages := h.listPages(t, BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&pageSize=1")

	for i, page := range pages[:len(pages)-1] {
		assert.True(t, page.Truncated, "truncated of page %d, which carries a cursor", i+1)
	}
	seen := make([]string, 0, len(clients))
	for _, page := range pages {
		seen = append(seen, subsOf(page.Items)...)
	}
	assert.ElementsMatch(t, clients, seen, "paging skipped or repeated a counter")
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
			assert.Equal(t, tc.want, got, "scanPrefix(%q)", tc.ids)
			assert.True(t, strings.HasPrefix(got, domainWide),
				"scanPrefix(%q) = %q leaves the domain prefix %q", tc.ids, got, domainWide)
		})
	}
}
