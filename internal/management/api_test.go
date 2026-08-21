package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
)

// call sends an authenticated request through the whole middleware stack.
func (h *testAPI) call(t *testing.T, auth *stubAuth, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer test-token")

	recorder := httptest.NewRecorder()
	h.api.Handler(auth, auth, nil).ServeHTTP(recorder, request)
	return recorder
}

func decodeBody[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &out), "body: %s", recorder.Body.String())
	return out
}

func TestHandler_refusesARequestWithoutAToken(t *testing.T) {
	// This listener has no anonymous path. Everything on it can change what is
	// enforced, so an unauthenticated call is refused before routing.
	h := newTestAPI(t)
	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", nil)
	recorder := httptest.NewRecorder()

	h.api.Handler(allowAll(), allowAll(), nil).ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Header().Get("WWW-Authenticate"), "Bearer")
	assert.Equal(t, ProblemContentType, recorder.Header().Get("Content-Type"))
	assert.Equal(t, CodeUnauthorized, decodeBody[Problem](t, recorder).Code)
}

func TestHandler_refusesATokenTheAPIServerRejects(t *testing.T) {
	h := newTestAPI(t)
	auth := allowAll()
	auth.authenticated = false

	recorder := h.call(t, auth, http.MethodGet, BasePath+"/domains", nil)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestHandler_refusesACallerRBACDenies(t *testing.T) {
	h := newTestAPI(t)
	auth := allowAll()
	auth.allowed = false

	recorder := h.call(t, auth, http.MethodGet, BasePath+"/domains", nil)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Equal(t, CodeForbidden, decodeBody[Problem](t, recorder).Code)
}

func TestHandler_deniesWithoutNamingTheRBACRule(t *testing.T) {
	// The reason describes the cluster's authorization policy to someone who
	// has just failed to prove they may read it. It belongs in the log.
	h := newTestAPI(t)
	auth := allowAll()
	auth.allowed = false

	recorder := h.call(t, auth, http.MethodGet, BasePath+"/domains", nil)

	assert.NotContains(t, recorder.Body.String(), "stub")
}

func TestHandler_answersAnUnknownPathAsAProblem(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/nothing-here", nil)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Equal(t, CodeNotFound, decodeBody[Problem](t, recorder).Code)
}

func TestHandler_echoesTheRequestID(t *testing.T) {
	// A client quotes this value when asking why a call behaved as it did, so
	// it has to come back on the response and match what the body carries.
	h := newTestAPI(t)
	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", nil)
	request.Header.Set(RequestIDHeader, "trace-me")
	recorder := httptest.NewRecorder()

	h.api.Handler(allowAll(), allowAll(), nil).ServeHTTP(recorder, request)

	assert.Equal(t, "trace-me", recorder.Header().Get(RequestIDHeader))
}

func TestListDomains_reportsTheBoundDomains(t *testing.T) {
	h := newTestAPI(t, perClientPolicy(), wholeDomainPolicy())

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains", nil)

	require.Equal(t, http.StatusOK, recorder.Code)
	list := decodeBody[List[DomainSummary]](t, recorder)
	require.Len(t, list.Items, 1)
	assert.Equal(t, testDomain, list.Items[0].Domain)
	assert.Equal(t, 2, list.Items[0].Policies)
	assert.Equal(t, 2, list.Items[0].Rules)
	assert.Contains(t, list.Items[0].EffectiveKeys, model.KeyClient)
}

func TestGetRules_reportsTheAxesInKeyOrder(t *testing.T) {
	// The axis order is what lets a client build a reset: a partial selection
	// has to name a leading run of it, so reporting it is what makes the reset
	// endpoint usable without knowing the key schema.
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/rules", nil)

	require.Equal(t, http.StatusOK, recorder.Code)
	view := decodeBody[RuleSetView](t, recorder)
	require.Len(t, view.Blocks, 1)
	require.Len(t, view.Blocks[0].Rules, 1)
	rule := view.Blocks[0].Rules[0]
	assert.Equal(t, "api/orders/per-client", rule.ID)
	assert.Equal(t, []string{model.KeyClient}, rule.Axes)
	require.Len(t, rule.Rates, 1)
	assert.Equal(t, int64(3), rule.Rates[0].Requests)
	assert.Equal(t, int64(3600), rule.Rates[0].PeriodSeconds)
}

func TestGetRules_reportsAnUnboundDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/gateway.typo/rules", nil)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Contains(t, decodeBody[Problem](t, recorder).Detail, "gateway.typo")
}

func TestListCounters_reportsWhatTheStoreWouldDoNext(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "alice", 2)

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", nil)

	require.Equal(t, http.StatusOK, recorder.Code)
	list := decodeBody[List[CounterView]](t, recorder)
	require.Len(t, list.Items, 1)
	counter := list.Items[0]
	assert.Equal(t, "api/orders/per-client", counter.RuleID)
	assert.Equal(t, map[string]string{model.KeyClient: "alice"}, counter.Axes)
	assert.Equal(t, int64(3), counter.Limit)
	assert.Equal(t, int64(1), counter.Remaining, "two of three spent leaves one")
	assert.False(t, counter.Limited)
}

func TestListCounters_readingDoesNotCharge(t *testing.T) {
	// The listing asks the store what it would answer, without charging. A
	// listing that spent budget would make an operator's own investigation the
	// cause of the refusal they were investigating.
	h := newTestAPI(t)
	h.spend(t, "alice", 1)

	for range 5 {
		h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", nil)
	}

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", nil)
	list := decodeBody[List[CounterView]](t, recorder)
	require.Len(t, list.Items, 1)
	assert.Equal(t, int64(2), list.Items[0].Remaining)
}

func TestListCounters_limitedOnlyKeepsTheRefusingCounters(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "alice", 3)
	h.spend(t, "bob", 1)

	recorder := h.call(t, allowAll(), http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?limited=true", nil)

	require.Equal(t, http.StatusOK, recorder.Code)
	list := decodeBody[List[CounterView]](t, recorder)
	require.Len(t, list.Items, 1)
	assert.Equal(t, map[string]string{model.KeyClient: "alice"}, list.Items[0].Axes)
	assert.True(t, list.Items[0].Limited)
	assert.Zero(t, list.Items[0].Remaining)
}

func TestListCounters_pagesWithAStableCursor(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol", "dave"} {
		h.spend(t, client, 1)
	}

	first := decodeBody[List[CounterView]](t,
		h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/counters?limit=2", nil))
	require.Len(t, first.Items, 2)
	require.True(t, first.Truncated)
	require.NotEmpty(t, first.NextCursor)

	second := decodeBody[List[CounterView]](t,
		h.call(t, allowAll(), http.MethodGet,
			BasePath+"/domains/"+testDomain+"/counters?limit=2&cursor="+first.NextCursor, nil))

	require.Len(t, second.Items, 2)
	assert.Empty(t, second.NextCursor, "four counters in pages of two end on the second page")
	assert.NotEqual(t, first.Items[0].Key, second.Items[0].Key, "a page must not repeat the previous one")
}

func TestListCounters_filtersByRuleID(t *testing.T) {
	h := newTestAPI(t, perClientPolicy(), wholeDomainPolicy())
	h.spend(t, "alice", 1)

	recorder := h.call(t, allowAll(), http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=global/everything/total", nil)

	list := decodeBody[List[CounterView]](t, recorder)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "global/everything/total", list.Items[0].RuleID)
	assert.Empty(t, list.Items[0].Axes, "a whole-domain rule counts without an axis")
}

func TestListCounters_rejectsAMalformedRuleID(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=not-a-triple", nil)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, decodeBody[Problem](t, recorder).Fields, "ruleId")
}

func TestResetCounters_liftsTheLimitOfOneClient(t *testing.T) {
	// The whole point of the endpoint: a client that has spent its budget is
	// admitted again without waiting out the window, and nobody else is
	// touched.
	h := newTestAPI(t)
	h.spend(t, "alice", 3)
	h.spend(t, "bob", 3)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client", Axes: map[string]string{model.KeyClient: "alice"}})

	require.Equal(t, http.StatusOK, recorder.Code)
	response := decodeBody[ResetResponse](t, recorder)
	assert.Equal(t, 1, response.ResetCount)
	assert.Equal(t, ScopeShared, response.Scope)

	remaining := decodeBody[List[CounterView]](t,
		h.call(t, allowAll(), http.MethodGet,
			BasePath+"/domains/"+testDomain+"/counters?limited=true", nil))
	require.Len(t, remaining.Items, 1)
	assert.Equal(t, map[string]string{model.KeyClient: "bob"}, remaining.Items[0].Axes,
		"resetting alice must leave bob limited")
}

func TestResetCounters_withoutAxesResetsTheWholeRule(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "alice", 3)
	h.spend(t, "bob", 3)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client"})

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, 2, decodeBody[ResetResponse](t, recorder).ResetCount)
}

func TestResetCounters_acceptsTheRuleNamedInParts(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "alice", 1)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{Policy: "api", Block: "orders", Rule: "per-client"})

	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestResetCounters_refusesBothFormsAtOnce(t *testing.T) {
	// The two forms can disagree, and guessing which one was meant is how a
	// reset lands on the wrong rule.
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client", Policy: "other"})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestResetCounters_reportsARuleThatIsNotEnforced(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/typo"})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, decodeBody[Problem](t, recorder).Detail, "api/orders/typo")
}

func TestResetCounters_rejectsAnAxisTheRuleDoesNotCountBy(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client", Axes: map[string]string{"tenant": "acme"}})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, decodeBody[Problem](t, recorder).Detail, "tenant")
}

func TestResetCounters_resettingAQuietClientReportsNothingDropped(t *testing.T) {
	// "The limit was lifted" and "nothing was counting" are different answers,
	// and an operator who reset a client that was never limited should be able
	// to see which one happened.
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client", Axes: map[string]string{model.KeyClient: "nobody"}})

	require.Equal(t, http.StatusOK, recorder.Code)
	response := decodeBody[ResetResponse](t, recorder)
	assert.Zero(t, response.ResetCount)
	assert.Empty(t, response.Keys)
}

func TestResetCounters_leavesAnAuditRecordNamingTheCaller(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "alice", 3)

	h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client", Axes: map[string]string{model.KeyClient: "alice"}})

	event := h.auditor.last()
	assert.Equal(t, ActionResetCounters, event.Action)
	assert.Equal(t, OutcomeSucceeded, event.Outcome)
	assert.Equal(t, "system:serviceaccount:core:operator", event.Subject.Name)
	assert.Equal(t, testDomain, event.Domain)
	assert.Equal(t, "api/orders/per-client", event.RuleID)
	assert.Equal(t, map[string]string{model.KeyClient: "alice"}, event.Axes)
	assert.Equal(t, 1, event.Keys)
	assert.NotEmpty(t, event.RequestID)
	assert.False(t, event.Time.IsZero())
}

func TestResetCounters_auditsARejectedAttempt(t *testing.T) {
	// Someone trying to lift a limit and failing is a management event too.
	h := newTestAPI(t)

	h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/typo"})

	event := h.auditor.last()
	assert.Equal(t, ActionResetCounters, event.Action)
	assert.Equal(t, OutcomeRejected, event.Outcome)
	assert.NotEmpty(t, event.Reason)
}

func TestResetCounters_rejectsAnUnknownField(t *testing.T) {
	// An unknown field is a typo or a version mismatch. Ignoring it would let
	// "axis" silently reset every client instead of the one that was named.
	h := newTestAPI(t)
	request := httptest.NewRequest(http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		strings.NewReader(`{"ruleId":"api/orders/per-client","axis":{"client":"alice"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()

	h.api.Handler(allowAll(), allowAll(), nil).ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestResetCounters_reportsReplicaScopeForAnUnsharedStore(t *testing.T) {
	// With the in-process store a reset reaches one replica out of several. An
	// operator has to be told that, or they will believe a limit was lifted
	// that is still being enforced everywhere else.
	h := newTestAPI(t)
	h.api.Scope = ScopeReplica

	recorder := h.call(t, allowAll(), http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counters/reset",
		ResetRequest{RuleID: "api/orders/per-client"})

	assert.Equal(t, ScopeReplica, decodeBody[ResetResponse](t, recorder).Scope)
}

func TestAPI_scopeDefaultsToTheNarrowerAnswer(t *testing.T) {
	api := &API{}

	assert.Equal(t, ScopeReplica, api.scope())
}

func TestListCounters_reportsAStoreThatCannotEnumerate(t *testing.T) {
	h := newTestAPI(t)
	h.api.Counters = blindStore{Store: h.counters}

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/domains/"+testDomain+"/counters", nil)

	assert.Equal(t, http.StatusNotImplemented, recorder.Code)
	assert.Equal(t, CodeUnsupported, decodeBody[Problem](t, recorder).Code)
}

// blindStore is a counter store without the Inspector half of the contract.
// Embedding the interface rather than the implementation is what hides Keys:
// only the three methods of store.Store come through the wrapper.
type blindStore struct{ counters.Store }

func TestBasePath_isNotUnderTheKubernetesAPIPrefix(t *testing.T) {
	// Kubernetes ships a ClusterRole named system:discovery granting get on
	// /api/* to the group system:authenticated, and binds it by default. Since
	// authorization here is a SubjectAccessReview against the request path, an
	// API served under /api/v1/... is readable by every identity in the
	// cluster whatever this chart's roles say — and these endpoints report the
	// axis values that identify clients.
	//
	// This is a security boundary rather than a naming preference, which is
	// why it is pinned by a test.
	assert.False(t, strings.HasPrefix(BasePath, "/api"),
		"a base path under /api is granted to system:authenticated by system:discovery")
	assert.True(t, strings.HasPrefix(BasePath, "/"))
}
