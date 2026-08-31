package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// reset runs one addressed DELETE with an Idempotency-Key.
func (h *testAPI) reset(t *testing.T, query, idempotencyKey string, roles []string) *testResponse {
	t.Helper()

	target := BasePath + "/domains/" + testDomain + "/counters?" + query
	request := httptest.NewRequest(http.MethodDelete, target, strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", roles))
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}

	recorder := h.send(t, request)
	return recorder
}

// remaining is what the listing reports for one client of the per-client rule.
func (h *testAPI) remaining(t *testing.T, client string) (int64, bool) {
	t.Helper()

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=api/orders/per-client&axis.client="+client,
		viewerRoles(), nil), http.StatusOK, &list)

	if len(list.Items) == 0 {
		return 0, false
	}
	return list.Items[0].Remaining, true
}

func TestReset_dropsTheCountersItAddresses(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=crawler", "key-1", operatorRoles()),
		http.StatusOK, &response)

	require.False(t, response.DryRun)
	require.Equal(t, testDomain, response.Domain)
	require.Equal(t, "api/orders/per-client", response.RuleID)
	require.Equal(t, h.version, response.RuleSetVersion)
	require.Equal(t, map[string]string{"client": "crawler"}, response.Axes)
	require.Len(t, response.Keys, 1)
	require.NotNil(t, response.ResetCount)
	require.Equal(t, 1, *response.ResetCount)
	require.Nil(t, response.MatchedCount)

	_, found := h.remaining(t, "crawler")
	require.False(t, found, "the counter is gone")

	// Nobody else's budget moved.
	alice, found := h.remaining(t, "alice")
	require.True(t, found)
	require.Equal(t, int64(2), alice)
}

func TestReset_previewChangesNothing(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)

	var preview ResetResponse
	decode(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=crawler&dryRun=true", "key-1",
		operatorRoles()), http.StatusOK, &preview)

	require.True(t, preview.DryRun)
	require.NotNil(t, preview.MatchedCount)
	require.Equal(t, 1, *preview.MatchedCount)
	require.Nil(t, preview.ResetCount)

	_, found := h.remaining(t, "crawler")
	require.True(t, found, "a preview deletes nothing")
}

// A rule with no counters at all keys one bucket for the whole rate, and its
// key is the bare rate prefix.
func TestReset_handlesARuleWithoutAxes(t *testing.T) {
	h := newTestAPI(t, wholeDomainPolicy())
	h.spend(t, "/anything", nil, 1)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=global/everything/total", "key-1", operatorRoles()),
		http.StatusOK, &response)
	require.Equal(t, 1, *response.ResetCount)
	require.Empty(t, response.Axes)
}

// The keys are computed, so a rule with several windows drops all of them
// unless the call narrows to one.
func TestReset_narrowsToOneWindowOnRequest(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeyClient: {"alice"}}, 1)

	var all ResetResponse
	decode(t, h.reset(t, "ruleId=api/by-order/each&axis.client=alice&axis.order_id=4711&dryRun=true",
		"key-1", operatorRoles()), http.StatusOK, &all)
	require.Len(t, all.Keys, 2, "one key per window")

	var narrowed ResetResponse
	decode(t, h.reset(t,
		"ruleId=api/by-order/each&axis.client=alice&axis.order_id=4711&period=1m&dryRun=true",
		"key-2", operatorRoles()), http.StatusOK, &narrowed)
	require.Len(t, narrowed.Keys, 1)

	// A period is normalized before comparison, so 60s and 1m are one window.
	var bySeconds ResetResponse
	decode(t, h.reset(t,
		"ruleId=api/by-order/each&axis.client=alice&axis.order_id=4711&period=60&dryRun=true",
		"key-3", operatorRoles()), http.StatusOK, &bySeconds)
	require.Equal(t, narrowed.Keys, bySeconds.Keys)
}

func TestReset_refusesAPartialAxisSelection(t *testing.T) {
	h := newTestAPI(t)

	// The rule counts by client and order_id; naming one would delete every
	// order of that client, which is a sweep and not this endpoint's job.
	body := requireError(t, h.reset(t, "ruleId=api/by-order/each&axis.client=alice", "key-1",
		operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
	require.Contains(t, body.Message, "every axis")
}

func TestReset_refusesWhatItCannotAddress(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]struct {
		query  string
		status int
		code   errs.ErrorCode
	}{
		"a prefix rule id": {
			query: "ruleId=api/orders", status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"several rule ids": {
			query:  "ruleId=api/orders/per-client&ruleId=api/orders/support&axis.client=alice",
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"an axis the rule does not count by": {
			query:  "ruleId=api/orders/per-client&axis.order_id=4711",
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"an explicit dryRun=false": {
			query:  "ruleId=api/orders/per-client&axis.client=alice&dryRun=false",
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"a rule outside the enforced set": {
			query:  "ruleId=api/orders/gone&axis.client=alice",
			status: http.StatusNotFound, code: CodeNotFound,
		},
		"a window the rule does not have": {
			query:  "ruleId=api/orders/per-client&axis.client=alice&period=5m",
			status: http.StatusNotFound, code: CodeNotFound,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			requireError(t, h.reset(t, tc.query, "key-"+strings.ReplaceAll(name, " ", "-"),
				operatorRoles()), tc.status, tc.code)
		})
	}
}

func TestReset_needsALogSafeIdempotencyKey(t *testing.T) {
	h := newTestAPI(t)
	query := "ruleId=api/orders/per-client&axis.client=alice"

	requireError(t, h.reset(t, query, "", operatorRoles()),
		http.StatusBadRequest, CodeInvalidRequest)

	// The key lands in the audit journal verbatim, so a value that could forge
	// a record is refused rather than sanitized.
	requireError(t, h.reset(t, query, "key\nlevel=info msg=\"reset by nobody\"", operatorRoles()),
		http.StatusBadRequest, CodeInvalidRequest)
}

func TestReset_pinsTheRuleSetVersionWhenAsked(t *testing.T) {
	h := newTestAPI(t)
	query := "ruleId=api/orders/per-client&axis.client=alice&expectedRuleSetVersion="

	requireError(t, h.reset(t, query+"000000000000", "key-1", operatorRoles()),
		http.StatusConflict, CodeConflict)

	decode(t, h.reset(t, query+h.version, "key-2", operatorRoles()), http.StatusOK, nil)
}

// Under live traffic a re-run would delete counters that did not exist the
// first time, so a retry answers the recorded outcome instead of executing.
func TestReset_retryReplaysTheRecordedOutcome(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)
	query := "ruleId=api/orders/per-client&axis.client=crawler"

	first := h.reset(t, query, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code)

	// The client spends again between the two calls.
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 2)

	second := h.reset(t, query, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, second.Code)
	require.JSONEq(t, first.Body.String(), second.Body.String())

	// And the counter the client rebuilt is still there.
	remaining, found := h.remaining(t, "crawler")
	require.True(t, found)
	require.Equal(t, int64(1), remaining)
}

func TestReset_refusesTheSameKeyForADifferentCommand(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK,
		h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-1", operatorRoles()).Code)

	requireError(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=bob", "key-1", operatorRoles()),
		http.StatusConflict, CodeConflict)

	// A preview and its execution are different commands for the same reason.
	requireError(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=alice&dryRun=true",
		"key-1", operatorRoles()), http.StatusConflict, CodeConflict)
}

// A refusal before acceptance binds nothing: a corrected repeat may reuse the
// key it never spent.
func TestReset_aRefusalBindsNothing(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.reset(t, "ruleId=api/orders/gone&axis.client=alice", "key-1", operatorRoles()),
		http.StatusNotFound, CodeNotFound)

	require.Equal(t, http.StatusOK,
		h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-1", operatorRoles()).Code)
}

// The canonical command normalizes what a client may spell in several ways, so
// a retry that spells its window differently is still a retry.
func TestReset_normalizesTheCommandBeforeComparingIt(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeyClient: {"alice"}}, 1)

	first := h.reset(t,
		"ruleId=api/by-order/each&axis.client=alice&axis.order_id=4711&period=1m&algorithm=GCRA",
		"key-1", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code)

	second := h.reset(t,
		"ruleId=api/by-order/each&axis.client=alice&axis.order_id=4711&period=60&algorithm=gcra",
		"key-1", operatorRoles())
	require.Equal(t, http.StatusOK, second.Code)
	require.JSONEq(t, first.Body.String(), second.Body.String())
}

// One subject's key never answers another's call, and never conflicts with it.
func TestReset_scopesTheKeyToItsSubject(t *testing.T) {
	h := newTestAPI(t)
	target := BasePath + "/domains/" + testDomain +
		"/counters?ruleId=api/orders/per-client&axis.client=alice"

	call := func(subject string) *testResponse {
		request := httptest.NewRequest(http.MethodDelete, target, strings.NewReader(""))
		request.Header.Set("Authorization", "Bearer "+testToken(subject, operatorRoles()))
		request.Header.Set("Idempotency-Key", "key-1")
		return h.send(t, request)
	}

	require.Equal(t, http.StatusOK, call("alice@example.com").Code)
	require.Equal(t, http.StatusOK, call("bob@example.com").Code)
}

func TestReset_reportsAnUnknownDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)

	target := BasePath + "/domains/gateway.typo/counters?ruleId=api/orders/per-client&axis.client=alice"
	request := httptest.NewRequest(http.MethodDelete, target, strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", operatorRoles()))
	request.Header.Set("Idempotency-Key", "key-1")

	recorder := h.send(t, request)
	requireError(t, recorder, http.StatusNotFound, CodeNotFound)
}

// The response a retry replays is the one that was recorded, byte for byte.
func TestReset_recordsTheBodyItAnswered(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, recorder.Code)

	var response ResetResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, "api/orders/per-client", response.RuleID)
	require.Equal(t, recorder.Header().Get("Content-Type"), "application/json")
}
