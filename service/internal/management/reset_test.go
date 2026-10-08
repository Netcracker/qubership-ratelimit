package management

import (
	"net/http"
	"testing"

	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// reset runs one addressed DELETE, with an Idempotency-Key unless it is empty.
func (h *testAPI) reset(t *testing.T, query, idempotencyKey string, caller string) *testResponse {
	t.Helper()

	target := BasePath + "/domains/" + testDomain + "/counters?" + query
	return h.callWith(t, http.MethodDelete, target, caller, nil, func(request *http.Request) {
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
	})
}

// remaining is what the listing reports for one client of the per-client rule,
// and whether it lists the client's counter at all.
func (h *testAPI) remaining(t *testing.T, client string) (int64, bool) {
	t.Helper()

	var list CounterList
	decode(t, h.call(t, http.MethodGet,
		BasePath+"/domains/"+testDomain+"/counters?ruleId=orders/per-client&axis.sub="+client,
		listedCaller, nil), http.StatusOK, &list)

	if len(list.Items) == 0 {
		return 0, false
	}
	return list.Items[0].Remaining, true
}

// addressAlice is the addressed command most of these tests repeat.
const addressAlice = "ruleId=orders/per-client&axis.sub=alice"

func TestReset_reportsTheCommandItRan(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=crawler", "key-1", listedCaller),
		http.StatusOK, &response)

	assert.False(t, response.DryRun, "dryRun of an execution")
	assert.Equal(t, testDomain, response.Domain)
	assert.Equal(t, "orders/per-client", response.RuleID)
	assert.Equal(t, h.version, response.RuleSetVersion)
	assert.Equal(t, map[string]string{"sub": "crawler"}, response.Axes)
	assert.Len(t, response.Keys, 1, "one key per window of orders/per-client")
	assert.Nil(t, response.MatchedCount, "matchedCount of an execution")
	require.NotNil(t, response.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *response.ResetCount)
}

// The reset drops the addressed counter, and nobody else's budget moves.
func TestReset_dropsOnlyTheAddressedCounter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=crawler", "key-1", listedCaller),
		http.StatusOK, nil)

	_, found := h.remaining(t, "crawler")
	assert.False(t, found, "the addressed counter of crawler is still listed")
	alice, found := h.remaining(t, "alice")
	assert.True(t, found, "the counter of alice is gone")
	assert.Equal(t, int64(2), alice, "the remaining budget of alice")
}

func TestReset_aPreviewCountsTheAddressedCounter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)

	var preview ResetResponse
	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=crawler&dryRun=true", "key-1",
		listedCaller), http.StatusOK, &preview)

	assert.True(t, preview.DryRun, "dryRun of a preview")
	assert.Nil(t, preview.ResetCount, "resetCount of a preview")
	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, 1, *preview.MatchedCount)
}

func TestReset_aPreviewDeletesNothing(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)

	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=crawler&dryRun=true", "key-1",
		listedCaller), http.StatusOK, nil)

	_, found := h.remaining(t, "crawler")
	assert.True(t, found, "the previewed counter of crawler is gone")
}

// A rule with no counters at all keys one bucket for the whole rate, and its
// key is the bare rate prefix.
func TestReset_resetsTheOneCounterOfARuleWithoutAxes(t *testing.T) {
	h := newTestAPI(t, wholeDomainBlocks()...)
	h.spend(t, "/anything", nil, 1)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=everything/total", "key-1", listedCaller),
		http.StatusOK, &response)

	assert.Empty(t, response.Axes)
	require.NotNil(t, response.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *response.ResetCount)
}

// The keys are computed, so a rule with several windows addresses all of them
// unless the call narrows to one.
func TestReset_addressesEveryWindowOfTheRuleByDefault(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)

	var all ResetResponse
	decode(t, h.reset(t, "ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&dryRun=true",
		"key-1", listedCaller), http.StatusOK, &all)

	assert.Len(t, all.Keys, 2, "one key per window of by-order/each")
}

func TestReset_narrowsToTheWindowOfTheGivenPeriod(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)

	var narrowed ResetResponse
	decode(t, h.reset(t,
		"ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&period=1m&dryRun=true",
		"key-1", listedCaller), http.StatusOK, &narrowed)

	assert.Len(t, narrowed.Keys, 1, "keys of by-order/each with period=1m")
}

// A period is normalized before comparison, so 60s and 1m are one window.
func TestReset_readsAPeriodInSecondsAsTheSameWindow(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)

	var byDuration, bySeconds ResetResponse
	decode(t, h.reset(t,
		"ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&period=1m&dryRun=true",
		"key-1", listedCaller), http.StatusOK, &byDuration)
	decode(t, h.reset(t,
		"ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&period=60&dryRun=true",
		"key-2", listedCaller), http.StatusOK, &bySeconds)

	require.Len(t, byDuration.Keys, 1, "keys of by-order/each with period=1m")
	assert.Equal(t, byDuration.Keys, bySeconds.Keys, "keys with period=60 against keys with period=1m")
}

// The rule counts by sub and order_id; naming one would delete every order of
// that client, which is a sweep and not this endpoint's job.
func TestReset_refusesAPartialAxisSelection(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.reset(t, "ruleId=by-order/each&axis.sub=alice", "key-1",
		listedCaller), http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"axis"}, body.Meta.Fields)
}

func TestReset_refusesWhatItCannotAddress(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		status int
		code   errs.ErrorCode
		fields []string
	}{
		{
			// One segment names a block, which is a selection rather than an
			// address: the addressed reset takes the whole block/rule id.
			name:   "a prefix rule id",
			query:  "ruleId=orders",
			status: http.StatusBadRequest, code: CodeInvalidRequest, fields: []string{"ruleId"},
		},
		{
			name:   "a rule id carrying the retired policy segment",
			query:  "ruleId=api/orders/per-client&axis.sub=alice",
			status: http.StatusBadRequest, code: CodeInvalidRequest, fields: []string{"ruleId"},
		},
		{
			name:   "several rule ids",
			query:  "ruleId=orders/per-client&ruleId=orders/support&axis.sub=alice",
			status: http.StatusBadRequest, code: CodeInvalidRequest, fields: []string{"ruleId"},
		},
		{
			name:   "an axis the rule does not count by",
			query:  "ruleId=orders/per-client&axis.order_id=4711",
			status: http.StatusBadRequest, code: CodeInvalidRequest, fields: []string{"axis.order_id"},
		},
		{
			name:   "an explicit dryRun=false",
			query:  "ruleId=orders/per-client&axis.sub=alice&dryRun=false",
			status: http.StatusBadRequest, code: CodeInvalidRequest, fields: []string{"dryRun"},
		},
		{
			name:   "a rule outside the enforced set",
			query:  "ruleId=orders/gone&axis.sub=alice",
			status: http.StatusNotFound, code: CodeNotFound,
		},
		{
			name:   "a window the rule does not have",
			query:  "ruleId=orders/per-client&axis.sub=alice&period=5m",
			status: http.StatusNotFound, code: CodeNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			body := requireError(t, h.reset(t, tc.query, "key-1", listedCaller), tc.status, tc.code)
			assert.Equal(t, tc.fields, body.Meta.Fields, "DELETE counters?%s", tc.query)
		})
	}
}

// The key lands in the audit journal verbatim, so a value that could forge a
// record is refused rather than sanitized, and the refusal names the header.
func TestReset_refusesAMutationWithoutALogSafeIdempotencyKey(t *testing.T) {
	cases := []struct{ name, key string }{
		{name: "no key", key: ""},
		{name: "a key that could forge a record", key: "key\nlevel=info msg=\"reset by nobody\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			body := requireError(t, h.reset(t, addressAlice, tc.key, listedCaller),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{"Idempotency-Key"}, body.Meta.Fields, "Idempotency-Key %q", tc.key)
		})
	}
}

// A version pin that no longer matches the enforced set is a conflict whose
// recovery is to re-read the rules; the pin of the version being enforced runs.
func TestReset_pinsTheRuleSetVersionWhenAsked(t *testing.T) {
	h := newTestAPI(t)
	query := addressAlice + "&expectedRuleSetVersion="

	body := requireError(t, h.reset(t, query+"000000000000", "key-1", listedCaller),
		http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictStaleRuleSet, body.Meta.ConflictType)

	decode(t, h.reset(t, query+h.version, "key-2", listedCaller), http.StatusOK, nil)
}

// Under live traffic a re-run would delete counters that did not exist the
// first time, so a retry answers the recorded outcome instead of executing, and
// the counter the client rebuilt in between stays.
func TestReset_retryReplaysTheRecordedOutcome(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)
	query := "ruleId=orders/per-client&axis.sub=crawler"

	first := h.reset(t, query, "key-1", listedCaller)
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	// The client spends again between the two calls.
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 2)

	second := h.reset(t, query, "key-1", listedCaller)
	require.Equal(t, http.StatusOK, second.Code, "body: %s", second.Body.String())
	assert.JSONEq(t, first.Body.String(), second.Body.String())

	remaining, found := h.remaining(t, "crawler")
	assert.True(t, found, "the counter crawler rebuilt after the reset is gone")
	assert.Equal(t, int64(1), remaining, "the remaining budget crawler rebuilt after the reset")
}

func TestReset_refusesAKeyBoundToAnotherSelection(t *testing.T) {
	h := newTestAPI(t)
	first := h.reset(t, addressAlice, "key-1", listedCaller)
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	body := requireError(t, h.reset(t, "ruleId=orders/per-client&axis.sub=bob", "key-1", listedCaller),
		http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictCommandMismatch, body.Meta.ConflictType)
}

// A preview and its execution are different commands, so the key of the
// execution does not answer the preview.
func TestReset_refusesTheKeyOfAnExecutionForItsPreview(t *testing.T) {
	h := newTestAPI(t)
	first := h.reset(t, addressAlice, "key-1", listedCaller)
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	body := requireError(t, h.reset(t, addressAlice+"&dryRun=true", "key-1", listedCaller),
		http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictCommandMismatch, body.Meta.ConflictType)
}

// A refusal before acceptance binds nothing: a corrected repeat may reuse the
// key it never spent.
func TestReset_aRefusalBindsNothing(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.reset(t, "ruleId=orders/gone&axis.sub=alice", "key-1", listedCaller),
		http.StatusNotFound, CodeNotFound)

	corrected := h.reset(t, addressAlice, "key-1", listedCaller)
	assert.Equal(t, http.StatusOK, corrected.Code, "body: %s", corrected.Body.String())
}

// The canonical command normalizes what a client may spell in several ways, so
// a retry that spells its window differently is still a retry.
func TestReset_normalizesTheCommandBeforeComparingIt(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)

	first := h.reset(t,
		"ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&period=1m&algorithm=GCRA",
		"key-1", listedCaller)
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	second := h.reset(t,
		"ruleId=by-order/each&axis.sub=alice&axis.order_id=4711&period=60&algorithm=gcra",
		"key-1", listedCaller)
	require.Equal(t, http.StatusOK, second.Code, "body: %s", second.Body.String())
	assert.JSONEq(t, first.Body.String(), second.Body.String())
}

// One subject's key never answers another's call: the same key and command
// from another subject runs afresh instead of replaying the first subject's
// outcome.
func TestReset_scopesTheKeyToItsSubject(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	var first, second ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &first)
	decode(t, h.reset(t, addressAlice, "key-1", otherCaller), http.StatusOK, &second)

	require.NotNil(t, first.ResetCount, "the answer of an execution carries resetCount")
	require.Equal(t, 1, *first.ResetCount, "the reset of the first subject")
	require.NotNil(t, second.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 0, *second.ResetCount, "the reset of the second subject, after the counter was gone")
}

func TestReset_reportsAnUnknownDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.callWith(t, http.MethodDelete, BasePath+"/domains/gateway.typo/counters?"+addressAlice,
		listedCaller, nil, func(request *http.Request) { request.Header.Set("Idempotency-Key", "key-1") })

	requireError(t, recorder, http.StatusNotFound, CodeNotFound)
}

func TestReset_writesItsResponseAsJSON(t *testing.T) {
	h := newTestAPI(t)

	var response ResetResponse
	recorder := h.reset(t, addressAlice, "key-1", listedCaller)
	decode(t, recorder, http.StatusOK, &response)

	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "orders/per-client", response.RuleID)
}

// A retry answers from the record, not from the snapshot serving now.
//
// Rebuilding the body would break three promises at once when the rule set
// moves between the call and its retry: a window added to the rule makes the
// replay list a key the command never deleted, the rule leaving the enforced
// set answers 404 before the record is consulted, and a pinned version answers
// 409 for a command that already ran.
func TestReset_replaysTheBodyItRecordedAfterTheRuleSetMoved(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	var first ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &first)
	require.NotNil(t, first.ResetCount, "the answer of an execution carries resetCount")
	require.Equal(t, 1, *first.ResetCount, "the reset before the rollout")
	require.NotEmpty(t, first.Keys, "the reset before the rollout")

	// A rollout adds a window to the same rule, which changes both the version
	// and the key set the rule would address now.
	h.replaceRules(t, widerOrders()...)
	require.NotEqual(t, first.RuleSetVersion, h.version, "the fixture did not move the rule set")

	var replay ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &replay)
	assert.Equal(t, first, replay, "a retry gets the body the command actually produced")
}

// The version pin is a check on a new command. A completed one does not start
// failing because the set moved after it ran.
func TestReset_aPinnedRetryStillReplays(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	query := addressAlice + "&expectedRuleSetVersion=" + h.version
	var first ResetResponse
	decode(t, h.reset(t, query, "key-1", listedCaller), http.StatusOK, &first)

	h.replaceRules(t, widerOrders()...)

	var replay ResetResponse
	decode(t, h.reset(t, query, "key-1", listedCaller), http.StatusOK, &replay)
	assert.Equal(t, first, replay, "the pin judges a new command, never one already recorded")
}

// A rule that left the enforced set answers 404 for a new command, and still
// replays for one that already ran.
func TestReset_replaysEvenWhenTheRuleIsGone(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	var first ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &first)

	h.replaceRules(t, wholeDomainBlocks()...)

	requireError(t, h.reset(t, addressAlice, "key-2", listedCaller), http.StatusNotFound, CodeNotFound)

	var replay ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &replay)
	assert.Equal(t, first, replay)
}
