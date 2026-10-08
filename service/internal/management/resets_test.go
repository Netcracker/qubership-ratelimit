package management

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The bulk action is the destructive one: it scans instead of computing, so
// every guard it has (the mandatory preview, the single-use token bound to what
// was looked at, the idempotency record bound at acceptance) is what stands
// between an operator and a domain reset by accident.

// bulk posts one counter-resets command, with an Idempotency-Key unless it is
// empty.
func (h *testAPI) bulk(t *testing.T, body any, idempotencyKey string, roles []string) *testResponse {
	t.Helper()

	target := BasePath + "/domains/" + testDomain + "/counter-resets"
	return h.callWith(t, http.MethodPost, target, roles, body, func(request *http.Request) {
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
	})
}

// preview runs step one over body, which it marks as a preview, and returns
// its answer.
func (h *testAPI) preview(t *testing.T, body map[string]any, key string) BulkResult {
	t.Helper()
	body["dryRun"] = true

	var result BulkResult
	decode(t, h.bulk(t, body, key, operatorRoles()), http.StatusOK, &result)
	return result
}

func TestBulk_aPreviewReportsTheMatchedCountersWithAConfirmationToken(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"bob"}}, 1)

	result := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}},
	}, "key-1")

	assert.True(t, result.DryRun, "dryRun of a preview")
	assert.Nil(t, result.ResetCount, "resetCount of a preview")
	assert.Equal(t, 2, result.Scanned)
	assert.Regexp(t, `^ct-[0-9a-f]{12}$`, result.ConfirmationToken)
	assert.NotNil(t, result.ConfirmationExpiresAt, "a minted token carries its expiry")
	require.NotNil(t, result.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, 2, *result.MatchedCount)
	assert.Equal(t, []BulkRuleCount{{RuleID: "orders/per-client", MatchedCount: new(2)}}, result.Rules)
}

func TestBulk_aPreviewDeletesNothing(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	h.preview(t, map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}}, "key-1")

	_, found := h.remaining(t, "alice")
	assert.True(t, found, "the previewed counter of alice is gone")
}

func TestBulk_anExecutionUnderThePreviewsTokenResetsTheSelection(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"bob"}}, 1)

	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)

	assert.False(t, executed.DryRun, "dryRun of an execution")
	assert.Nil(t, executed.MatchedCount, "matchedCount of an execution")
	require.NotNil(t, executed.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 2, *executed.ResetCount)
	_, found := h.remaining(t, "alice")
	assert.False(t, found, "the counter of alice is still listed")
	_, found = h.remaining(t, "bob")
	assert.False(t, found, "the counter of bob is still listed")
}

// A cold execution is the mistake the two-step exists to prevent.
func TestBulk_refusesAnExecutionWithoutAToken(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}},
	}, "key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"confirmationToken"}, body.Meta.Fields)
}

// A value this API never minted is a mistyped request, not a look that went
// stale: telling the caller "expired" would send them to repeat a preview they
// already ran. TestBulk_reportsAnUnknownWellFormedTokenAsGone holds the token
// that is well formed.
func TestBulk_refusesATokenThisAPINeverMints(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"orders"}},
		"confirmationToken": "not-a-token",
	}, "key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{"confirmationToken"}, body.Meta.Fields)
}

// A token in the minted form that the store does not hold expired or was used.
func TestBulk_reportsAnUnknownWellFormedTokenAsGone(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"orders"}},
		"confirmationToken": "ct-0123456789ab",
	}, "key-1", operatorRoles()), http.StatusGone, CodeGone)
}

// A second command with the same token, under a new key and so not a retry,
// finds the token spent.
func TestBulk_tokenIsSingleUse(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")
	execute := map[string]any{"selector": selector, "confirmationToken": preview.ConfirmationToken}

	first := h.bulk(t, execute, "key-execute", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code, "the first execution: %s", first.Body.String())

	requireError(t, h.bulk(t, execute, "key-again", operatorRoles()), http.StatusGone, CodeGone)
}

// The token is bound to what was looked at, not merely to the fact of looking.
func TestBulk_tokenIsBoundToItsSelection(t *testing.T) {
	h := newTestAPI(t)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}},
	}, "key-preview")

	body := requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"cascade"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictStaleConfirmation, body.Meta.ConflictType)
}

// Another operator, holding the token they read from someone's terminal, is
// refused it.
func TestBulk_tokenIsBoundToItsSubject(t *testing.T) {
	h := newTestAPI(t)

	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	target := BasePath + "/domains/" + testDomain + "/counter-resets"
	recorder := h.callWith(t, http.MethodPost, target, operatorRoles(), map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, func(request *http.Request) {
		request.Header.Set("Idempotency-Key", "key-execute")
		request.Header.Set("Authorization", "Bearer "+testToken("mallory@example.com", operatorRoles()))
	})

	body := requireError(t, recorder, http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictStaleConfirmation, body.Meta.ConflictType)
}

func TestBulk_theDomainWideFormResetsEveryCounterOfTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.spend(t, "/api/invoices/1", map[string][]string{model.KeySub: {"bob"}}, 1)

	preview := h.preview(t, map[string]any{"confirmDomain": testDomain}, "key-preview")
	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	require.Equal(t, 2, *preview.MatchedCount, "the domain-wide preview")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"confirmDomain": testDomain, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.NotNil(t, executed.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 2, *executed.ResetCount)

	var list CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		viewerRoles(), nil), http.StatusOK, &list)
	assert.Empty(t, list.Items, "counters left in the domain after the domain-wide reset")
}

func TestBulk_refusesTheShapesTheFormsForbid(t *testing.T) {
	cases := []struct {
		name   string
		body   map[string]any
		fields []string
	}{
		{name: "a body naming no selection", body: map[string]any{"dryRun": true}},
		{
			name: "the domain-wide form mixed with a selector",
			body: map[string]any{
				"confirmDomain": testDomain,
				"selector":      map[string]any{"ruleIds": []string{"orders"}},
				"dryRun":        true,
			},
			fields: []string{"confirmDomain"},
		},
		{
			name:   "a confirmDomain naming another domain",
			body:   map[string]any{"confirmDomain": "gateway.typo", "dryRun": true},
			fields: []string{"confirmDomain"},
		},
		{
			name:   "an explicit dryRun=false",
			body:   map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": false},
			fields: []string{"dryRun"},
		},
		{
			name: "a preview carrying a token",
			body: map[string]any{
				"selector":          map[string]any{"ruleIds": []string{"orders"}},
				"dryRun":            true,
				"confirmationToken": "ct-whatever",
			},
			fields: []string{"confirmationToken"},
		},
		{
			name:   "an empty selector",
			body:   map[string]any{"selector": map[string]any{}, "dryRun": true},
			fields: []string{"selector"},
		},
		{
			name:   "a limited=false pretending to narrow",
			body:   map[string]any{"selector": map[string]any{"limited": false}, "dryRun": true},
			fields: []string{"selector.limited"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			body := requireError(t, h.bulk(t, tc.body, "key-1", operatorRoles()),
				http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, tc.fields, body.Meta.Fields, "POST counter-resets %v", tc.body)
		})
	}
}

func TestBulk_refusesAViewer(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", viewerRoles()), http.StatusForbidden, CodeForbidden)
}

// A lost preview answered again returns the original token rather than
// minting a second one.
func TestBulk_retryAnswersTheRecordedOutcome(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}

	first := h.bulk(t, body, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	second := h.bulk(t, body, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, second.Code, "body: %s", second.Body.String())
	assert.JSONEq(t, first.Body.String(), second.Body.String())
}

func TestBulk_refusesTheSameKeyForADifferentCommand(t *testing.T) {
	h := newTestAPI(t)

	first := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"cascade"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictCommandMismatch, body.Meta.ConflictType)
}

// A preview and its execution are different commands over one selection.
func TestBulk_previewAndExecutionNeedDifferentKeys(t *testing.T) {
	h := newTestAPI(t)

	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-1")

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictCommandMismatch, body.Meta.ConflictType)
}

// Two spellings of one selection are one selection, so a token minted under one
// works under the other.
func TestBulk_normalizesTheSelectionTheTokenIsBoundTo(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeySub: {"alice"}}, 1)

	preview := h.preview(t, map[string]any{"selector": map[string]any{
		"ruleIds": []string{"by-order", "by-order"},
		"period":  "1m",
	}}, "key-preview")
	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	require.Equal(t, 1, *preview.MatchedCount, "the preview under period=1m")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": map[string]any{
			"ruleIds": []string{"by-order"},
			"period":  "60",
		},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.NotNil(t, executed.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *executed.ResetCount)
}

// Selector members are matched against the key, never validated against the
// enforced set: a stale rule id sweeps whatever is left of it.
func TestBulk_reachesCountersOfRemovedRules(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	// The rule leaves the enforced set while its counters live out their TTL.
	h.replaceRules(t, cascadeBlocks()...)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders/per-client"}},
	}, "key-preview")
	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	require.Equal(t, 1, *preview.MatchedCount, "an orphan still matches its own id")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"orders/per-client"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.NotNil(t, executed.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *executed.ResetCount)
}

func TestBulk_reportsAnUnknownDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)

	target := BasePath + "/domains/gateway.typo/counter-resets"
	recorder := h.callWith(t, http.MethodPost, target, operatorRoles(),
		map[string]any{"confirmDomain": "gateway.typo", "dryRun": true},
		func(request *http.Request) { request.Header.Set("Idempotency-Key", "key-1") })

	requireError(t, recorder, http.StatusNotFound, CodeNotFound)
}

// A typo must not widen a selection, so an unknown member is refused rather
// than ignored.
func TestBulk_refusesAnUnknownSelectorMember(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.bulk(t, rawJSON(`{"selector":{"ruleIdsx":["orders"]},"dryRun":true}`), "key-1",
		operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
}

// An axis the selector cannot address is refused, and the refusal names the
// field, so a client can point at its own input.
func TestBulk_refusesAnAxisThatAddressesNoCounter(t *testing.T) {
	for name, axes := range map[string]map[string][]string{
		"an axis without a name":      {"": {"alice"}},
		"an axis without values":      {model.KeySub: {}},
		"an axis with an empty value": {model.KeySub: {"alice", ""}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestAPI(t)
			body := requireError(t, h.bulk(t, map[string]any{
				"selector": map[string]any{"axes": axes}, "dryRun": true,
			}, "key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{"selector.axes"}, body.Meta.Fields)
		})
	}
}

// A mutation without a usable Idempotency-Key is refused, and the refusal
// names the header, so a client can tell it from a fault in the body.
func TestBulk_refusesAMutationWithoutAUsableIdempotencyKey(t *testing.T) {
	for name, key := range map[string]string{
		"no key":                   "",
		"a key outside the format": "bad key",
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestAPI(t)
			body := requireError(t, h.bulk(t, map[string]any{
				"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
			}, key, operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
			assert.Equal(t, []string{"Idempotency-Key"}, body.Meta.Fields)
		})
	}
}
