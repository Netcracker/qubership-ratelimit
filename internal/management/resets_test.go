package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The bulk action is the destructive one: it scans instead of computing, so
// every guard it has — the mandatory preview, the single-use token bound to
// what was looked at, the idempotency record bound at acceptance — is what
// stands between an operator and a domain reset by accident.

// bulk posts one counter-resets command.
func (h *testAPI) bulk(t *testing.T, body any, idempotencyKey string, roles []string) *testResponse {
	t.Helper()

	target := BasePath + "/domains/" + testDomain + "/counter-resets"
	recorder := h.callWith(t, http.MethodPost, target, roles, body, func(request *http.Request) {
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
	})
	return recorder
}

// preview runs step one and returns its answer.
func (h *testAPI) preview(t *testing.T, body map[string]any, key string) BulkResult {
	t.Helper()
	body["dryRun"] = true

	var result BulkResult
	decode(t, h.bulk(t, body, key, operatorRoles()), http.StatusOK, &result)
	return result
}

func TestBulk_previewMintsATokenAndDeletesNothing(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"bob"}}, 1)

	result := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-1")

	require.True(t, result.DryRun)
	require.NotNil(t, result.MatchedCount)
	require.Equal(t, 2, *result.MatchedCount)
	require.Nil(t, result.ResetCount)
	require.Equal(t, 2, result.Scanned)
	require.NotEmpty(t, result.ConfirmationToken)
	require.NotNil(t, result.ConfirmationExpiresAt)
	require.Len(t, result.Rules, 1)
	require.Equal(t, "api/orders/per-client", result.Rules[0].RuleID)
	require.Equal(t, 2, *result.Rules[0].MatchedCount)

	_, found := h.remaining(t, "alice")
	require.True(t, found, "a preview deletes nothing")
}

func TestBulk_executionNeedsThePreviewsToken(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"bob"}}, 1)

	selector := map[string]any{"ruleIds": []string{"api/orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)

	require.False(t, executed.DryRun)
	require.NotNil(t, executed.ResetCount)
	require.Equal(t, 2, *executed.ResetCount)
	require.Nil(t, executed.MatchedCount)

	_, found := h.remaining(t, "alice")
	require.False(t, found)
	_, found = h.remaining(t, "bob")
	require.False(t, found)
}

// A cold execution is the mistake the two-step exists to prevent.
func TestBulk_refusesAnExecutionWithoutAToken(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)
}

// A value this API never minted is a mistyped request, not a look that went
// stale: telling the caller "expired" would send them to repeat a preview they
// already ran.
func TestBulk_refusesAMalformedToken(t *testing.T) {
	h := newTestAPI(t)

	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"api/orders"}},
		"confirmationToken": "not-a-token",
	}, "key-1", operatorRoles()), http.StatusBadRequest, CodeInvalidRequest)

	// Well-formed but unknown is the expired case.
	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"api/orders"}},
		"confirmationToken": "ct-0123456789ab",
	}, "key-2", operatorRoles()), http.StatusGone, CodeGone)
}

func TestBulk_tokenIsSingleUse(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	selector := map[string]any{"ruleIds": []string{"api/orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")
	execute := map[string]any{"selector": selector, "confirmationToken": preview.ConfirmationToken}

	require.Equal(t, http.StatusOK, h.bulk(t, execute, "key-execute", operatorRoles()).Code)

	// A second command with the same token — a new key, so not a retry — finds
	// the token spent.
	requireError(t, h.bulk(t, execute, "key-again", operatorRoles()),
		http.StatusGone, CodeGone)
}

// The token is bound to what was looked at, not merely to the fact of looking.
func TestBulk_tokenIsBoundToItsSelection(t *testing.T) {
	h := newTestAPI(t)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-preview")

	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"quote-api/cascade"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusConflict, CodeConflict)
}

func TestBulk_tokenIsBoundToItsSubject(t *testing.T) {
	h := newTestAPI(t)

	selector := map[string]any{"ruleIds": []string{"api/orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	// Another operator, holding the token they read from someone's terminal.
	target := BasePath + "/domains/" + testDomain + "/counter-resets"
	recorder := h.callWith(t, http.MethodPost, target, operatorRoles(), map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, func(request *http.Request) {
		request.Header.Set("Idempotency-Key", "key-execute")
		request.Header.Set("Authorization", "Bearer "+testToken("mallory@example.com", operatorRoles()))
	})
	requireError(t, recorder, http.StatusConflict, CodeConflict)
}

func TestBulk_domainWideFormStandsAlone(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)
	h.spend(t, "/api/quotes/1", map[string][]string{model.KeyClient: {"bob"}}, 1)

	preview := h.preview(t, map[string]any{"confirmDomain": testDomain}, "key-preview")
	require.Equal(t, 2, *preview.MatchedCount)

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"confirmDomain": testDomain, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.Equal(t, 2, *executed.ResetCount)

	var list CounterList
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/counters",
		viewerRoles(), nil), http.StatusOK, &list)
	require.Empty(t, list.Items)
}

func TestBulk_refusesTheShapesTheFormsForbid(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]struct {
		body   map[string]any
		status int
		code   errs.ErrorCode
	}{
		"a body naming no selection": {
			body: map[string]any{"dryRun": true}, status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"the domain-wide form mixed with a selector": {
			body: map[string]any{
				"confirmDomain": testDomain,
				"selector":      map[string]any{"ruleIds": []string{"api/orders"}},
				"dryRun":        true,
			},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"a confirmDomain naming another domain": {
			body:   map[string]any{"confirmDomain": "gateway.typo", "dryRun": true},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"an explicit dryRun=false": {
			body: map[string]any{
				"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": false,
			},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"a preview carrying a token": {
			body: map[string]any{
				"selector":          map[string]any{"ruleIds": []string{"api/orders"}},
				"dryRun":            true,
				"confirmationToken": "ct-whatever",
			},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"an empty selector": {
			body:   map[string]any{"selector": map[string]any{}, "dryRun": true},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
		"a limited=false pretending to narrow": {
			body: map[string]any{
				"selector": map[string]any{"limited": false}, "dryRun": true,
			},
			status: http.StatusBadRequest, code: CodeInvalidRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			requireError(t, h.bulk(t, tc.body, "key-"+strings.ReplaceAll(name, " ", "-"),
				operatorRoles()), tc.status, tc.code)
		})
	}
}

func TestBulk_needsAnIdempotencyKeyAndTheOperatorRole(t *testing.T) {
	h := newTestAPI(t)
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true}

	requireError(t, h.bulk(t, body, "", operatorRoles()),
		http.StatusBadRequest, CodeInvalidRequest)
	requireError(t, h.bulk(t, body, "key-1", viewerRoles()),
		http.StatusForbidden, CodeForbidden)
}

func TestBulk_retryAnswersTheRecordedOutcome(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true}

	first := h.bulk(t, body, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, first.Code)

	// A lost preview answered again returns the original token rather than
	// minting a second one.
	second := h.bulk(t, body, "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, second.Code)
	require.JSONEq(t, first.Body.String(), second.Body.String())
}

func TestBulk_refusesTheSameKeyForADifferentCommand(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()).Code)

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"quote-api"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)
}

// A preview and its execution are different commands over one selection.
func TestBulk_previewAndExecutionNeedDifferentKeys(t *testing.T) {
	h := newTestAPI(t)

	selector := map[string]any{"ruleIds": []string{"api/orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-1")

	requireError(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)
}

// Two spellings of one selection are one selection, so a token minted under one
// works under the other.
func TestBulk_normalizesTheSelectionTheTokenIsBoundTo(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders/4711", map[string][]string{model.KeyClient: {"alice"}}, 1)

	preview := h.preview(t, map[string]any{"selector": map[string]any{
		"ruleIds": []string{"api/by-order", "api/by-order"},
		"period":  "1m",
	}}, "key-preview")
	require.Equal(t, 1, *preview.MatchedCount)

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": map[string]any{
			"ruleIds": []string{"api/by-order"},
			"period":  "60",
		},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.Equal(t, 1, *executed.ResetCount)
}

// Selector members are matched against the key, never validated against the
// enforced set: a stale rule id sweeps whatever is left of it.
func TestBulk_reachesCountersOfRemovedRules(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	// The rule leaves the enforced set while its counters live out their TTL.
	h.replaceRules(t, quotePolicy())

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders/per-client"}},
	}, "key-preview")
	require.Equal(t, 1, *preview.MatchedCount, "an orphan still matches its own id")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"api/orders/per-client"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.Equal(t, 1, *executed.ResetCount)
}

func TestBulk_reportsAnUnknownDomainAsNotFound(t *testing.T) {
	h := newTestAPI(t)

	target := BasePath + "/domains/gateway.typo/counter-resets"
	recorder := h.callWith(t, http.MethodPost, target, operatorRoles(),
		map[string]any{"confirmDomain": "gateway.typo", "dryRun": true},
		func(request *http.Request) { request.Header.Set("Idempotency-Key", "key-1") })

	requireError(t, recorder, http.StatusNotFound, CodeNotFound)
}

func TestBulk_refusesAnUnknownSelectorMember(t *testing.T) {
	h := newTestAPI(t)

	// A typo must not widen a selection, so an unknown member is refused rather
	// than ignored.
	request := httptest.NewRequest(http.MethodPost,
		BasePath+"/domains/"+testDomain+"/counter-resets",
		strings.NewReader(`{"selector":{"ruleIdsx":["api/orders"]},"dryRun":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", operatorRoles()))
	request.Header.Set("Idempotency-Key", "key-1")

	requireError(t, h.send(t, request), http.StatusBadRequest, CodeInvalidRequest)
}
