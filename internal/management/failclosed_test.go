package management

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// An unreachable store is never read as "no record exists". That distinction is
// the whole safety of a destructive command: absence means "run it", and an
// outage read as absence would run a sweep a second time. Every one of these
// paths therefore answers RLS-0503 and binds nothing.

// brokenRecords fails whichever step the test names, and delegates the rest.
type brokenRecords struct {
	records.Store

	failLookup bool
	failAccept bool
	failToken  bool
	failReset  bool
}

var errStoreDown = errors.New("the store is not answering")

func (b *brokenRecords) Lookup(ctx context.Context, keys records.Keys) (records.Record, error) {
	if b.failLookup {
		return records.Record{}, errStoreDown
	}
	return b.Store.Lookup(ctx, keys)
}

func (b *brokenRecords) Accept(ctx context.Context, a records.Acceptance) (records.Accepted, error) {
	if b.failAccept {
		return records.Accepted{}, errStoreDown
	}
	return b.Store.Accept(ctx, a)
}

func (b *brokenRecords) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if b.failToken {
		return nil, false, errStoreDown
	}
	return b.Store.Get(ctx, key)
}

func (b *brokenRecords) Reset(ctx context.Context, a records.Addressed) (records.AddressedOutcome, error) {
	if b.failReset {
		return records.AddressedOutcome{}, errStoreDown
	}
	return b.Store.Reset(ctx, a)
}

// break_ swaps in a record store that fails the named step.
func (h *testAPI) breakRecords(broken *brokenRecords) {
	broken.Store = h.records
	h.api.Records = broken
}

func TestFailClosed_anUnreadableRecordRefusesTheCommand(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failLookup: true})

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusServiceUnavailable, CodeStoreDown)
}

// A 503 at the acceptance write is the one ambiguous answer, and the message
// says how to resolve it: the same key, never a new one.
func TestFailClosed_anAmbiguousAcceptanceNamesItsRecovery(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failAccept: true})

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusServiceUnavailable, CodeStoreDown)
	require.Contains(t, body.Message, "retry the same Idempotency-Key")
}

func TestFailClosed_anUnreadableTokenRefusesTheExecution(t *testing.T) {
	h := newTestAPI(t)
	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-preview")

	h.breakRecords(&brokenRecords{failToken: true})
	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"api/orders"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusServiceUnavailable, CodeStoreDown)
}

// The addressed form is one step, so a store that refuses it bound nothing and
// deleted nothing: the message says the call can simply be retried.
func TestFailClosed_anAddressedResetThatNeverRanCanBeRetried(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failReset: true})

	body := requireError(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=alice",
		"key-1", operatorRoles()), http.StatusServiceUnavailable, CodeStoreDown)
	require.Contains(t, body.Message, "nothing was bound")
}

// A record whose command ended while this call was walking is answered from what
// was recorded, not from what this call did.
func TestFailClosed_aLostLeaseAnswersFromTheRecord(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	// The lease is taken away mid-command by expiring it, and somebody else
	// finalizes the record before the walk commits.
	stealer := &stealingRecords{Store: h.records}
	h.api.Records = stealer

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)
	require.NotNil(t, body.Meta.PartialReset)
	require.Equal(t, "id-stolen", body.ID, "the recorded outcome is the one that stands")
	require.Equal(t, 7, body.Meta.PartialReset.Scanned)
}

// stealingRecords finalizes the command behind the walker's back, the way a
// retry does once a lease looks dead.
type stealingRecords struct {
	records.Store
}

func (s *stealingRecords) Commit(ctx context.Context, c records.Commit) error {
	// The other hand records its own outcome first, and this walker then finds
	// the domain no longer its own.
	if err := s.Store.Commit(ctx, records.Commit{
		Keys:    c.Keys,
		Fencing: c.Fencing,
		Outcome: records.Outcome{
			Failed: true, Code: CodeInterrupted.Code, ErrorID: "id-stolen",
			Message:  "finalized by somebody else",
			Progress: records.Progress{Scanned: 7},
		},
	}); err != nil {
		return err
	}
	return records.ErrLeaseLost
}

// The limited filter needs the rule's windows, so it judges every candidate
// before deleting it. Both reset forms carry it.
func TestLimited_sweepsOnlyTheCountersRefusingRightNow(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	selector := map[string]any{"ruleIds": []string{"api/orders"}, "limited": true}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")
	require.Equal(t, 1, *preview.MatchedCount, "only the refusing counter matches")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusOK, &executed)
	require.Equal(t, 1, *executed.ResetCount)

	_, found := h.remaining(t, "crawler")
	require.False(t, found, "the refusing counter is gone")
	remaining, found := h.remaining(t, "alice")
	require.True(t, found, "and the one still under its limit was left alone")
	require.Equal(t, int64(2), remaining)
}

func TestLimited_addressedResetSkipsACounterUnderItsLimit(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=alice&limited=true",
		"key-1", operatorRoles()), http.StatusOK, &response)
	require.Equal(t, 0, *response.ResetCount, "alice is not refusing, so nothing was reset")

	remaining, found := h.remaining(t, "alice")
	require.True(t, found)
	require.Equal(t, int64(2), remaining)
}

func TestLimited_addressedResetDropsARefusingCounter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=crawler&limited=true",
		"key-1", operatorRoles()), http.StatusOK, &response)
	require.Equal(t, 1, *response.ResetCount)

	_, found := h.remaining(t, "crawler")
	require.False(t, found)
}

// StartBackground is what keeps an accepted sweep alive past its request; the
// runner calls it, and without it the walk would run under a background context
// that shutdown never reaches.
func TestBackgroundContext_isTheOneTheRunnerGave(t *testing.T) {
	h := newTestAPI(t)
	require.Equal(t, context.Background(), h.api.backgroundContext())

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	h.api.StartBackground(ctx)
	require.Equal(t, ctx, h.api.backgroundContext())
}
