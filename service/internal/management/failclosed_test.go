package management

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
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

// breakRecords swaps in broken, which fails the steps its flags name and
// delegates the rest to the record store the fixture built.
func (h *testAPI) breakRecords(broken *brokenRecords) {
	broken.Store = h.records
	h.api.Records = broken
}

func TestFailClosed_anUnreadableRecordRefusesTheCommand(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failLookup: true})

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)
}

// A 503 at the acceptance write is the one ambiguous answer, and the message
// says how to resolve it: the same key, never a new one.
func TestFailClosed_anAmbiguousAcceptanceNamesItsRecovery(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failAccept: true})

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)
	assert.Contains(t, body.Message, "retry the same Idempotency-Key")
}

func TestFailClosed_anUnreadableTokenRefusesTheExecution(t *testing.T) {
	h := newTestAPI(t)
	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}},
	}, "key-preview")

	h.breakRecords(&brokenRecords{failToken: true})
	requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"orders"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-execute", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)
}

// The addressed form is one step, so a store that refuses it bound nothing and
// deleted nothing: the message says the call can simply be retried.
func TestFailClosed_anAddressedResetThatNeverRanCanBeRetried(t *testing.T) {
	h := newTestAPI(t)
	h.breakRecords(&brokenRecords{failReset: true})

	body := requireError(t, h.reset(t, "ruleId=orders/per-client&axis.sub=alice",
		"key-1", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)
	assert.Contains(t, body.Message, "nothing was bound")
}

// A record whose command ended while this call was walking is answered from what
// was recorded, not from what this call did.
func TestFailClosed_aLostLeaseAnswersFromTheRecord(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	// The lease is taken away mid-command by expiring it, and somebody else
	// finalizes the record before the walk commits.
	stealer := &stealingRecords{Store: h.records}
	h.api.Records = stealer

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusInternalServerError, CodeInterrupted)
	assert.Equal(t, "id-stolen", body.ID, "the recorded outcome is the one that stands")
	require.NotNil(t, body.Meta.PartialReset, "an interrupted command discloses its progress")
	assert.Equal(t, 7, body.Meta.PartialReset.Scanned)
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

func TestLimited_aPreviewCountsOnlyTheCountersRefusingRightNow(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}, "limited": true},
	}, "key-preview")

	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, 1, *preview.MatchedCount, "only the refusing counter matches")
}

func TestLimited_aSweepResetsOnlyTheCountersRefusingRightNow(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	selector := map[string]any{"ruleIds": []string{"orders"}, "limited": true}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	var executed BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", listedCaller), http.StatusOK, &executed)

	require.NotNil(t, executed.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *executed.ResetCount)
	_, found := h.remaining(t, "crawler")
	assert.False(t, found, "the refusing counter is still listed")
	remaining, found := h.remaining(t, "alice")
	assert.True(t, found, "the counter under its limit is gone")
	assert.Equal(t, int64(2), remaining, "the remaining budget of the counter under its limit")
}

func TestLimited_addressedResetSkipsACounterUnderItsLimit(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=alice&limited=true",
		"key-1", listedCaller), http.StatusOK, &response)
	require.NotNil(t, response.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 0, *response.ResetCount, "alice is not refusing, so nothing was reset")
	// keys reports what the command addressed, one per window of the rule;
	// narrowing it to the refusing subset would leave the body saying the
	// command never looked at the counter it skipped.
	assert.Len(t, response.Keys, 1, "keys is the computed list, not the subset limited kept")

	remaining, found := h.remaining(t, "alice")
	assert.True(t, found, "the counter under its limit is gone")
	assert.Equal(t, int64(2), remaining, "the remaining budget of the counter under its limit")
}

func TestLimited_addressedResetDropsARefusingCounter(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"crawler"}}, 3)

	var response ResetResponse
	decode(t, h.reset(t, "ruleId=orders/per-client&axis.sub=crawler&limited=true",
		"key-1", listedCaller), http.StatusOK, &response)
	require.NotNil(t, response.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *response.ResetCount)

	_, found := h.remaining(t, "crawler")
	assert.False(t, found, "the refusing counter is still listed")
}

// StartBackground is what keeps an accepted sweep alive past its request; the
// runner calls it, and without it the walk runs under context.Background, which
// shutdown never reaches.
func TestBackgroundContext_isTheOneTheRunnerGave(t *testing.T) {
	h := newTestAPI(t)
	require.Equal(t, context.Background(), h.api.backgroundContext(), "before StartBackground")

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	h.api.StartBackground(ctx)
	assert.Equal(t, ctx, h.api.backgroundContext(), "after StartBackground")
}

// A bulk command whose record cannot be read is refused before anything binds,
// so its retry under the same key, once the store answers, runs the command
// instead of finding it in flight.
func TestFailClosed_aCommandRefusedForAnUnreadableRecordRunsOnRetry(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}
	broken := &brokenRecords{failLookup: true}
	h.breakRecords(broken)
	requireError(t, h.bulk(t, body, "key-1", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)

	broken.failLookup = false
	var retry BulkResult
	decode(t, h.bulk(t, body, "key-1", listedCaller), http.StatusOK, &retry)

	require.NotNil(t, retry.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, 1, *retry.MatchedCount, "counters the retried preview matched")
}

// An execution whose confirmation token cannot be read is refused before
// acceptance, so it spends neither its key nor its token: its retry under the
// same key, once the store answers, runs it.
func TestFailClosed_anExecutionRefusedForAnUnreadableTokenRunsOnRetry(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")
	execute := map[string]any{"selector": selector, "confirmationToken": preview.ConfirmationToken}
	broken := &brokenRecords{failToken: true}
	h.breakRecords(broken)
	requireError(t, h.bulk(t, execute, "key-execute", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)

	broken.failToken = false
	var retry BulkResult
	decode(t, h.bulk(t, execute, "key-execute", listedCaller), http.StatusOK, &retry)

	require.NotNil(t, retry.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *retry.ResetCount, "counters the retried execution reset")
}

// The addressed reset is one step in the store, so a store that refuses the
// step binds nothing, as the message of the 503 states: the retry under the
// same key, once the store answers, runs the reset.
func TestFailClosed_anAddressedResetTheStoreRefusedRunsOnRetry(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	broken := &brokenRecords{failReset: true}
	h.breakRecords(broken)
	requireError(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)

	broken.failReset = false
	var retry ResetResponse
	decode(t, h.reset(t, addressAlice, "key-1", listedCaller), http.StatusOK, &retry)

	require.NotNil(t, retry.ResetCount, "the answer of an execution carries resetCount")
	assert.Equal(t, 1, *retry.ResetCount, "counters the retried reset dropped")
}

// silentRecords answers no lookup until the caller's context ends.
type silentRecords struct {
	records.Store
}

func (silentRecords) Lookup(ctx context.Context, _ records.Keys) (records.Record, error) {
	<-ctx.Done()
	return records.Record{}, ctx.Err()
}

// A store that does not answer fails the request at requestTimeout with
// RLS-0503. The request used to wait on the client's own timeouts, more than
// a minute and a half against an address that does not answer.
func TestFailClosed_aStoreThatDoesNotAnswerFailsTheRequestAtItsDeadline(t *testing.T) {
	timeout := requestTimeout
	requestTimeout = 50 * time.Millisecond
	t.Cleanup(func() { requestTimeout = timeout })
	h := newTestAPI(t)
	h.api.Records = silentRecords{Store: h.records}

	// The call runs aside, so a request that never ends fails this test by
	// name rather than the whole binary at the timeout of go test.
	answered := make(chan *testResponse, 1)
	go func() {
		answered <- h.bulk(t, map[string]any{
			"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
		}, "key-1", listedCaller)
	}()
	select {
	case response := <-answered:
		requireError(t, response, http.StatusServiceUnavailable, CodeStoreDown)
	case <-time.After(5 * time.Second):
		t.Fatal("the request did not end within 5s of a 50ms deadline")
	}
}

// lateLostCommit records the outcome after delay and then answers
// ErrLeaseLost, as a commit whose reply was lost does once the client's retry
// finds the lease released, and its Lookup honors the caller's context.
type lateLostCommit struct {
	records.Store
	delay time.Duration
}

func (l lateLostCommit) Commit(ctx context.Context, commit records.Commit) error {
	time.Sleep(l.delay)
	if err := l.Store.Commit(ctx, commit); err != nil {
		return err
	}
	return records.ErrLeaseLost
}

func (l lateLostCommit) Lookup(ctx context.Context, keys records.Keys) (records.Record, error) {
	if err := ctx.Err(); err != nil {
		return records.Record{}, err
	}
	return l.Store.Lookup(ctx, keys)
}

// A sweep that outlives the request's deadline and then finds its lease lost
// reads the recorded outcome back under the context it recorded it in, and
// answers it. The read-back used to run under the expired request context
// and answered 503 for a command that was recorded.
func TestBulk_readsTheOutcomeBackPastTheRequestsDeadline(t *testing.T) {
	timeout := requestTimeout
	requestTimeout = 100 * time.Millisecond
	t.Cleanup(func() { requestTimeout = timeout })
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.api.Records = lateLostCommit{Store: h.records, delay: 200 * time.Millisecond}

	var preview BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusOK, &preview)

	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, 1, *preview.MatchedCount)
}
