package management

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
)

// A bulk command runs to completion inside the call, under a server deadline and
// a domain lease. These tests cover what that costs: the second sweep is
// refused, a client that comes back mid-walk polls, a walker that died is
// finalized by the next retry, and every one of those failures discloses what
// the command actually did.

// deadlineAfter makes the walk run out of time once it has consulted the clock
// the given number of times: one for the deadline itself, one before each
// store step, and one per key.
func (h *testAPI) deadlineAfter(t *testing.T, checks int) {
	t.Helper()

	now := time.Now()
	consulted := 0
	h.api.Now = func() time.Time {
		consulted++
		if consulted > checks {
			return now.Add(sweepDeadline + time.Second)
		}
		return now
	}
}

// occupy claims the domain's sweep lease for somebody else, which is what a
// concurrent command sees.
func (h *testAPI) occupy(t *testing.T, ttl time.Duration) {
	t.Helper()

	accepted, err := h.records.Accept(context.Background(), records.Acceptance{
		Keys: records.Keys{
			Record: recordTag(testNamespace, testDomain) + "idem:other",
			Lease:  leaseKey(testNamespace, testDomain),
		},
		Command:  "someone-elses-command",
		Fencing:  "someone-elses-fencing",
		LeaseTTL: ttl,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK, "Accept of someone else's command: %+v", accepted)
}

// accepted plants a record for the command this test will send, as though an
// earlier call had been accepted and had, or had not, come back.
func (h *testAPI) accepted(t *testing.T, key string, command bulkCommand, leaseTTL time.Duration) records.Keys {
	t.Helper()

	name := recordKey(testNamespace, testDomain, endpointResets, "alice@example.com", key)
	keys := commandKeys(testNamespace, testDomain, name, command)

	accepted, err := h.records.Accept(context.Background(), records.Acceptance{
		Keys:     keys,
		Command:  command.command(testDomain),
		Fencing:  "the-original-walker",
		LeaseTTL: leaseTTL,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK, "Accept of the planted command: %+v", accepted)
	return keys
}

// previewCommand is the preview of the orders block that accepted and
// plantDeadSweep plant records for.
func previewCommand(t *testing.T) bulkCommand {
	t.Helper()

	command, apiErr := parseBulk(testDomain, BulkResetRequest{
		Selector: &SelectorBody{RuleIDs: []string{"orders"}},
		DryRun:   new(true),
	})
	require.Nil(t, apiErr, "parseBulk of a preview of the orders block")
	return command
}

// One sweep per domain. The refusal names its recovery, and Retry-After is
// what the other sweep's lease has left.
func TestBulk_refusesASecondSweepInTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.clock(t)
	h.occupy(t, 30*time.Second)

	recorder := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles())

	body := requireError(t, recorder, http.StatusConflict, CodeConflict)
	assert.Equal(t, ConflictSweepInFlight, body.Meta.ConflictType)
	assert.Equal(t, "30", recorder.Header().Get("Retry-After"), "the seconds left on the other sweep's lease")
}

// The refusal of a second sweep happens before anything binds, so the caller's
// key is still spendable once the domain is free.
func TestBulk_aSweepRefusedForABusyDomainBindsNothing(t *testing.T) {
	h := newTestAPI(t)
	now := h.clock(t)
	h.occupy(t, 30*time.Second)
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}
	requireError(t, h.bulk(t, body, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)

	*now = now.Add(time.Minute)

	again := h.bulk(t, body, "key-1", operatorRoles())
	assert.Equal(t, http.StatusOK, again.Code, "the same key once the lease expired: %s", again.Body.String())
}

// A retry that meets its own command still in flight is a poll: no body, and a
// Retry-After of the poll interval rather than the 30 seconds the lease has
// left, since a sweep ends in seconds.
func TestBulk_retryOfARunningCommandPolls(t *testing.T) {
	h := newTestAPI(t)
	h.clock(t)
	h.accepted(t, "key-1", previewCommand(t), 30*time.Second)

	recorder := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles())

	require.Equal(t, http.StatusAccepted, recorder.Code, "body: %s", recorder.Body.String())
	assert.Empty(t, recorder.Body.String(), "there is nothing to say yet")
	assert.Equal(t, "5", recorder.Header().Get("Retry-After"))
}

// plantDeadSweep leaves the record of a preview of the orders block under
// key-1 accepted, with the progress a walker committed before it died, and
// moves the clock past its lease.
func (h *testAPI) plantDeadSweep(t *testing.T, progress records.Progress) {
	t.Helper()

	now := h.clock(t)
	keys := h.accepted(t, "key-1", previewCommand(t), 30*time.Second)
	require.NoError(t, h.records.Batch(context.Background(), records.Batch{
		Keys: keys, Fencing: "the-original-walker", Progress: progress,
	}))
	*now = now.Add(time.Minute)
}

// A walker that never came back leaves an accepted record with a dead lease. The
// first retry finalizes it as interrupted, and the disclosure is the progress
// the batches had committed.
func TestBulk_retryFinalizesADeadSweep(t *testing.T) {
	h := newTestAPI(t)
	h.plantDeadSweep(t, records.Progress{
		Scanned: 40, Matched: 12, Rules: map[string]int{"orders/per-client": 12},
		Keys: []string{"rl:v1:{gateway.public}:orders/per-client:gcra:3600:alice:"},
	})

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)

	require.NotNil(t, body.Meta.PartialReset, "a command that may have deleted must disclose")
	assert.Equal(t, PartialReset{
		DryRun:       true,
		Scanned:      40,
		MatchedCount: new(12),
		Rules:        []BulkRuleCount{{RuleID: "orders/per-client", MatchedCount: new(12)}},
		Keys:         []string{"rl:v1:{gateway.public}:orders/per-client:gcra:3600:alice:"},
	}, *body.Meta.PartialReset)
}

// A later retry replays the outcome the first retry finalized rather than
// finalizing again.
func TestBulk_retryAfterTheFinalizationReplaysIt(t *testing.T) {
	h := newTestAPI(t)
	h.plantDeadSweep(t, records.Progress{
		Scanned: 40, Matched: 12, Rules: map[string]int{"orders/per-client": 12},
		Keys: []string{"rl:v1:{gateway.public}:orders/per-client:gcra:3600:alice:"},
	})
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}
	finalized := requireError(t, h.bulk(t, body, "key-1", operatorRoles()),
		http.StatusInternalServerError, CodeInterrupted)

	replay := requireError(t, h.bulk(t, body, "key-1", operatorRoles()),
		http.StatusInternalServerError, CodeInterrupted)

	assert.Equal(t, finalized.ID, replay.ID, "a replay is the same error instance")
	require.NotNil(t, replay.Meta.PartialReset, "a replay of an interrupted command discloses")
	assert.Equal(t, 40, replay.Meta.PartialReset.Scanned)
}

// The deadline is the server's bound on synchronous work. Hitting it is a
// recorded failure with its own code, because its recovery differs: narrow the
// selection, do not repeat the same width.
func TestBulk_aSweepPastTheDeadlineDisclosesWhatItWalked(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
	}

	// The clock is consulted for the deadline, then before the first step, then
	// before each key; it jumps past the deadline once the walk has counted
	// one key, so the failure discloses that key rather than zeroes.
	h.deadlineAfter(t, 3)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)

	assert.Contains(t, body.Message, "narrow")
	require.NotNil(t, body.Meta.PartialReset, "a failure after acceptance discloses")
	assert.True(t, body.Meta.PartialReset.DryRun, "dryRun of the disclosure of a preview")
	assert.Equal(t, 1, body.Meta.PartialReset.Scanned, "keys walked before the deadline")
	assert.NotNil(t, body.Meta.PartialReset.MatchedCount, "the disclosure of a preview carries matchedCount")
}

// The deadline failure is recorded: a retry of the same command replays it
// instead of walking again.
func TestBulk_retryReplaysTheDeadlineFailure(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
	}
	h.deadlineAfter(t, 3)
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}
	failed := requireError(t, h.bulk(t, body, "key-1", operatorRoles()),
		http.StatusUnprocessableEntity, CodeWorkLimit)

	replay := requireError(t, h.bulk(t, body, "key-1", operatorRoles()),
		http.StatusUnprocessableEntity, CodeWorkLimit)

	assert.Equal(t, failed.ID, replay.ID, "a replay is the same error instance")
}

// The walk reads the store step by step and carries its batch across the
// steps: 1300 counters of one block are three steps of the store, and the
// preview counts every one of them once.
func TestBulk_aPreviewWalksEveryStepOfALargeBlock(t *testing.T) {
	h := newTestAPI(t)
	const clients = 1300
	for i := range clients {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {fmt.Sprintf("client-%04d", i)}}, 1)
	}

	var preview BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusOK, &preview)

	assert.Equal(t, clients, preview.Scanned, "keys the walk examined")
	require.NotNil(t, preview.MatchedCount, "the answer of a preview carries matchedCount")
	assert.Equal(t, clients, *preview.MatchedCount, "counters the selection matched")
}

// A step that returns no key gives the per-key check nothing to run on, so
// the deadline is also checked before every step: a walk over empty steps
// stops at the deadline instead of running to the end of the store.
func TestBulk_theDeadlineIsCheckedBeforeEveryStep(t *testing.T) {
	h := newTestAPI(t)
	h.api.Counters = &emptySteps{Store: h.counters, until: 5}

	// The clock is consulted for the deadline and before the first step; the
	// check before the second step finds the deadline passed.
	h.deadlineAfter(t, 2)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)

	require.NotNil(t, body.Meta.PartialReset, "a failure after acceptance discloses")
	assert.Equal(t, 0, body.Meta.PartialReset.Scanned, "no key was walked before the deadline")
}

// A failed sweep frees the domain: the lease is released with the outcome, so
// the next command is not blocked by a command that already ended.
func TestBulk_aRecordedFailureReleasesTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	body := map[string]any{"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true}

	h.deadlineAfter(t, 1)
	requireError(t, h.bulk(t, body, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)

	h.api.Now = nil
	next := h.bulk(t, body, "key-2", operatorRoles())
	assert.Equal(t, http.StatusOK, next.Code, "the next command in the domain: %s", next.Body.String())
}

// contextBoundRecords refuses a write under a done context, the way the Redis
// client refuses to send one; the in-memory store ignores the context.
type contextBoundRecords struct {
	records.Store
}

func (c contextBoundRecords) Commit(ctx context.Context, commit records.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Store.Commit(ctx, commit)
}

func (c contextBoundRecords) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Store.Put(ctx, key, value, ttl)
}

// shutDown gives the sweeps a background context that is already cancelled,
// as a service shutting down does, over records that refuse a done context.
func (h *testAPI) shutDown(t *testing.T) {
	t.Helper()
	h.api.Records = contextBoundRecords{Store: h.records}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.api.StartBackground(ctx)
}

// A sweep that shutdown interrupts still records its outcome and answers it.
// The outcome used to be written under the walk's cancelled context, which
// the store refused, so the client got RLS-0503 and the command stayed
// accepted until its lease expired.
func TestBulk_recordsItsOutcomeWhenShutdownEndsTheWalk(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	h.shutDown(t)

	var preview BulkResult
	decode(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusOK, &preview)
	assert.Regexp(t, `^ct-[0-9a-f]{12}$`, preview.ConfirmationToken, "the token of the preview")
}

// The failure of such a sweep is recorded as well, with its own code rather
// than RLS-0503.
func TestBulk_recordsAFailureWhenShutdownEndsTheWalk(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
	}
	h.shutDown(t)
	h.deadlineAfter(t, 3)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)
	assert.NotNil(t, body.Meta.PartialReset, "a failure after acceptance discloses")
}

// batchRefusingRecords cancels the sweeps' context when the first batch is
// sent and then refuses it, the way the Redis client refuses a call under a
// done context: the walk fails inside a store call, and nothing is deleted.
type batchRefusingRecords struct {
	contextBoundRecords
	cancel context.CancelFunc
}

func (b batchRefusingRecords) Batch(ctx context.Context, batch records.Batch) error {
	b.cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.Store.Batch(ctx, batch)
}

// A sweep that shutdown interrupts inside a batch discloses what the store
// committed, not what the walker counted. The walker counts a batch before the
// store runs it, and the failure used to report the three deletions of a batch
// the store refused, while all three counters still existed.
func TestBulk_aFailureInsideABatchDisclosesWhatTheStoreCommitted(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
	}
	selector := map[string]any{"ruleIds": []string{"orders"}}
	preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	h.api.StartBackground(ctx)
	h.api.Records = batchRefusingRecords{contextBoundRecords: contextBoundRecords{Store: h.records}, cancel: cancel}

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": selector, "confirmationToken": preview.ConfirmationToken,
	}, "key-execute", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)
	require.NotNil(t, body.Meta.PartialReset, "a failure after acceptance discloses")
	require.NotNil(t, body.Meta.PartialReset.ResetCount, "the disclosure of an execution carries resetCount")
	assert.Equal(t, 0, *body.Meta.PartialReset.ResetCount, "the failure names deletions the store refused")

	for _, client := range []string{"alice", "bob", "carol"} {
		_, found := h.remaining(t, client)
		assert.True(t, found, "the counter of %s is gone", client)
	}
}

// readBackFailingRecords refuses the first batch the way batchRefusingRecords
// does, and then answers the read-back of the failed sweep's record with
// lookupErr, or with no record when lookupErr is nil.
type readBackFailingRecords struct {
	batchRefusingRecords
	refused   *bool
	lookupErr error
}

func (r readBackFailingRecords) Batch(ctx context.Context, batch records.Batch) error {
	*r.refused = true
	return r.batchRefusingRecords.Batch(ctx, batch)
}

func (r readBackFailingRecords) Lookup(ctx context.Context, keys records.Keys) (records.Record, error) {
	if !*r.refused {
		return r.Store.Lookup(ctx, keys)
	}
	return records.Record{}, r.lookupErr
}

// A sweep that fails inside a batch reads its committed progress back before
// it records the failure. When that read fails, or finds no record, the
// command has nothing true to report: it answers that the store is down,
// rather than reporting the walker's count or a progress of zero.
func TestBulk_aFailureWithoutItsCommittedProgressAnswersThatTheStoreIsDown(t *testing.T) {
	for name, lookupErr := range map[string]error{"read fails": errStoreDown, "record gone": nil} {
		t.Run(name, func(t *testing.T) {
			h := newTestAPI(t)
			for _, client := range []string{"alice", "bob", "carol"} {
				h.spend(t, "/api/orders", map[string][]string{model.KeySub: {client}}, 1)
			}
			selector := map[string]any{"ruleIds": []string{"orders"}}
			preview := h.preview(t, map[string]any{"selector": selector}, "key-preview")

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			h.api.StartBackground(ctx)
			refused := false
			h.api.Records = readBackFailingRecords{
				batchRefusingRecords: batchRefusingRecords{
					contextBoundRecords: contextBoundRecords{Store: h.records}, cancel: cancel,
				},
				refused:   &refused,
				lookupErr: lookupErr,
			}

			requireError(t, h.bulk(t, map[string]any{
				"selector": selector, "confirmationToken": preview.ConfirmationToken,
			}, "key-execute", operatorRoles()), http.StatusServiceUnavailable, CodeStoreDown)
			assert.True(t, refused, "the sweep never reached the store")
		})
	}
}

// putRefusingRecords fails every Put, which is how a preview's token write
// fails, over records that refuse a done context.
type putRefusingRecords struct {
	contextBoundRecords
}

func (putRefusingRecords) Put(context.Context, string, []byte, time.Duration) error {
	return errStoreDown
}

// A preview whose token cannot be stored records that failure too when
// shutdown has ended the walk, rather than answering that the store is down.
func TestBulk_recordsAFailedMintWhenShutdownEndsTheWalk(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.api.StartBackground(ctx)
	h.api.Records = putRefusingRecords{contextBoundRecords{Store: h.records}}

	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)
}
