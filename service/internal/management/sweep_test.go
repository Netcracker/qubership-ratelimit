package management

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

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
		Keys:     records.Keys{Record: recordTag(testNamespace, testDomain) + "idem:other", Lease: leaseKey(testNamespace, testDomain)},
		Command:  "someone-elses-command",
		Fencing:  "someone-elses-fencing",
		LeaseTTL: ttl,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK)
}

// accepted plants a record for the command this test will send, as though an
// earlier call had been accepted and had, or had not, come back.
func (h *testAPI) accepted(t *testing.T, key string, command bulkCommand, leaseTTL time.Duration) records.Keys {
	t.Helper()

	name := recordKey(testNamespace, testDomain, endpointResets, listedCaller, key)
	keys := commandKeys(testNamespace, testDomain, name, command)

	accepted, err := h.records.Accept(context.Background(), records.Acceptance{
		Keys:     keys,
		Command:  command.command(testDomain),
		Fencing:  "the-original-walker",
		LeaseTTL: leaseTTL,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK)
	return keys
}

// previewCommand is the command the helpers below plant records for.
func previewCommand(t *testing.T) bulkCommand {
	t.Helper()

	command, apiErr := parseBulk(testDomain, BulkResetRequest{
		Selector: &SelectorBody{RuleIDs: []string{"orders"}},
		DryRun:   new(true),
	})
	require.Nil(t, apiErr)
	return command
}

// One sweep per domain, and the refusal happens before anything binds — so the
// caller's key and its token are both still spendable.
func TestBulk_refusesASecondSweepInTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.occupy(t, 30*time.Second)

	recorder := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller)

	body := requireError(t, recorder, http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictSweepInFlight, body.Meta.ConflictType)
	require.NotEmpty(t, recorder.Header().Get("Retry-After"), "the caller is told how long to wait")

	// Nothing bound: the same key works once the domain is free.
	h.records.Now = func() time.Time { return time.Now().Add(time.Minute) }
	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller).Code)
}

// A retry that meets its own command still in flight is a poll: no body, and a
// Retry-After naming when the outcome can be had.
func TestBulk_retryOfARunningCommandPolls(t *testing.T) {
	h := newTestAPI(t)
	h.accepted(t, "key-1", previewCommand(t), 30*time.Second)

	recorder := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller)

	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Empty(t, recorder.Body.String(), "there is nothing to say yet")
	require.NotEmpty(t, recorder.Header().Get("Retry-After"))
}

// A walker that never came back leaves an accepted record with a dead lease. The
// first retry finalizes it as interrupted, and the disclosure is the progress
// the batches had committed.
func TestBulk_retryFinalizesADeadSweep(t *testing.T) {
	h := newTestAPI(t)
	now := h.clock(t)

	command := previewCommand(t)
	keys := h.accepted(t, "key-1", command, 30*time.Second)

	// The walker got through part of the selection and then died.
	require.NoError(t, h.records.Batch(context.Background(), records.Batch{
		Keys: keys, Fencing: "the-original-walker",
		Progress: records.Progress{
			Scanned: 40, Matched: 12, Rules: map[string]int{"orders/per-client": 12},
			Keys: []string{"rl:v1:{gateway.public}:orders/per-client:gcra:3600:alice:"},
		},
	}))
	*now = now.Add(time.Minute)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusInternalServerError, CodeInterrupted)

	require.NotNil(t, body.Meta.PartialReset, "a command that may have deleted must disclose")
	require.Equal(t, 40, body.Meta.PartialReset.Scanned)
	require.NotNil(t, body.Meta.PartialReset.MatchedCount)
	require.Equal(t, 12, *body.Meta.PartialReset.MatchedCount)
	require.Len(t, body.Meta.PartialReset.Rules, 1)

	// And a later retry replays that outcome rather than finalizing again.
	replay := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusInternalServerError, CodeInterrupted)
	require.Equal(t, body.ID, replay.ID, "a replay is the same error instance")
	require.Equal(t, 40, replay.Meta.PartialReset.Scanned)
}

// The deadline is the server's bound on synchronous work. Hitting it is a
// recorded failure with its own code, because its recovery differs: narrow the
// selection, do not repeat the same width.
func TestBulk_deadlineIsRecordedWithItsDisclosure(t *testing.T) {
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
	}, "key-1", listedCaller), http.StatusUnprocessableEntity, CodeWorkLimit)

	require.NotNil(t, body.Meta.PartialReset)
	require.True(t, body.Meta.PartialReset.DryRun)
	require.Equal(t, 1, body.Meta.PartialReset.Scanned, "keys walked before the deadline")
	require.NotNil(t, body.Meta.PartialReset.MatchedCount)
	require.Contains(t, body.Message, "narrow")

	// The outcome is recorded: a retry of the same command replays it instead of
	// walking again.
	replay := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusUnprocessableEntity, CodeWorkLimit)
	require.Equal(t, body.ID, replay.ID)
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
	}, "key-1", listedCaller), http.StatusOK, &preview)

	require.Equal(t, clients, preview.Scanned, "keys the walk examined")
	require.NotNil(t, preview.MatchedCount)
	require.Equal(t, clients, *preview.MatchedCount, "counters the selection matched")
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
	}, "key-1", listedCaller), http.StatusUnprocessableEntity, CodeWorkLimit)

	require.NotNil(t, body.Meta.PartialReset)
	require.Equal(t, 0, body.Meta.PartialReset.Scanned, "no key was walked before the deadline")
}

// A failed sweep frees the domain: the lease is released with the outcome, so
// the next command is not blocked by a command that already ended.
func TestBulk_aRecordedFailureReleasesTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeySub: {"alice"}}, 1)

	h.deadlineAfter(t, 1)
	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusUnprocessableEntity, CodeWorkLimit)

	h.api.Now = nil
	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-2", listedCaller).Code, "the domain took the next command")
}

// Every 409 names its recovery, so a client branches on the field rather than
// on prose.
func TestBulk_conflictsNameTheirRecovery(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}}, "dryRun": true,
	}, "key-1", listedCaller).Code)

	mismatch := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"cascade"}}, "dryRun": true,
	}, "key-1", listedCaller), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictCommandMismatch, mismatch.Meta.ConflictType)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"orders"}},
	}, "key-2")

	stale := requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"cascade"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-3", listedCaller), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictStaleConfirmation, stale.Meta.ConflictType)
}

// The addressed DELETE pins the rule-set version the same way, and its conflict
// names the same kind of recovery.
func TestReset_versionConflictNamesItsRecovery(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.reset(t,
		"ruleId=orders/per-client&axis.sub=alice&expectedRuleSetVersion=000000000000",
		"key-1", listedCaller), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictStaleRuleSet, body.Meta.ConflictType)
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
	}, "key-1", listedCaller), http.StatusOK, &preview)
	require.NotEmpty(t, preview.ConfirmationToken, "the preview's token was not stored")
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
	}, "key-1", listedCaller), http.StatusUnprocessableEntity, CodeWorkLimit)
	require.NotNil(t, body.Meta.PartialReset)
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
	}, "key-execute", listedCaller), http.StatusInternalServerError, CodeInterrupted)
	require.NotNil(t, body.Meta.PartialReset)
	require.NotNil(t, body.Meta.PartialReset.ResetCount)
	require.Zero(t, *body.Meta.PartialReset.ResetCount, "the failure names deletions the store refused")

	for _, client := range []string{"alice", "bob", "carol"} {
		_, found := h.remaining(t, client)
		require.True(t, found, "the counter of %s is gone", client)
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
				batchRefusingRecords: batchRefusingRecords{contextBoundRecords: contextBoundRecords{Store: h.records}, cancel: cancel},
				refused:              &refused,
				lookupErr:            lookupErr,
			}

			requireError(t, h.bulk(t, map[string]any{
				"selector": selector, "confirmationToken": preview.ConfirmationToken,
			}, "key-execute", listedCaller), http.StatusServiceUnavailable, CodeStoreDown)
			require.True(t, refused, "the sweep never reached the store")
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
	}, "key-1", listedCaller), http.StatusInternalServerError, CodeInterrupted)
}
