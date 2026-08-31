package management

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// A bulk command runs to completion inside the call, under a server deadline and
// a domain lease. These tests cover what that costs: the second sweep is
// refused, a client that comes back mid-walk polls, a walker that died is
// finalized by the next retry, and every one of those failures discloses what
// the command actually did.

// deadlineAfter makes the walk run out of time once it has consulted the clock
// the given number of times: one for the deadline itself, then one per key.
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
		Keys:     records.Keys{Record: "rlm:v1:{" + testDomain + "}:idem:other", Lease: leaseKey(testDomain)},
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

	name := recordKey(testDomain, endpointResets, "alice@example.com", key)
	keys := commandKeys(testDomain, name, command)

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
		Selector: &SelectorBody{RuleIDs: []string{"api/orders"}},
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
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles())

	body := requireError(t, recorder, http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictSweepInFlight, body.Meta.ConflictType)
	require.NotEmpty(t, recorder.Header().Get("Retry-After"), "the caller is told how long to wait")

	// Nothing bound: the same key works once the domain is free.
	h.records.Now = func() time.Time { return time.Now().Add(time.Minute) }
	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()).Code)
}

// A retry that meets its own command still in flight is a poll: no body, and a
// Retry-After naming when the outcome can be had.
func TestBulk_retryOfARunningCommandPolls(t *testing.T) {
	h := newTestAPI(t)
	h.accepted(t, "key-1", previewCommand(t), 30*time.Second)

	recorder := h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles())

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
			Scanned: 40, Matched: 12, Rules: map[string]int{"api/orders/per-client": 12},
			Keys: []string{"rl:v1:{gateway.public}:api/orders/per-client:gcra:3600:alice:"},
		},
	}))
	*now = now.Add(time.Minute)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)

	require.NotNil(t, body.Meta.PartialReset, "a command that may have deleted must disclose")
	require.Equal(t, 40, body.Meta.PartialReset.Scanned)
	require.NotNil(t, body.Meta.PartialReset.MatchedCount)
	require.Equal(t, 12, *body.Meta.PartialReset.MatchedCount)
	require.Len(t, body.Meta.PartialReset.Rules, 1)

	// And a later retry replays that outcome rather than finalizing again.
	replay := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusInternalServerError, CodeInterrupted)
	require.Equal(t, body.ID, replay.ID, "a replay is the same error instance")
	require.Equal(t, 40, replay.Meta.PartialReset.Scanned)
}

// The deadline is the server's bound on synchronous work. Hitting it is a
// recorded failure with its own code, because its recovery differs: narrow the
// selection, do not repeat the same width.
func TestBulk_deadlineIsRecordedWithItsDisclosure(t *testing.T) {
	h := newTestAPI(t)
	for _, client := range []string{"alice", "bob", "carol"} {
		h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {client}}, 1)
	}

	// The clock jumps past the deadline after the walk has counted one key, so
	// the failure discloses progress rather than zeroes.
	h.deadlineAfter(t, 2)

	body := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)

	require.NotNil(t, body.Meta.PartialReset)
	require.True(t, body.Meta.PartialReset.DryRun)
	require.NotNil(t, body.Meta.PartialReset.MatchedCount)
	require.Contains(t, body.Message, "narrow")

	// The outcome is recorded: a retry of the same command replays it instead of
	// walking again.
	replay := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)
	require.Equal(t, body.ID, replay.ID)
}

// A failed sweep frees the domain: the lease is released with the outcome, so
// the next command is not blocked by a command that already ended.
func TestBulk_aRecordedFailureReleasesTheDomain(t *testing.T) {
	h := newTestAPI(t)
	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"alice"}}, 1)

	h.deadlineAfter(t, 1)
	requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusUnprocessableEntity, CodeWorkLimit)

	h.api.Now = nil
	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-2", operatorRoles()).Code, "the domain took the next command")
}

// Every 409 names its recovery, so a client branches on the field rather than
// on prose.
func TestBulk_conflictsNameTheirRecovery(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}}, "dryRun": true,
	}, "key-1", operatorRoles()).Code)

	mismatch := requireError(t, h.bulk(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"quote-api"}}, "dryRun": true,
	}, "key-1", operatorRoles()), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictCommandMismatch, mismatch.Meta.ConflictType)

	preview := h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-2")

	stale := requireError(t, h.bulk(t, map[string]any{
		"selector":          map[string]any{"ruleIds": []string{"quote-api/cascade"}},
		"confirmationToken": preview.ConfirmationToken,
	}, "key-3", operatorRoles()), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictStaleConfirmation, stale.Meta.ConflictType)
}

// The addressed DELETE pins the rule-set version the same way, and its conflict
// names the same kind of recovery.
func TestReset_versionConflictNamesItsRecovery(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.reset(t,
		"ruleId=api/orders/per-client&axis.client=alice&expectedRuleSetVersion=000000000000",
		"key-1", operatorRoles()), http.StatusConflict, CodeConflict)
	require.Equal(t, ConflictStaleRuleSet, body.Meta.ConflictType)
}
