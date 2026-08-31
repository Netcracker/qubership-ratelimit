package records_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The record is the operation: it says whether a command may run, what it did,
// and — through the domain lease it claims — whether the walker that took it on
// is still alive. These tests work that state machine.

const (
	recordKey = "rlm:v1:{d}:idem:counter-resets:abc"
	leaseKey  = "rlm:v1:{d}:sweep"
	tokenKey  = "rlm:v1:{d}:ct:ct-0123456789ab"
)

func keys() records.Keys {
	return records.Keys{Record: recordKey, Lease: leaseKey}
}

func newRecords() *records.Memory { return records.NewMemory(memory.New()) }

func accept(t *testing.T, commands *records.Memory, k records.Keys, command, fencing string) records.Accepted {
	t.Helper()
	accepted, err := commands.Accept(context.Background(), records.Acceptance{
		Keys: k, Command: command, Fencing: fencing, LeaseTTL: time.Minute,
	})
	require.NoError(t, err)
	return accepted
}

func TestAccept_bindsTheKeyAndClaimsTheLease(t *testing.T) {
	commands := newRecords()

	accepted := accept(t, commands, keys(), "command-a", "fence-1")
	require.True(t, accepted.OK)

	record, err := commands.Lookup(context.Background(), keys())
	require.NoError(t, err)
	require.True(t, record.Found)
	require.Equal(t, "command-a", record.Command)
	require.False(t, record.Terminal)
	require.True(t, record.Alive(), "the sweep that took this on still holds the domain")
}

// One sweep per domain: the second command is refused before anything binds, so
// its Idempotency-Key and its confirmation token are still spendable.
func TestAccept_refusesASecondSweepInTheDomain(t *testing.T) {
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	other := records.Keys{Record: recordKey + "-2", Lease: leaseKey}
	second := accept(t, commands, other, "command-b", "fence-2")

	require.False(t, second.OK)
	require.True(t, second.SweepBusy)
	require.Positive(t, second.LeaseTTL, "the caller is told how long to wait")

	record, err := commands.Lookup(context.Background(), other)
	require.NoError(t, err)
	require.False(t, record.Found, "a refusal before acceptance binds nothing")
}

// The lease is checked before the token is consumed: a command refused for a
// sweep already in flight must not spend the look that authorized it.
func TestAccept_keepsTheTokenWhenTheDomainIsBusy(t *testing.T) {
	ctx := context.Background()
	commands := newRecords()
	require.NoError(t, commands.Put(ctx, tokenKey, []byte(`{"selection":"x"}`), time.Minute))
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	busy, err := commands.Accept(ctx, records.Acceptance{
		Keys:     records.Keys{Record: recordKey + "-2", Lease: leaseKey, Token: tokenKey},
		Command:  "command-b",
		Fencing:  "fence-2",
		LeaseTTL: time.Minute,
	})
	require.NoError(t, err)
	require.True(t, busy.SweepBusy)

	_, found, err := commands.Get(ctx, tokenKey)
	require.NoError(t, err)
	require.True(t, found, "the token was not spent on a command that never ran")
}

func TestAccept_consumesTheTokenExactlyOnce(t *testing.T) {
	ctx := context.Background()
	commands := newRecords()
	require.NoError(t, commands.Put(ctx, tokenKey, []byte(`{"selection":"x"}`), time.Minute))

	first, err := commands.Accept(ctx, records.Acceptance{
		Keys:    records.Keys{Record: recordKey, Lease: leaseKey, Token: tokenKey},
		Command: "command-a", Fencing: "fence-1", LeaseTTL: time.Minute,
	})
	require.NoError(t, err)
	require.True(t, first.OK)
	require.JSONEq(t, `{"selection":"x"}`, string(first.Token))

	// The sweep ends, and the domain is free again.
	require.NoError(t, commands.Commit(ctx, records.Commit{
		Keys: keys(), Fencing: "fence-1", Outcome: records.Outcome{},
	}))

	second, err := commands.Accept(ctx, records.Acceptance{
		Keys:    records.Keys{Record: recordKey + "-2", Lease: leaseKey, Token: tokenKey},
		Command: "command-b", Fencing: "fence-2", LeaseTTL: time.Minute,
	})
	require.NoError(t, err)
	require.True(t, second.TokenMissing, "a single-use token cannot authorize a second command")
}

func TestAccept_reportsTheBindingAKeyAlreadyHas(t *testing.T) {
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	again := accept(t, commands, keys(), "command-a", "fence-2")
	require.False(t, again.OK)
	require.Equal(t, "command-a", again.Existing.Command)
}

// A batch is one step: prove the domain is still ours, delete, record what that
// made true. A walker that lost the lease deletes nothing further.
func TestBatch_deletesAndAdvancesProgressUnderTheFencingToken(t *testing.T) {
	ctx := context.Background()
	counters := memory.New()
	commands := records.NewMemory(counters)
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	err := commands.Batch(ctx, records.Batch{
		Keys: keys(), Fencing: "fence-1",
		Progress: records.Progress{Scanned: 10, Matched: 4, Reset: 4, Rules: map[string]int{"a/b/c": 4}},
	})
	require.NoError(t, err)

	record, err := commands.Lookup(ctx, keys())
	require.NoError(t, err)
	require.Equal(t, 10, record.Progress.Scanned)
	require.Equal(t, 4, record.Progress.Reset)
	require.Equal(t, map[string]int{"a/b/c": 4}, record.Progress.Rules)
}

func TestBatch_refusesAWalkerThatLostTheDomain(t *testing.T) {
	ctx := context.Background()
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	err := commands.Batch(ctx, records.Batch{
		Keys: keys(), Fencing: "fence-someone-else",
		Progress: records.Progress{Scanned: 1},
	})
	require.ErrorIs(t, err, records.ErrLeaseLost)

	record, err := commands.Lookup(ctx, keys())
	require.NoError(t, err)
	require.Zero(t, record.Progress.Scanned, "a lost lease writes nothing at all")
}

func TestCommit_recordsTheOutcomeAndReleasesTheDomain(t *testing.T) {
	ctx := context.Background()
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	require.NoError(t, commands.Commit(ctx, records.Commit{
		Keys: keys(), Fencing: "fence-1",
		Outcome: records.Outcome{
			Progress: records.Progress{Scanned: 12, Reset: 5},
			Token:    "ct-0123456789ab",
		},
	}))

	record, err := commands.Lookup(ctx, keys())
	require.NoError(t, err)
	require.True(t, record.Terminal)
	require.Equal(t, 5, record.Outcome.Progress.Reset)
	require.Equal(t, "ct-0123456789ab", record.Outcome.Token)
	require.False(t, record.Alive())

	// The domain takes another sweep now.
	other := records.Keys{Record: recordKey + "-2", Lease: leaseKey}
	require.True(t, accept(t, commands, other, "command-b", "fence-2").OK)
}

func TestCommit_refusesAWalkerThatLostTheDomain(t *testing.T) {
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	err := commands.Commit(context.Background(), records.Commit{
		Keys: keys(), Fencing: "fence-someone-else", Outcome: records.Outcome{},
	})
	require.ErrorIs(t, err, records.ErrLeaseLost)
}

// A record left accepted with a dead lease is a sweep whose walker never came
// back. The first retry finalizes it, and the disclosure comes from the progress
// the batches had committed.
func TestFinalize_recordsTheOutcomeOfADeadSweep(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	commands := newRecords()
	commands.Now = func() time.Time { return now }
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)
	require.NoError(t, commands.Batch(ctx, records.Batch{
		Keys: keys(), Fencing: "fence-1",
		Progress: records.Progress{Scanned: 40, Reset: 31},
	}))

	// The walker dies. Its lease outlives it, and then it does not.
	now = now.Add(2 * time.Minute)

	record, err := commands.Finalize(ctx, records.Finalize{
		Keys:    keys(),
		Outcome: records.Outcome{Failed: true, Code: "RLS-0501", ErrorID: "id-1"},
	})
	require.NoError(t, err)
	require.True(t, record.Terminal)
	require.True(t, record.Outcome.Failed)
	require.Equal(t, "RLS-0501", record.Outcome.Code)
	require.Equal(t, 31, record.Outcome.Progress.Reset, "the disclosure is what the batches committed")
}

// A live owner beats the finalizer: nobody rewrites an outcome somebody may
// still be producing.
func TestFinalize_leavesALiveSweepAlone(t *testing.T) {
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	record, err := commands.Finalize(context.Background(), records.Finalize{
		Keys:    keys(),
		Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
	})
	require.NoError(t, err)
	require.False(t, record.Terminal)
	require.True(t, record.Alive())
}

func TestFinalize_keepsTheOutcomeAlreadyRecorded(t *testing.T) {
	ctx := context.Background()
	commands := newRecords()
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)
	require.NoError(t, commands.Commit(ctx, records.Commit{
		Keys: keys(), Fencing: "fence-1",
		Outcome: records.Outcome{Progress: records.Progress{Reset: 7}},
	}))

	record, err := commands.Finalize(ctx, records.Finalize{
		Keys:    keys(),
		Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
	})
	require.NoError(t, err)
	require.False(t, record.Outcome.Failed, "a finished command is not re-judged")
	require.Equal(t, 7, record.Outcome.Progress.Reset)
}

// The addressed form is one step, so it has no intermediate state to recover
// from: bind, delete, record.
func TestReset_bindsDeletesAndRecordsInOneStep(t *testing.T) {
	ctx := context.Background()
	counters := memory.New()
	commands := records.NewMemory(counters)

	live := spend(t, counters, "rl:v1:{d}:a/b/c:gcra:60:alice:")

	outcome, err := commands.Reset(ctx, records.Addressed{
		Record: recordKey, Command: "command-a", Delete: []string{live},
	})
	require.NoError(t, err)
	require.False(t, outcome.Replayed)
	require.Equal(t, 1, outcome.Count)

	found, err := counters.Keys(ctx, live)
	require.NoError(t, err)
	require.Empty(t, found, "the counter is gone")
}

func TestReset_replaysTheRecordedCount(t *testing.T) {
	ctx := context.Background()
	counters := memory.New()
	commands := records.NewMemory(counters)
	live := spend(t, counters, "rl:v1:{d}:a/b/c:gcra:60:alice:")

	first, err := commands.Reset(ctx, records.Addressed{
		Record: recordKey, Command: "command-a", Delete: []string{live},
	})
	require.NoError(t, err)
	require.Equal(t, 1, first.Count)

	// The client spends again, and retries the same command.
	spend(t, counters, live)
	second, err := commands.Reset(ctx, records.Addressed{
		Record: recordKey, Command: "command-a", Delete: []string{live},
	})
	require.NoError(t, err)
	require.True(t, second.Replayed)
	require.Equal(t, 1, second.Count, "the retry answers what the first call did")

	found, err := counters.Keys(ctx, live)
	require.NoError(t, err)
	require.Len(t, found, 1, "and it did not delete a second time")
}

func TestReset_previewCountsWithoutDeleting(t *testing.T) {
	ctx := context.Background()
	counters := memory.New()
	commands := records.NewMemory(counters)
	live := spend(t, counters, "rl:v1:{d}:a/b/c:gcra:60:alice:")

	outcome, err := commands.Reset(ctx, records.Addressed{
		Record: recordKey, Command: "command-a", Delete: []string{live}, DryRun: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, outcome.Count)

	found, err := counters.Keys(ctx, live)
	require.NoError(t, err)
	require.Len(t, found, 1, "a preview deletes nothing")
}

func TestReset_reportsTheCommandAKeyIsBoundTo(t *testing.T) {
	commands := newRecords()

	_, err := commands.Reset(context.Background(), records.Addressed{
		Record: recordKey, Command: "command-a",
	})
	require.NoError(t, err)

	outcome, err := commands.Reset(context.Background(), records.Addressed{
		Record: recordKey, Command: "command-b",
	})
	require.NoError(t, err)
	require.True(t, outcome.Replayed)
	require.Equal(t, "command-a", outcome.Command, "the caller compares and refuses")
}

// Retention runs from the outcome, not from acceptance, so a slow command is
// not penalized for being slow. The lease has to outlive the walk for the two to
// differ at all — a commit under a dead lease is refused, which is the point of
// the lease.
func TestRetention_startsAtTheRecordedOutcome(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	commands := newRecords()
	commands.Now = func() time.Time { return now }
	accepted, err := commands.Accept(ctx, records.Acceptance{
		Keys: keys(), Command: "command-a", Fencing: "fence-1", LeaseTTL: 2 * time.Hour,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK)

	// The command runs for an hour and then records what it did.
	now = now.Add(time.Hour)
	require.NoError(t, commands.Commit(ctx, records.Commit{
		Keys: keys(), Fencing: "fence-1", Outcome: records.Outcome{},
	}))

	// Past the window the acceptance would have given it, the outcome is still
	// there to replay.
	now = now.Add(records.Retention - 30*time.Minute)
	record, err := commands.Lookup(ctx, keys())
	require.NoError(t, err)
	require.True(t, record.Found)

	now = now.Add(time.Hour)
	record, err = commands.Lookup(ctx, keys())
	require.NoError(t, err)
	require.False(t, record.Found)
}

// A record that never got an outcome expires from acceptance, so an interrupted
// command does not sit in limbo forever.
func TestRetention_expiresAnInterruptedRecordFromAcceptance(t *testing.T) {
	now := time.Now()
	commands := newRecords()
	commands.Now = func() time.Time { return now }
	require.True(t, accept(t, commands, keys(), "command-a", "fence-1").OK)

	now = now.Add(records.Retention + time.Minute)
	record, err := commands.Lookup(context.Background(), keys())
	require.NoError(t, err)
	require.False(t, record.Found)
}

// spend puts one counter key in the store, the way traffic would.
func spend(t *testing.T, counters *memory.Store, k string) string {
	t.Helper()
	// A decision creates the key; the window is irrelevant to what these tests
	// assert, only that the key exists afterwards.
	_, err := counters.Decide(context.Background(), []store.Bucket{{
		Key: k, Algorithm: algo.GCRAID, Window: algo.Window{Requests: 10, Period: time.Minute, Burst: 10},
	}}, 1)
	require.NoError(t, err)
	return k
}
