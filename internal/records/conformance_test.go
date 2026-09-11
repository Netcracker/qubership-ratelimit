package records_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// One contract, two implementations, one suite.
//
// The in-process store and the shared one are the same state machine over
// different primitives — a mutex against a Lua script — and the whole point of
// the shared one is that it behaves identically under concurrency the other
// never sees. A suite that runs against both is what keeps "they agree" a fact
// rather than an assumption; without it the Redis scripts would be exercised
// only in production, on the destructive path.

// factory builds a store and the counters it deletes from.
type factory func(t *testing.T) (records.Store, store.Store)

func TestConformance(t *testing.T) {
	for name, build := range map[string]factory{
		"in-process": memoryFactory,
		"redis":      redisFactory,
	} {
		t.Run(name, func(t *testing.T) { runConformance(t, build) })
	}
}

func runConformance(t *testing.T, build factory) {
	t.Run("acceptance binds the key and claims the lease", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		accepted := acceptWith(t, commands, k, "command-a", "fence-1", time.Minute)
		require.True(t, accepted.OK)

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		require.True(t, record.Found)
		require.Equal(t, "command-a", record.Command)
		require.False(t, record.Terminal)
		require.True(t, record.Alive())
	})

	t.Run("a second sweep in the domain is refused before anything binds", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease = first.Lease

		require.True(t, acceptWith(t, commands, first, "command-a", "fence-1", time.Minute).OK)
		busy := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)

		require.True(t, busy.SweepBusy)
		require.Positive(t, busy.LeaseTTL)

		record, err := commands.Lookup(t.Context(), second)
		require.NoError(t, err)
		require.False(t, record.Found)
	})

	t.Run("a busy domain does not spend the confirmation token", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease, second.Token = first.Lease, first.Record+":token"

		require.NoError(t, commands.Put(t.Context(), second.Token, []byte(`{"selection":"x"}`), time.Minute))
		require.True(t, acceptWith(t, commands, first, "command-a", "fence-1", time.Minute).OK)

		busy := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)
		require.True(t, busy.SweepBusy)

		_, found, err := commands.Get(t.Context(), second.Token)
		require.NoError(t, err)
		require.True(t, found)
	})

	t.Run("the confirmation token is consumed exactly once", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease = first.Lease
		first.Token = first.Record + ":token"
		second.Token = first.Token

		require.NoError(t, commands.Put(t.Context(), first.Token, []byte(`{"selection":"x"}`), time.Minute))

		accepted := acceptWith(t, commands, first, "command-a", "fence-1", time.Minute)
		require.True(t, accepted.OK)
		require.JSONEq(t, `{"selection":"x"}`, string(accepted.Token))

		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: first, Fencing: "fence-1", Outcome: records.Outcome{},
		}))

		again := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)
		require.True(t, again.TokenMissing)
	})

	t.Run("a bound key reports the command it carries", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)
		again := acceptWith(t, commands, k, "command-a", "fence-2", time.Minute)

		require.False(t, again.OK)
		require.Equal(t, "command-a", again.Existing.Command)
	})

	t.Run("a batch deletes and advances the progress together", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)

		live := spend(t, counters, counterKey(t))
		require.NoError(t, commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "fence-1", Delete: []string{live},
			Progress: records.Progress{Scanned: 10, Matched: 4, Reset: 4,
				Rules: map[string]int{"a/b/c": 4}, Keys: []string{live}},
		}))

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		require.Equal(t, 10, record.Progress.Scanned)
		require.Equal(t, 4, record.Progress.Reset)
		require.Equal(t, map[string]int{"a/b/c": 4}, record.Progress.Rules)

		found := keysUnder(t, counters, live)
		require.Empty(t, found, "the batch deleted what it counted")
	})

	t.Run("a walker that lost the domain writes nothing", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)

		live := spend(t, counters, counterKey(t))
		err := commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "someone-else", Delete: []string{live},
			Progress: records.Progress{Scanned: 99},
		})
		require.ErrorIs(t, err, records.ErrLeaseLost)

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		require.Zero(t, record.Progress.Scanned)

		found := keysUnder(t, counters, live)
		require.Len(t, found, 1, "and it deleted nothing either")
	})

	t.Run("the outcome releases the domain", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)

		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "fence-1",
			Outcome: records.Outcome{
				Progress: records.Progress{Scanned: 12, Reset: 5},
				Token:    "ct-0123456789ab",
			},
		}))

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		require.True(t, record.Terminal)
		require.Equal(t, 5, record.Outcome.Progress.Reset)
		require.Equal(t, "ct-0123456789ab", record.Outcome.Token)
		require.False(t, record.Alive())

		next := freshKeys(t)
		next.Lease = k.Lease
		require.True(t, acceptWith(t, commands, next, "command-b", "fence-2", time.Minute).OK)
	})

	t.Run("only the owner may record the outcome", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)

		err := commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "someone-else", Outcome: records.Outcome{},
		})
		require.ErrorIs(t, err, records.ErrLeaseLost)
	})

	t.Run("a dead sweep is finalized from its committed progress", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		// A lease shorter than the test is how a dead walker is staged: it
		// expires while the record stays accepted.
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", 100*time.Millisecond).OK)
		require.NoError(t, commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "fence-1", Progress: records.Progress{Scanned: 40, Reset: 31},
		}))
		waitForLease(t, commands, k)

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys:    k,
			Outcome: records.Outcome{Failed: true, Code: "RLS-0501", ErrorID: "id-1"},
		})
		require.NoError(t, err)
		require.True(t, record.Terminal)
		require.True(t, record.Outcome.Failed)
		require.Equal(t, "RLS-0501", record.Outcome.Code)
		require.Equal(t, 31, record.Outcome.Progress.Reset)
	})

	t.Run("a live sweep is left alone", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys: k, Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
		})
		require.NoError(t, err)
		require.False(t, record.Terminal)
		require.True(t, record.Alive())
	})

	t.Run("an outcome already recorded is not re-judged", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		require.True(t, acceptWith(t, commands, k, "command-a", "fence-1", time.Minute).OK)
		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "fence-1",
			Outcome: records.Outcome{Progress: records.Progress{Reset: 7}},
		}))

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys: k, Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
		})
		require.NoError(t, err)
		require.False(t, record.Outcome.Failed)
		require.Equal(t, 7, record.Outcome.Progress.Reset)
	})

	t.Run("the addressed reset binds, deletes, and records in one step", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))

		outcome, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})
		require.NoError(t, err)
		require.False(t, outcome.Replayed)
		require.Equal(t, 1, outcome.Count)

		found := keysUnder(t, counters, live)
		require.Empty(t, found)
	})

	t.Run("the addressed reset replays instead of deleting twice", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))

		first, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})
		require.NoError(t, err)
		require.Equal(t, 1, first.Count)

		spend(t, counters, live)
		second, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})
		require.NoError(t, err)
		require.True(t, second.Replayed)
		require.Equal(t, 1, second.Count)

		found := keysUnder(t, counters, live)
		require.Len(t, found, 1, "the retry deleted nothing")
	})

	t.Run("the addressed preview counts without deleting", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))

		outcome, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, DryRun: true,
		})
		require.NoError(t, err)
		require.Equal(t, 1, outcome.Count)

		found := keysUnder(t, counters, live)
		require.Len(t, found, 1)
	})

	// The answer is what a replay is built from: the API renders the body once
	// and hands it here, so a retry gets the bytes the first call gave rather
	// than a body rebuilt from a rule set that has moved on. It crosses the
	// wire as a hash field in Redis and as a value in the memory store, and a
	// renamed field on either side would break every replay while the cases
	// above stayed green.
	t.Run("the addressed reset carries its answer back to the replay", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))
		answer := []byte(`{"domain":"gateway.public","ruleId":"orders/per-client"}`)

		first, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, Answer: answer,
		})
		require.NoError(t, err)
		require.False(t, first.Replayed)

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		require.True(t, record.Found)
		require.True(t, record.Terminal)
		require.Equal(t, answer, record.Answer)

		second, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, Answer: answer,
		})
		require.NoError(t, err)
		require.True(t, second.Replayed)
		require.Equal(t, answer, second.Answer)
	})

	t.Run("the addressed reset reports the command a key is bound to", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		_, err := commands.Reset(t.Context(), records.Addressed{Record: k.Record, Command: "command-a"})
		require.NoError(t, err)

		outcome, err := commands.Reset(t.Context(), records.Addressed{Record: k.Record, Command: "command-b"})
		require.NoError(t, err)
		require.True(t, outcome.Replayed)
		require.Equal(t, "command-a", outcome.Command)
	})

	t.Run("an absent record is absent, not an error", func(t *testing.T) {
		commands, _ := build(t)

		record, err := commands.Lookup(t.Context(), freshKeys(t))
		require.NoError(t, err)
		require.False(t, record.Found)

		_, found, err := commands.Get(t.Context(), "rlm:v1:{d}:ct:nothing")
		require.NoError(t, err)
		require.False(t, found)
	})
}

// acceptWith runs one acceptance.
func acceptWith(
	t *testing.T,
	commands records.Store,
	k records.Keys,
	command, fencing string,
	lease time.Duration,
) records.Accepted {
	t.Helper()

	accepted, err := commands.Accept(t.Context(), records.Acceptance{
		Keys: k, Command: command, Fencing: fencing, LeaseTTL: lease,
	})
	require.NoError(t, err)
	return accepted
}

// waitForLease blocks until the domain lease has expired, which is what makes a
// walker dead as far as any other caller can tell.
func waitForLease(t *testing.T, commands records.Store, k records.Keys) {
	t.Helper()

	require.Eventually(t, func() bool {
		record, err := commands.Lookup(t.Context(), k)
		return err == nil && !record.Alive()
	}, 2*time.Second, 20*time.Millisecond, "the lease never expired")
}

// keysUnder walks the keys of one prefix to the end, which is how a test
// checks whether a counter still exists on any store.
func keysUnder(t *testing.T, counters store.Store, prefix string) []string {
	t.Helper()
	var found []string
	cursor := ""
	for {
		keys, next, err := counters.(store.Inspector).Scan(t.Context(), prefix, cursor, 100)
		require.NoError(t, err, "Scan(%q, %q)", prefix, cursor)
		found = append(found, keys...)
		if next == "" {
			return found
		}
		cursor = next
	}
}

// spend puts one counter key in the store, the way traffic would.
func spend(t *testing.T, counters store.Store, k string) string {
	t.Helper()

	_, err := counters.Decide(t.Context(), []store.Bucket{{
		Key:       k,
		Algorithm: algo.GCRAID,
		Window:    algo.Window{Requests: 10, Period: time.Minute, Burst: 10},
	}}, 1)
	require.NoError(t, err)
	return k
}
