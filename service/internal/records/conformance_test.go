package records_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
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

		require.True(t, accepted.OK, "Accept(command-a) = %+v", accepted)
		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.True(t, record.Found, "Lookup = %+v", record)
		assert.Equal(t, "command-a", record.Command, "Record.Command")
		assert.False(t, record.Terminal, "Record.Terminal")
		assert.True(t, record.Alive(), "Alive() of %+v", record)
	})

	// Acceptance is the one write that has to be atomic under concurrent
	// callers: whatever interleaving they meet, exactly one of them binds.
	t.Run("concurrent acceptances of one key bind it once", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		outcomes := acceptConcurrently(t, commands, func(int) records.Keys { return k })

		assert.Equal(t, 1, outcomes.ok, "acceptances that bound the key: %+v", outcomes)
		assert.Equal(t, concurrentCallers-1, outcomes.existing, "acceptances answered from the record: %+v", outcomes)
	})

	t.Run("concurrent acceptances under one token spend it once", func(t *testing.T) {
		commands, _ := build(t)
		token := freshKeys(t).Record + ":token"
		require.NoError(t, commands.Put(t.Context(), token, []byte(`{"selection":"x"}`), time.Minute))

		outcomes := acceptConcurrently(t, commands, func(int) records.Keys {
			k := freshKeys(t)
			k.Token = token
			return k
		})

		assert.Equal(t, 1, outcomes.ok, "acceptances that spent the token: %+v", outcomes)
		assert.Equal(t, concurrentCallers-1, outcomes.tokenMissing, "acceptances refused the spent token: %+v", outcomes)
	})

	t.Run("concurrent sweeps of one domain take the lease once", func(t *testing.T) {
		commands, _ := build(t)
		lease := freshKeys(t).Lease

		outcomes := acceptConcurrently(t, commands, func(int) records.Keys {
			k := freshKeys(t)
			k.Lease = lease
			return k
		})

		assert.Equal(t, 1, outcomes.ok, "acceptances that took the lease: %+v", outcomes)
		assert.Equal(t, concurrentCallers-1, outcomes.busy, "acceptances refused as a sweep in flight: %+v", outcomes)
	})

	t.Run("a second sweep in the domain is refused before anything binds", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease = first.Lease
		mustAccept(t, commands, first, "fence-1", time.Minute)

		busy := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)

		assert.True(t, busy.SweepBusy, "Accept(command-b) = %+v", busy)
		assert.Positive(t, busy.LeaseTTL, "Accepted.LeaseTTL")
		record, err := commands.Lookup(t.Context(), second)
		require.NoError(t, err)
		assert.False(t, record.Found, "Lookup of the record of command-b = %+v", record)
	})

	t.Run("a busy domain does not spend the confirmation token", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease, second.Token = first.Lease, first.Record+":token"
		require.NoError(t, commands.Put(t.Context(), second.Token, []byte(`{"selection":"x"}`), time.Minute))
		mustAccept(t, commands, first, "fence-1", time.Minute)

		busy := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)

		require.True(t, busy.SweepBusy, "Accept(command-b) = %+v", busy)
		_, found, err := commands.Get(t.Context(), second.Token)
		require.NoError(t, err)
		assert.True(t, found, "Get(%q) after the refused acceptance", second.Token)
	})

	t.Run("the confirmation token is consumed exactly once", func(t *testing.T) {
		commands, _ := build(t)
		first, second := freshKeys(t), freshKeys(t)
		second.Lease = first.Lease
		first.Token = first.Record + ":token"
		second.Token = first.Token
		require.NoError(t, commands.Put(t.Context(), first.Token, []byte(`{"selection":"x"}`), time.Minute))

		accepted := acceptWith(t, commands, first, "command-a", "fence-1", time.Minute)
		require.True(t, accepted.OK, "Accept(command-a) = %+v", accepted)
		assert.JSONEq(t, `{"selection":"x"}`, string(accepted.Token), "Accepted.Token")
		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: first, Fencing: "fence-1", Outcome: records.Outcome{},
		}))
		again := acceptWith(t, commands, second, "command-b", "fence-2", time.Minute)

		assert.True(t, again.TokenMissing, "Accept(command-b) with the token command-a consumed = %+v", again)
	})

	t.Run("a confirmation token past its TTL is missing", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		k.Token = k.Record + ":token"
		require.NoError(t, commands.Put(t.Context(), k.Token, []byte(`{"selection":"x"}`), 100*time.Millisecond))
		waitForTokenToExpire(t, commands, k.Token)

		accepted := acceptWith(t, commands, k, "command-a", "fence-1", time.Minute)

		assert.True(t, accepted.TokenMissing, "Accept(command-a) with a token past its TTL = %+v", accepted)
		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.False(t, record.Found, "Lookup of the record of command-a = %+v", record)
	})

	t.Run("a bound key reports the command it carries", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		first := acceptWith(t, commands, k, "command-a", "fence-1", time.Minute)
		require.True(t, first.OK, "Accept(command-a) = %+v", first)

		again := acceptWith(t, commands, k, "command-a", "fence-2", time.Minute)

		assert.False(t, again.OK, "Accept(command-a) on the bound key = %+v", again)
		assert.Equal(t, "command-a", again.Existing.Command, "Accepted.Existing.Command")
	})

	t.Run("a batch deletes and advances the progress together", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)
		live := spend(t, counters, counterKey(t))
		progress := records.Progress{Scanned: 10, Matched: 4, Reset: 4,
			Rules: map[string]int{"a/b/c": 4}, Keys: []string{live}}

		require.NoError(t, commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "fence-1", Delete: []string{live}, Progress: progress,
		}))

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.Equal(t, progress, record.Progress, "Record.Progress")
		assert.Empty(t, keysUnder(t, counters, live), "counters under %q", live)
	})

	t.Run("a walker that lost the domain writes nothing", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)
		live := spend(t, counters, counterKey(t))

		err := commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "someone-else", Delete: []string{live},
			Progress: records.Progress{Scanned: 99},
		})

		assert.ErrorIs(t, err, records.ErrLeaseLost)
		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.Equal(t, records.Progress{}, record.Progress, "Record.Progress")
		assert.Equal(t, []string{live}, keysUnder(t, counters, live), "counters under %q", live)
	})

	t.Run("a commit records its outcome as terminal", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)
		outcome := records.Outcome{
			Progress: records.Progress{Scanned: 12, Reset: 5},
			Token:    "ct-0123456789ab",
		}

		require.NoError(t, commands.Commit(t.Context(), records.Commit{Keys: k, Fencing: "fence-1", Outcome: outcome}))

		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.True(t, record.Terminal, "Record.Terminal")
		assert.Equal(t, outcome, record.Outcome, "Record.Outcome")
		assert.False(t, record.Alive(), "Alive() of %+v", record)
	})

	t.Run("a commit releases the domain to the next sweep", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)
		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "fence-1",
			Outcome: records.Outcome{
				Progress: records.Progress{Scanned: 12, Reset: 5},
				Token:    "ct-0123456789ab",
			},
		}))
		next := freshKeys(t)
		next.Lease = k.Lease

		accepted := acceptWith(t, commands, next, "command-b", "fence-2", time.Minute)

		assert.True(t, accepted.OK, "Accept(command-b) in the released domain = %+v", accepted)
	})

	t.Run("only the owner may record the outcome", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)

		err := commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "someone-else", Outcome: records.Outcome{},
		})

		assert.ErrorIs(t, err, records.ErrLeaseLost)
		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.False(t, record.Terminal, "Record.Terminal after the refused Commit")
		assert.True(t, record.Alive(), "Alive() after the refused Commit of %+v", record)
	})

	t.Run("a dead sweep is finalized from its committed progress", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		// A lease shorter than the test is how a dead walker is staged: it
		// expires while the record stays accepted.
		mustAccept(t, commands, k, "fence-1", 100*time.Millisecond)
		require.NoError(t, commands.Batch(t.Context(), records.Batch{
			Keys: k, Fencing: "fence-1", Progress: records.Progress{Scanned: 40, Reset: 31},
		}))
		waitForLease(t, commands, k)

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys:    k,
			Outcome: records.Outcome{Failed: true, Code: "RLS-0501", ErrorID: "id-1"},
		})

		require.NoError(t, err)
		assert.True(t, record.Terminal, "Record.Terminal")
		assert.Equal(t, records.Outcome{
			Failed: true, Code: "RLS-0501", ErrorID: "id-1",
			Progress: records.Progress{Scanned: 40, Reset: 31},
		}, record.Outcome, "Record.Outcome")
	})

	t.Run("a live sweep is left alone", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys: k, Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
		})

		require.NoError(t, err)
		assert.False(t, record.Terminal, "Record.Terminal")
		assert.True(t, record.Alive(), "Alive() of %+v", record)
	})

	t.Run("an outcome already recorded is not re-judged", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		mustAccept(t, commands, k, "fence-1", time.Minute)
		require.NoError(t, commands.Commit(t.Context(), records.Commit{
			Keys: k, Fencing: "fence-1",
			Outcome: records.Outcome{Progress: records.Progress{Reset: 7}},
		}))

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys: k, Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
		})

		require.NoError(t, err)
		assert.Equal(t, records.Outcome{Progress: records.Progress{Reset: 7}}, record.Outcome, "Record.Outcome")
	})

	t.Run("finalizing a record never accepted writes nothing", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)

		record, err := commands.Finalize(t.Context(), records.Finalize{
			Keys: k, Outcome: records.Outcome{Failed: true, Code: "RLS-0501"},
		})

		require.NoError(t, err)
		assert.False(t, record.Found, "Finalize of a record never accepted = %+v", record)
		after, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.False(t, after.Found, "Lookup after the Finalize = %+v", after)
	})

	t.Run("the addressed reset binds, deletes, and records in one step", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))

		outcome, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})

		require.NoError(t, err)
		assert.False(t, outcome.Replayed, "AddressedOutcome.Replayed")
		assert.Equal(t, 1, outcome.Count, "AddressedOutcome.Count")
		assert.Empty(t, keysUnder(t, counters, live), "counters under %q", live)
	})

	t.Run("the addressed reset replays instead of deleting twice", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))
		first, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})
		require.NoError(t, err)
		require.Equal(t, 1, first.Count, "Count of the first Reset")
		spend(t, counters, live)

		second, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live},
		})

		require.NoError(t, err)
		assert.True(t, second.Replayed, "AddressedOutcome.Replayed of the retry")
		assert.Equal(t, 1, second.Count, "AddressedOutcome.Count of the retry")
		assert.Equal(t, []string{live}, keysUnder(t, counters, live), "counters under %q", live)
	})

	t.Run("the addressed preview counts without deleting", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))

		outcome, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, DryRun: true,
		})

		require.NoError(t, err)
		assert.Equal(t, 1, outcome.Count, "AddressedOutcome.Count")
		assert.Equal(t, []string{live}, keysUnder(t, counters, live), "counters under %q", live)
	})

	// The answer is what a replay is built from: the API renders the body once
	// and hands it here, so a retry gets the bytes the first call gave rather
	// than a body rebuilt from a rule set that has moved on. It crosses the
	// wire as a hash field in Redis and as a value in the memory store, and a
	// renamed field on either side would break every replay while every other
	// subtest of this suite stayed green.
	t.Run("the addressed reset carries its answer back to the replay", func(t *testing.T) {
		commands, counters := build(t)
		k := freshKeys(t)
		live := spend(t, counters, counterKey(t))
		answer := []byte(`{"domain":"gateway.public","ruleId":"orders/per-client"}`)

		first, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, Answer: answer,
		})
		require.NoError(t, err)
		require.False(t, first.Replayed, "AddressedOutcome.Replayed of the first Reset")
		record, err := commands.Lookup(t.Context(), k)
		require.NoError(t, err)
		assert.True(t, record.Found, "Lookup = %+v", record)
		assert.True(t, record.Terminal, "Record.Terminal")
		assert.Equal(t, answer, record.Answer, "Record.Answer")
		second, err := commands.Reset(t.Context(), records.Addressed{
			Record: k.Record, Command: "command-a", Delete: []string{live}, Answer: answer,
		})

		require.NoError(t, err)
		assert.True(t, second.Replayed, "AddressedOutcome.Replayed of the retry")
		assert.Equal(t, answer, second.Answer, "AddressedOutcome.Answer of the retry")
	})

	t.Run("the addressed reset reports the command a key is bound to", func(t *testing.T) {
		commands, _ := build(t)
		k := freshKeys(t)
		_, err := commands.Reset(t.Context(), records.Addressed{Record: k.Record, Command: "command-a"})
		require.NoError(t, err)

		outcome, err := commands.Reset(t.Context(), records.Addressed{Record: k.Record, Command: "command-b"})

		require.NoError(t, err)
		assert.True(t, outcome.Replayed, "AddressedOutcome.Replayed of command-b")
		assert.Equal(t, "command-a", outcome.Command, "AddressedOutcome.Command of command-b")
	})

	t.Run("an absent record is absent, not an error", func(t *testing.T) {
		commands, _ := build(t)

		record, err := commands.Lookup(t.Context(), freshKeys(t))

		require.NoError(t, err)
		assert.False(t, record.Found, "Lookup of a record never written = %+v", record)
	})

	t.Run("an absent token is absent, not an error", func(t *testing.T) {
		commands, _ := build(t)

		_, found, err := commands.Get(t.Context(), "rlm:v1:{d}:ct:nothing")

		require.NoError(t, err)
		assert.False(t, found, "Get of a token never put")
	})
}

// concurrentCallers is how many acceptances acceptConcurrently races.
const concurrentCallers = 32

// acceptances counts how a race of acceptances ended.
type acceptances struct {
	ok, existing, tokenMissing, busy, failed int
}

// acceptConcurrently starts concurrentCallers acceptances at once, the i-th
// over keysOf(i) with a fencing token of its own, and counts their outcomes.
func acceptConcurrently(t *testing.T, commands records.Store, keysOf func(i int) records.Keys) acceptances {
	t.Helper()

	keys := make([]records.Keys, concurrentCallers)
	for i := range keys {
		keys[i] = keysOf(i)
	}
	results := make([]records.Accepted, concurrentCallers)
	errs := make([]error, concurrentCallers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range concurrentCallers {
		wg.Go(func() {
			<-start
			results[i], errs[i] = commands.Accept(t.Context(), records.Acceptance{
				Keys: keys[i], Command: "command-a", Fencing: fmt.Sprintf("fence-%d", i), LeaseTTL: time.Minute,
			})
		})
	}
	close(start)
	wg.Wait()

	var out acceptances
	for i, result := range results {
		switch {
		case errs[i] != nil:
			out.failed++
		case result.OK:
			out.ok++
		case result.TokenMissing:
			out.tokenMissing++
		case result.SweepBusy:
			out.busy++
		case result.Existing.Found:
			out.existing++
		}
	}
	require.Zero(t, out.failed, "acceptances that failed: %v", errs)
	return out
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

// mustAccept accepts command-a under the fencing token, as the step a test
// needs to succeed before its act.
//
//nolint:unparam // every call site shows the fencing token its batches and commits repeat
func mustAccept(t *testing.T, commands records.Store, k records.Keys, fencing string, lease time.Duration) {
	t.Helper()

	accepted := acceptWith(t, commands, k, "command-a", fencing, lease)
	require.True(t, accepted.OK, "Accept(command-a, %s) = %+v", fencing, accepted)
}

// waitForLease blocks until the domain lease has expired, which is what makes a
// walker dead as far as any other caller can tell.
func waitForLease(t *testing.T, commands records.Store, k records.Keys) {
	t.Helper()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		record, err := commands.Lookup(t.Context(), k)
		assert.NoError(c, err, "Lookup")
		assert.False(c, record.Alive(), "Alive() of %+v", record)
	}, 2*time.Second, 20*time.Millisecond, "the lease of the record to expire")
}

// waitForTokenToExpire blocks until the confirmation token under key has
// expired, as Get reports it.
func waitForTokenToExpire(t *testing.T, commands records.Store, key string) {
	t.Helper()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, found, err := commands.Get(t.Context(), key)
		assert.NoError(c, err, "Get(%q)", key)
		assert.False(c, found, "Get(%q) found the token", key)
	}, 2*time.Second, 20*time.Millisecond, "the confirmation token %s to expire", key)
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
