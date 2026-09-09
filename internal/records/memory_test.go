package records_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The in-process store owns one thing the shared one does not: an injectable
// clock. Retention is what that clock is for, so these two tests live here
// rather than in the suite both stores run.
func newRecords() *records.Memory { return records.NewMemory(memory.New()) }

// Retention runs from the outcome, not from acceptance, so a slow command is
// not penalized for being slow. The lease has to outlive the walk for the two to
// differ at all — a commit under a dead lease is refused, which is the point of
// the lease.
func TestRetention_startsAtTheRecordedOutcome(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	keys := freshKeys(t)

	commands := newRecords()
	commands.Now = func() time.Time { return now }
	accepted, err := commands.Accept(ctx, records.Acceptance{
		Keys: keys, Command: "command-a", Fencing: "fence-1", LeaseTTL: 2 * time.Hour,
	})
	require.NoError(t, err)
	require.True(t, accepted.OK)

	// The command runs for an hour and then records what it did.
	now = now.Add(time.Hour)
	require.NoError(t, commands.Commit(ctx, records.Commit{
		Keys: keys, Fencing: "fence-1", Outcome: records.Outcome{},
	}))

	// Past the window the acceptance would have given it, the outcome is still
	// there to replay.
	now = now.Add(records.Retention - 30*time.Minute)
	record, err := commands.Lookup(ctx, keys)
	require.NoError(t, err)
	require.True(t, record.Found)

	now = now.Add(time.Hour)
	record, err = commands.Lookup(ctx, keys)
	require.NoError(t, err)
	require.False(t, record.Found)
}

// A record that never got an outcome expires from acceptance, so an interrupted
// command does not sit in limbo forever.
func TestRetention_expiresAnInterruptedRecordFromAcceptance(t *testing.T) {
	now := time.Now()
	keys := freshKeys(t)

	commands := newRecords()
	commands.Now = func() time.Time { return now }
	require.True(t, acceptWith(t, commands, keys, "command-a", "fence-1", time.Minute).OK)

	now = now.Add(records.Retention + time.Minute)
	record, err := commands.Lookup(t.Context(), keys)
	require.NoError(t, err)
	require.False(t, record.Found)
}
