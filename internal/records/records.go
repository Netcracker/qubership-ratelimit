// Package records keeps what a mutation of this service must survive a retry:
// the record of an accepted command, the confirmation token that let it start,
// and the domain lease that keeps two sweeps from running at once.
//
// A reset is not repeatable by nature. Under live traffic a second run deletes
// counters that did not exist during the first, so a retried call must answer
// the first call's outcome instead of running again. That makes the record part
// of the command's correctness, not a cache, which is why it lives in the
// counter store beside the counters themselves. The two share a fate on
// purpose: losing the store empties both, and a re-executed reset over an
// emptied store deletes nothing that mattered.
//
// Partial loss is engineered away rather than assumed away. The store runs
// without eviction, so memory pressure fails a write (which fails closed)
// instead of dropping a key; acceptance is one atomic write in one slot, so the
// token, the record, and the lease cannot go missing separately; and each batch
// of a sweep verifies its fencing token, deletes, and advances the recorded
// progress in one step, so what a command did is never unknown.
package records

import (
	"context"
	"errors"
	"time"
)

// Retention is how long a record answers a retry. It is set at acceptance and
// refreshed by the outcome, so a record that never got one still expires, from
// acceptance.
const Retention = 24 * time.Hour

// ErrLeaseLost reports a write refused because the caller no longer holds the
// domain's sweep lease. A walker that lost its lease deletes nothing further:
// the check and the deletions are one step, so there is no gap for an expired
// lease to fall into.
var ErrLeaseLost = errors.New("records: the sweep lease is no longer held")

// Keys names the storage keys one command touches. They share the domain's hash
// tag, so a cluster keeps them in one slot and a single script may touch all
// three together with the counters they describe.
type Keys struct {
	// Record holds the command's binding, progress, and outcome.
	Record string

	// Lease is the domain's sweep slot. Its value is the fencing token of the
	// command holding it.
	Lease string

	// Token is the confirmation token an execution consumes; empty for a
	// command that needs none.
	Token string
}

// Progress is what a sweep has done so far. It is committed by the same script
// that deletes the batch it counts, so a failed command can disclose it exactly
// up to the last batch that ran.
type Progress struct {
	Scanned int `json:"scanned"`
	Matched int `json:"matched"`
	Reset   int `json:"reset"`

	// Rules is the per-rule breakdown, complete over what was walked.
	Rules map[string]int `json:"rules,omitempty"`

	// Keys is a bounded sample of the keys the walk touched; Truncated says the
	// walk touched more than the sample carries.
	Keys      []string `json:"keys,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Outcome is a command's terminal result: the body a retry replays, or the
// failure it replays instead.
type Outcome struct {
	// Failed marks a recorded failure. Code, ErrorID, and Message reproduce it
	// exactly, because a replay is the same error instance, not a new one.
	Failed  bool   `json:"failed,omitempty"`
	Code    string `json:"code,omitempty"`
	ErrorID string `json:"errorId,omitempty"`
	Message string `json:"message,omitempty"`

	// Progress is what the command did, successful or not.
	Progress Progress `json:"progress"`

	// Token and TokenExpiresAt carry a preview's confirmation token, so a
	// retried preview answers the original token rather than minting a second.
	Token          string    `json:"token,omitempty"`
	TokenExpiresAt time.Time `json:"tokenExpiresAt,omitempty"`
}

// Record is one Idempotency-Key's binding and everything a retry needs to
// answer without running the command again.
type Record struct {
	// Found is false when no record exists: the command has not been accepted,
	// or its retention has passed and the request is evaluated afresh.
	Found bool

	// Command is the canonical command hash the key is bound to. The same key
	// with a different command is a conflict, never a replay.
	Command string

	// Terminal marks a recorded outcome. Until then the record is accepted and
	// the sweep may still be running.
	Terminal bool
	Outcome  Outcome

	// Progress is what the sweep had committed when the record was read, which
	// is what a finalizing retry discloses.
	Progress Progress

	// Fencing is the token of the sweep that owns this command.
	Fencing string

	// LeaseHolder is the domain lease's current value, empty when no sweep
	// holds it, and LeaseTTL how long it still lives. A record whose Fencing
	// equals LeaseHolder has a live owner; one without has a dead one, and the
	// first retry finalizes it.
	LeaseHolder string
	LeaseTTL    time.Duration
}

// Alive reports whether the sweep that owns this record is still running.
func (r Record) Alive() bool {
	return !r.Terminal && r.Fencing != "" && r.Fencing == r.LeaseHolder
}

// Acceptance is the point of no return of a bulk command, as one write:
// consuming the confirmation token, binding the key, creating the record, and
// claiming the domain's sweep lease.
//
// They are one step because splitting them leaves a state nobody can recover
// from: a bound key without a lease loses the sweep, a consumed token without a
// bound key lets the same command run twice, and a claimed lease without a
// record blocks the domain forever.
type Acceptance struct {
	Keys    Keys
	Command string

	// Fencing is the token this command will stamp on every write it makes. It
	// becomes the lease's value, which is what lets a batch prove ownership.
	Fencing string

	// LeaseTTL outlives the sweep deadline, so a lease expires only after the
	// walk it protects can no longer be running.
	LeaseTTL time.Duration
}

// Accepted is what an Acceptance did.
type Accepted struct {
	// OK is true when the command may run.
	OK bool

	// Existing describes the binding that stopped the acceptance, when the key
	// was already bound. A retry is answered from it.
	Existing Record

	// TokenMissing reports a confirmation token that expired or was already
	// used. A client cannot tell those apart and must not: both mean the same
	// thing, look again before deleting.
	TokenMissing bool

	// SweepBusy reports another sweep already running in this domain. Nothing
	// was bound, and LeaseTTL is how long the caller should wait.
	SweepBusy bool
	LeaseTTL  time.Duration

	// Token is the consumed token's document, carrying what it was bound to.
	Token []byte
}

// Batch is one step of a sweep: the deletions and the progress they produced,
// under the fencing token that proves the walker still owns the domain.
type Batch struct {
	Keys    Keys
	Fencing string

	// Delete is empty for a preview, which counts without deleting.
	Delete []string

	Progress Progress
}

// Commit writes a command's terminal outcome and releases the lease. It applies
// only under the writer's own live fencing token: a walker that lost the domain
// does not get to say how the command ended.
type Commit struct {
	Keys    Keys
	Fencing string
	Outcome Outcome
}

// Finalize records the outcome of a command whose walker died, as a
// compare-and-set against the still-empty outcome. The first retry to find an
// accepted record with an expired lease performs it; later ones replay what it
// wrote.
type Finalize struct {
	Keys    Keys
	Outcome Outcome
}

// Addressed is the whole addressed reset: bind the key, delete the computed
// keys, record the outcome. One script, so the form has no intermediate states
// to recover from.
type Addressed struct {
	Record  string
	Command string

	// Delete are the computed keys. A preview counts which of them exist and
	// deletes nothing.
	Delete []string
	DryRun bool
}

// AddressedOutcome is what an addressed reset did, or what it did the first
// time when this call was a retry.
type AddressedOutcome struct {
	// Replayed marks a retry answered from the record.
	Replayed bool

	// Command is the canonical command the key is bound to, which a retry must
	// match.
	Command string

	// Count is the number of keys deleted, or matched on a preview.
	Count int
}

// Store keeps the records, tokens, and leases of the mutating endpoints.
type Store interface {
	// Lookup reads a binding and the domain lease in one step, without creating
	// anything. A bulk command consults it before validating its confirmation
	// token, so a retry of a finished execution answers what it did rather than
	// a refusal for the token it consumed itself.
	Lookup(ctx context.Context, keys Keys) (Record, error)

	// Accept performs the atomic acceptance of a bulk command.
	Accept(ctx context.Context, acceptance Acceptance) (Accepted, error)

	// Batch verifies the fencing token, deletes the batch, and advances the
	// recorded progress. It reports ErrLeaseLost when the token no longer holds
	// the domain, and then nothing was deleted.
	Batch(ctx context.Context, batch Batch) error

	// Commit records the terminal outcome and releases the lease.
	Commit(ctx context.Context, commit Commit) error

	// Finalize records the outcome of a dead sweep if, and only if, none is
	// recorded yet and no lease is held. It returns the record as it stands
	// afterwards, so a caller that lost the race replays the winner's outcome.
	Finalize(ctx context.Context, finalize Finalize) (Record, error)

	// Reset runs the addressed reset as one atomic step.
	Reset(ctx context.Context, addressed Addressed) (AddressedOutcome, error)

	// Put stores a confirmation token under a TTL.
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Get reads a confirmation token. The absent case is reported as
	// found=false, never as an error: an error means the store did not answer,
	// which callers fail closed on instead of reading as "no such token".
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
}
