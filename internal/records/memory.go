package records

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	counters "github.com/netcracker/qubership-ratelimit/engine/store"
)

// Memory keeps records in this process, beside the in-process counters.
//
// It is the counterpart of the in-process counter store and shares its one
// limitation: with several replicas each holds its own records, so a retry that
// lands elsewhere executes again. That is why the in-process counter store is a
// single-replica and test configuration, for the same reason limits themselves
// need a shared store. At one replica it satisfies the same contract the shared
// store does, this package's atomicity included: one mutex stands in for the
// one script.
type Memory struct {
	// Now is the clock, injectable for tests; nil means time.Now.
	Now func() time.Time

	// counters is where the sweep's deletions land. The record store owns them
	// during a batch because the batch has to be one step: verify, delete,
	// advance.
	counters counters.Store

	mu        sync.Mutex
	records   map[string]*entry
	leases    map[string]lease
	documents map[string]document
}

type entry struct {
	command  string
	fencing  string
	terminal bool
	progress Progress
	outcome  Outcome

	expiresAt time.Time
}

type lease struct {
	value     string
	expiresAt time.Time
}

type document struct {
	value     []byte
	expiresAt time.Time
}

// NewMemory returns an empty in-process command store over the given counters.
func NewMemory(store counters.Store) *Memory {
	return &Memory{
		counters:  store,
		records:   map[string]*entry{},
		leases:    map[string]lease{},
		documents: map[string]document{},
	}
}

var _ Store = (*Memory)(nil)

// Lookup reads a binding and the domain lease.
func (m *Memory) Lookup(_ context.Context, keys Keys) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.read(keys), nil
}

// Accept binds the command, consumes its token, and claims the domain lease.
func (m *Memory) Accept(_ context.Context, acceptance Acceptance) (Accepted, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if existing := m.record(acceptance.Keys.Record); existing != nil {
		return Accepted{Existing: m.read(acceptance.Keys)}, nil
	}

	// The lease is checked before the token is consumed: a command refused for a
	// sweep already in flight must not spend the look that authorized it.
	if held, ok := m.lease(acceptance.Keys.Lease); ok {
		return Accepted{SweepBusy: true, LeaseTTL: held.expiresAt.Sub(now)}, nil
	}

	var token []byte
	if acceptance.Keys.Token != "" {
		held, ok := m.document(acceptance.Keys.Token)
		if !ok {
			return Accepted{TokenMissing: true}, nil
		}
		// Single use: the token is gone whether or not the sweep succeeds.
		delete(m.documents, acceptance.Keys.Token)
		token = held.value
	}

	m.records[acceptance.Keys.Record] = &entry{
		command:   acceptance.Command,
		fencing:   acceptance.Fencing,
		expiresAt: now.Add(Retention),
	}
	m.leases[acceptance.Keys.Lease] = lease{
		value:     acceptance.Fencing,
		expiresAt: now.Add(acceptance.LeaseTTL),
	}
	return Accepted{OK: true, Token: token}, nil
}

// Batch verifies the fencing token, deletes, and advances the progress.
func (m *Memory) Batch(ctx context.Context, batch Batch) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.owns(batch.Keys.Lease, batch.Fencing) {
		return ErrLeaseLost
	}
	record := m.record(batch.Keys.Record)
	if record == nil {
		return ErrLeaseLost
	}
	if len(batch.Delete) > 0 {
		if err := m.counters.Reset(ctx, batch.Delete); err != nil {
			return err
		}
	}
	record.progress = clone(batch.Progress)
	return nil
}

// Commit records the terminal outcome and releases the lease.
func (m *Memory) Commit(_ context.Context, commit Commit) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.owns(commit.Keys.Lease, commit.Fencing) {
		return ErrLeaseLost
	}
	record := m.record(commit.Keys.Record)
	if record == nil {
		return ErrLeaseLost
	}

	record.terminal = true
	record.outcome = cloneOutcome(commit.Outcome)
	record.progress = clone(commit.Outcome.Progress)
	// Retention runs from the outcome.
	record.expiresAt = m.now().Add(Retention)
	delete(m.leases, commit.Keys.Lease)
	return nil
}

// Finalize records the outcome of a dead sweep, if none is recorded yet.
func (m *Memory) Finalize(_ context.Context, finalize Finalize) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	record := m.record(finalize.Keys.Record)
	if record == nil {
		return Record{}, nil
	}
	if record.terminal {
		return m.read(finalize.Keys), nil
	}
	if _, held := m.lease(finalize.Keys.Lease); held {
		// A live owner beat the finalizer to it; the caller polls instead.
		return m.read(finalize.Keys), nil
	}

	outcome := cloneOutcome(finalize.Outcome)
	outcome.Progress = clone(record.progress)
	record.terminal = true
	record.outcome = outcome
	record.expiresAt = m.now().Add(Retention)
	return m.read(finalize.Keys), nil
}

// Reset runs the addressed reset: bind, delete, record, as one step.
func (m *Memory) Reset(ctx context.Context, addressed Addressed) (AddressedOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing := m.record(addressed.Record); existing != nil {
		return AddressedOutcome{
			Replayed: true, Command: existing.command, Count: existing.progress.Reset,
		}, nil
	}

	live, err := m.live(ctx, addressed.Delete)
	if err != nil {
		return AddressedOutcome{}, err
	}
	if !addressed.DryRun && len(live) > 0 {
		if err := m.counters.Reset(ctx, live); err != nil {
			return AddressedOutcome{}, err
		}
	}

	m.records[addressed.Record] = &entry{
		command:   addressed.Command,
		terminal:  true,
		progress:  Progress{Reset: len(live)},
		expiresAt: m.now().Add(Retention),
	}
	return AddressedOutcome{Command: addressed.Command, Count: len(live)}, nil
}

// live reports which of the keys exist right now, so a reset can say what it
// actually dropped rather than what it addressed.
func (m *Memory) live(ctx context.Context, keys []string) ([]string, error) {
	inspector, ok := m.counters.(counters.Inspector)
	if !ok {
		// Without enumeration the count would have to be guessed. Deleting the
		// computed keys is still correct, since absent keys are a no-op.
		return keys, nil
	}

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		// A bucket key is the prefix of its own subtree, so this addresses
		// exactly one counter.
		found, err := inspector.Keys(ctx, k)
		if err != nil {
			return nil, err
		}
		if slices.Contains(found, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// Put stores a confirmation token under a TTL.
func (m *Memory) Put(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.documents[key] = document{value: value, expiresAt: m.now().Add(ttl)}
	return nil
}

// Get reads a confirmation token.
func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	held, ok := m.document(key)
	if !ok {
		return nil, false, nil
	}
	return held.value, true, nil
}

// read renders the record and the lease the caller needs to judge it.
func (m *Memory) read(keys Keys) Record {
	record := m.record(keys.Record)
	if record == nil {
		return Record{}
	}

	out := Record{
		Found:    true,
		Command:  record.command,
		Terminal: record.terminal,
		Outcome:  cloneOutcome(record.outcome),
		Progress: clone(record.progress),
		Fencing:  record.fencing,
	}
	if held, ok := m.lease(keys.Lease); ok {
		out.LeaseHolder = held.value
		out.LeaseTTL = held.expiresAt.Sub(m.now())
	}
	return out
}

// record returns the entry, treating an expired one as absent.
func (m *Memory) record(key string) *entry {
	held, ok := m.records[key]
	if !ok {
		return nil
	}
	if !m.now().Before(held.expiresAt) {
		delete(m.records, key)
		return nil
	}
	return held
}

func (m *Memory) lease(key string) (lease, bool) {
	held, ok := m.leases[key]
	if !ok || !m.now().Before(held.expiresAt) {
		return lease{}, false
	}
	return held, true
}

func (m *Memory) document(key string) (document, bool) {
	held, ok := m.documents[key]
	if !ok || !m.now().Before(held.expiresAt) {
		return document{}, false
	}
	return held, true
}

func (m *Memory) owns(key, fencing string) bool {
	held, ok := m.lease(key)
	return ok && held.value == fencing
}

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// clone copies progress so a caller cannot change what the store recorded.
func clone(progress Progress) Progress {
	out := progress
	out.Rules = maps.Clone(progress.Rules)
	out.Keys = slices.Clone(progress.Keys)
	return out
}

func cloneOutcome(outcome Outcome) Outcome {
	out := outcome
	out.Progress = clone(outcome.Progress)
	return out
}
