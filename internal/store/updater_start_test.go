package store

import (
	"context"
	"errors"
	"maps"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// stubInformer records the handler the updater registers so a test can deliver
// events to it. The embedded interface supplies the methods the updater never
// calls; touching one of them panics, which is the intent.
type stubInformer struct {
	cache.Informer

	mu       sync.Mutex
	handler  toolscache.ResourceEventHandler
	removed  bool
	addError error
}

type stubRegistration struct{}

func (stubRegistration) HasSynced() bool { return true }

func (stubRegistration) HasSyncedChecker() toolscache.DoneChecker { return doneChecker{} }

// doneChecker reports the stub registration as synced from the moment it exists.
type doneChecker struct{}

func (doneChecker) Name() string { return "stub registration" }

func (doneChecker) Done() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (s *stubInformer) AddEventHandler(
	handler toolscache.ResourceEventHandler,
) (toolscache.ResourceEventHandlerRegistration, error) {
	if s.addError != nil {
		return nil, s.addError
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
	return stubRegistration{}, nil
}

func (s *stubInformer) RemoveEventHandler(toolscache.ResourceEventHandlerRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed = true
	return nil
}

func (s *stubInformer) deliverAdd(t *testing.T, obj any) {
	t.Helper()
	s.mu.Lock()
	handler := s.handler
	s.mu.Unlock()
	require.NotNil(t, handler, "no event handler is registered")
	handler.OnAdd(obj, false)
}

func (s *stubInformer) deliverDelete(t *testing.T, obj any) {
	t.Helper()
	s.mu.Lock()
	handler := s.handler
	s.mu.Unlock()
	require.NotNil(t, handler, "no event handler is registered")
	handler.OnDelete(obj)
}

func (s *stubInformer) handlerRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handler != nil
}

func (s *stubInformer) handlerRemoved() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removed
}

// stubSource is an InformerSource backed by a fake client. Both watched kinds
// resolve to the same informer, which is enough here: the updater treats an event
// from either as "rebuild the whole namespace".
type stubSource struct {
	client.Reader
	informer *stubInformer
	getError error
}

func (s *stubSource) GetInformer(
	context.Context, client.Object, ...cache.InformerGetOption,
) (cache.Informer, error) {
	if s.getError != nil {
		return nil, s.getError
	}
	return s.informer, nil
}

func newStubSource(t *testing.T, objects ...client.Object) *stubSource {
	t.Helper()
	return &stubSource{
		Reader:   fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build(),
		informer: &stubInformer{},
	}
}

func startUpdater(t *testing.T, source *stubSource, ruleStore *Store) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	updater := &Updater{
		Cache:    source,
		Store:    ruleStore,
		Debounce: 10 * time.Millisecond,
		Log:      logr.Discard(),
		Counters: memory.New(),
	}
	done := make(chan error, 1)
	go func() { done <- updater.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("the updater did not stop after its context was cancelled")
		}
	})
	return cancel
}

func TestUpdaterStart_fillsTheStoreBeforeAnyEvent(t *testing.T) {
	// The manager syncs the cache before it starts this runnable, so the first
	// rebuild must already see every existing policy — a replica that waited for
	// an event would answer checks from an empty store until one arrived.
	source := newStubSource(t, policyObject("public", "gateway.public"))
	ruleStore := New()

	startUpdater(t, source, ruleStore)

	require.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.public") },
		2*time.Second, 5*time.Millisecond)
	assert.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_rebuildsOnAnEvent(t *testing.T) {
	source := newStubSource(t)
	ruleStore := New()
	startUpdater(t, source, ruleStore)
	require.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)
	require.False(t, ruleStore.Load().Has("gateway.private"))

	added := policyObject("private", "gateway.private")
	require.NoError(t, source.Reader.(client.Client).Create(context.Background(), added))
	source.informer.deliverAdd(t, added)

	assert.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.private") },
		2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_dropsADeletedPolicy(t *testing.T) {
	removed := policyObject("private", "gateway.private")
	source := newStubSource(t, removed)
	ruleStore := New()
	startUpdater(t, source, ruleStore)
	require.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.private") },
		2*time.Second, 5*time.Millisecond)

	require.NoError(t, source.Reader.(client.Client).Delete(context.Background(), removed))
	source.informer.deliverDelete(t, removed)

	assert.Eventually(t, func() bool { return !ruleStore.Load().Has("gateway.private") },
		2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_removesItsHandlerOnShutdown(t *testing.T) {
	source := newStubSource(t)
	cancel := startUpdater(t, source, New())
	require.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)

	cancel()

	assert.Eventually(t, source.informer.handlerRemoved, 2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_reportsAMissingInformer(t *testing.T) {
	updater := &Updater{
		Cache:    &stubSource{getError: errors.New("no informer")},
		Store:    New(),
		Log:      logr.Discard(),
		Counters: memory.New(),
	}

	assert.Error(t, updater.Start(context.Background()))
}

func TestUpdaterStart_reportsAFailedHandlerRegistration(t *testing.T) {
	source := newStubSource(t)
	source.informer.addError = errors.New("cannot add handler")
	updater := &Updater{Cache: source, Store: New(), Log: logr.Discard(), Counters: memory.New()}

	assert.Error(t, updater.Start(context.Background()))
}

func TestUpdaterStart_rebuildsOnAMappingEvent(t *testing.T) {
	// A mapping decides how identity is read, so it has to trigger a rebuild too:
	// a rule that references a mapped key comes alive on the rebuild that first
	// sees the mapping.
	source := newStubSource(t)
	ruleStore := New()
	startUpdater(t, source, ruleStore)
	require.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)

	mapping := mappingObject("gateway.mapped")
	require.NoError(t, source.Reader.(client.Client).Create(context.Background(), mapping))
	source.informer.deliverAdd(t, mapping)

	// The domain becoming known is the whole assertion: a mapping alone claims a
	// domain, and the keys it declares are the engine's business, not the store's.
	assert.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.mapped") },
		2*time.Second, 5*time.Millisecond)
}

// stubState records what the updater persisted, so a test can assert on the
// write-ahead order and on the leader gate.
type stubState struct {
	mu           sync.Mutex
	loaded       []string
	saved        map[string]policy.Bundle
	deleted      []string
	failing      bool
	saveFailures int
	attempts     int
}

func newStubState() *stubState {
	return &stubState{saved: map[string]policy.Bundle{}}
}

func (s *stubState) Load(_ context.Context, domains []string) (map[string]policy.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = append(s.loaded, domains...)
	if s.failing {
		return nil, errors.New("cannot read the state")
	}
	out := make(map[string]policy.Bundle, len(s.saved))
	maps.Copy(out, s.saved)
	return out, nil
}

func (s *stubState) Save(_ context.Context, domain string, bundle policy.Bundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.failing {
		return errors.New("cannot write the state")
	}
	if s.saveFailures > 0 {
		s.saveFailures--
		return errors.New("the write did not land")
	}
	s.saved[domain] = bundle
	return nil
}

func (s *stubState) ListDomains(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.saved))
	for domain := range s.saved {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out, nil
}

func (s *stubState) Delete(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, domain)
	delete(s.saved, domain)
	return nil
}

func (s *stubState) attempted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func (s *stubState) savedDomains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	domains := make([]string, 0, len(s.saved))
	for domain := range s.saved {
		domains = append(domains, domain)
	}
	return domains
}

func (s *stubState) deletedDomains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deleted...)
}

func startUpdaterWithState(
	t *testing.T,
	source *stubSource,
	ruleStore *Store,
	state StateStore,
	elected <-chan struct{},
) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	updater := &Updater{
		Cache:    source,
		Store:    ruleStore,
		Debounce: 10 * time.Millisecond,
		Log:      logr.Discard(),
		Counters: memory.New(),
		State:    state,
		Elected:  elected,
	}
	done := make(chan error, 1)
	go func() { done <- updater.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("the updater did not stop after its context was cancelled")
		}
	})
}

func closedChannel() <-chan struct{} {
	elected := make(chan struct{})
	close(elected)
	return elected
}

func TestUpdaterStart_theLeaderPersistsTheStateOfEachDomain(t *testing.T) {
	// A restart has to find out which generation is being enforced, and etcd only
	// holds the latest one.
	source := newStubSource(t, policyObject("public", "gateway.public"))
	state := newStubState()

	startUpdaterWithState(t, source, New(), state, closedChannel())

	assert.Eventually(t, func() bool {
		return len(state.savedDomains()) == 1 && state.savedDomains()[0] == "gateway.public"
	}, 2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_aNonLeaderReadsTheStateButNeverWritesIt(t *testing.T) {
	// Several writers would fight over one ConfigMap for no gain: every replica
	// computes the same bundles.
	source := newStubSource(t, policyObject("public", "gateway.public"))
	state := newStubState()

	// A channel that is never closed is a replica that never wins the lease.
	startUpdaterWithState(t, source, New(), state, make(chan struct{}))

	require.Eventually(t, func() bool { return len(state.loaded) > 0 },
		2*time.Second, 5*time.Millisecond)
	assert.Empty(t, state.savedDomains())
}

func TestUpdaterStart_dropsTheStateOfARetiredDomain(t *testing.T) {
	removed := policyObject("private", "gateway.private")
	source := newStubSource(t, removed)
	state := newStubState()
	startUpdaterWithState(t, source, New(), state, closedChannel())
	require.Eventually(t, func() bool { return len(state.savedDomains()) == 1 },
		2*time.Second, 5*time.Millisecond)

	require.NoError(t, source.Reader.(client.Client).Delete(context.Background(), removed))
	source.informer.deliverDelete(t, removed)

	assert.Eventually(t, func() bool {
		return len(state.deletedDomains()) == 1 && state.deletedDomains()[0] == "gateway.private"
	}, 2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_servesRulesEvenWhenTheStateIsUnreadable(t *testing.T) {
	// Refusing to serve over an unreadable cache would turn a recoverable state
	// into an outage: the rules themselves come from the objects.
	source := newStubSource(t, policyObject("public", "gateway.public"))
	state := newStubState()
	state.failing = true
	ruleStore := New()

	startUpdaterWithState(t, source, ruleStore, state, closedChannel())

	assert.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.public") },
		2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_persistsOnceLeadershipIsAcquired(t *testing.T) {
	// This runnable is not leader-gated, so it starts before the lease is
	// acquired and its first rebuild writes nothing. Becoming leader has to be a
	// trigger of its own, or the state of a namespace that then goes quiet would
	// never be written at all.
	source := newStubSource(t, policyObject("public", "gateway.public"))
	state := newStubState()
	elected := make(chan struct{})
	ruleStore := New()

	startUpdaterWithState(t, source, ruleStore, state, elected)
	require.Eventually(t, func() bool { return ruleStore.Load().Has("gateway.public") },
		2*time.Second, 5*time.Millisecond)
	require.Empty(t, state.savedDomains(), "a replica without the lease must not write")

	close(elected)

	assert.Eventually(t, func() bool { return len(state.savedDomains()) == 1 },
		2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_retriesAWriteThatFailed(t *testing.T) {
	// The bundle the store holds is not the bundle that was computed. Treating a
	// failed write as done would leave the state unwritten until something else
	// happened to change it.
	added := policyObject("private", "gateway.private")
	source := newStubSource(t)
	state := newStubState()
	state.saveFailures = 1
	startUpdaterWithState(t, source, New(), state, closedChannel())
	require.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, source.Reader.(client.Client).Create(context.Background(), added))
	source.informer.deliverAdd(t, added)
	require.Eventually(t, func() bool { return state.attempted() > 0 },
		2*time.Second, 5*time.Millisecond)
	require.Empty(t, state.savedDomains(), "the first write failed")

	// Any later rebuild has to try again, even though nothing changed meanwhile.
	source.informer.deliverAdd(t, added)

	assert.Eventually(t, func() bool { return len(state.savedDomains()) == 1 },
		2*time.Second, 5*time.Millisecond)
}
