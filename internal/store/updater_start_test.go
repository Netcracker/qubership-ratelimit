package store

import (
	"context"
	"errors"
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

// stubSource is an InformerSource backed by a fake client.
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
		Counters: memory.New(),
		Debounce: 10 * time.Millisecond,
		Log:      logr.Discard(),
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
	source := newStubSource(t, policy("public", "gateway.public"))
	ruleStore := New()

	startUpdater(t, source, ruleStore)

	require.Eventually(t, func() bool { return ruleStore.HasDomain("gateway.public") },
		2*time.Second, 5*time.Millisecond)
	assert.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_rebuildsOnAnEvent(t *testing.T) {
	source := newStubSource(t)
	ruleStore := New()
	startUpdater(t, source, ruleStore)
	require.Eventually(t, source.informer.handlerRegistered, 2*time.Second, 5*time.Millisecond)
	require.False(t, ruleStore.HasDomain("gateway.private"))

	added := policy("private", "gateway.private")
	require.NoError(t, source.Reader.(client.Client).Create(context.Background(), added))
	source.informer.deliverAdd(t, added)

	assert.Eventually(t, func() bool { return ruleStore.HasDomain("gateway.private") },
		2*time.Second, 5*time.Millisecond)
}

func TestUpdaterStart_dropsADeletedPolicy(t *testing.T) {
	removed := policy("private", "gateway.private")
	source := newStubSource(t, removed)
	ruleStore := New()
	startUpdater(t, source, ruleStore)
	require.Eventually(t, func() bool { return ruleStore.HasDomain("gateway.private") },
		2*time.Second, 5*time.Millisecond)

	require.NoError(t, source.Reader.(client.Client).Delete(context.Background(), removed))
	source.informer.deliverDelete(t, removed)

	assert.Eventually(t, func() bool { return !ruleStore.HasDomain("gateway.private") },
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
		Cache: &stubSource{getError: errors.New("no informer")},
		Store: New(),
		Log:   logr.Discard(),
	}

	assert.Error(t, updater.Start(context.Background()))
}

func TestUpdaterStart_reportsAFailedHandlerRegistration(t *testing.T) {
	source := newStubSource(t)
	source.informer.addError = errors.New("cannot add handler")
	updater := &Updater{Cache: source, Store: New(), Counters: memory.New(), Log: logr.Discard()}

	assert.Error(t, updater.Start(context.Background()))
}
