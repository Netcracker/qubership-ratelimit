package store

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// DefaultDebounce is how long the updater waits after the first event of a burst
// before rebuilding. The informer replays one event per existing object at
// startup, so without it a namespace with N policies would rebuild N times.
const DefaultDebounce = 200 * time.Millisecond

// InformerSource is the part of cache.Cache the updater uses: an informer to
// subscribe to, and a reader to rebuild the rule set from. The manager's cache
// satisfies it.
type InformerSource interface {
	client.Reader
	GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error)
}

// Updater keeps the Store in sync with the RateLimitPolicy objects in the cache.
//
// It runs on every replica and subscribes to the informer directly instead of
// living inside Reconcile: Reconcile only runs on the leader, so a store filled
// there would leave non-leader replicas answering checks from an empty store —
// a failure that shows up as limits that apply on some pods and not others.
type Updater struct {
	Cache    InformerSource
	Store    *Store
	Debounce time.Duration
	Log      logr.Logger
}

// NeedLeaderElection reports false: every replica serves rate limit checks, so
// every replica needs a populated store.
func (u *Updater) NeedLeaderElection() bool { return false }

// Start subscribes to RateLimitPolicy events and rebuilds the store on each
// burst. It returns when ctx is cancelled.
func (u *Updater) Start(ctx context.Context) error {
	debounce := u.Debounce
	if debounce <= 0 {
		debounce = DefaultDebounce
	}

	informer, err := u.Cache.GetInformer(ctx, &ratelimitv1alpha1.RateLimitPolicy{})
	if err != nil {
		return fmt.Errorf("get RateLimitPolicy informer: %w", err)
	}

	// Buffered by one: a pending trigger already covers any event that arrives
	// before the rebuild runs, because the rebuild always reads the full list.
	trigger := make(chan struct{}, 1)
	notify := func(any) {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	registration, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { notify(obj) },
		UpdateFunc: func(_, obj any) { notify(obj) },
		DeleteFunc: func(obj any) { notify(obj) },
	})
	if err != nil {
		return fmt.Errorf("add RateLimitPolicy event handler: %w", err)
	}
	defer func() {
		if err := informer.RemoveEventHandler(registration); err != nil {
			u.Log.Error(err, "failed to remove event handler")
		}
	}()

	// The cache is synced before this runnable starts, so the first rebuild
	// already sees every existing policy; the replayed Add events then collapse
	// into a single extra rebuild.
	u.rebuild(ctx)

	timer := time.NewTimer(debounce)
	if !timer.Stop() {
		<-timer.C
	}
	// A nil channel blocks forever, which is how "no rebuild is scheduled" is
	// expressed here. The timer is armed by the first event of a burst and not
	// re-armed by the rest, so a steady stream of events cannot starve the
	// rebuild the way a reset-on-every-event debounce would.
	var pending <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
			if pending == nil {
				timer.Reset(debounce)
				pending = timer.C
			}
		case <-pending:
			pending = nil
			u.rebuild(ctx)
		}
	}
}

func (u *Updater) rebuild(ctx context.Context) {
	ruleSet, err := BuildRuleSet(ctx, u.Cache)
	if err != nil {
		// Keep the previous snapshot: stale rules are better than none, and the
		// next event triggers another attempt.
		u.Log.Error(err, "failed to rebuild the rate limit store, keeping the previous snapshot")
		return
	}
	u.Store.Replace(ruleSet)

	u.Log.Info("rate limit store rebuilt", "domains", len(ruleSet.Domains))
}

// BuildRuleSet lists every RateLimitPolicy the reader can see and collects the
// domains they bind to.
func BuildRuleSet(ctx context.Context, reader client.Reader) (*RuleSet, error) {
	var list ratelimitv1alpha1.RateLimitPolicyList
	if err := reader.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list RateLimitPolicy: %w", err)
	}

	domains := make([]string, 0, len(list.Items))
	for i := range list.Items {
		// The CRD requires a non-empty domain, so this only skips an object
		// written by a client that bypassed validation.
		if domain := list.Items[i].Spec.Domain; domain != "" {
			domains = append(domains, domain)
		}
	}
	return NewRuleSet(domains), nil
}
