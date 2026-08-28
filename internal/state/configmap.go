// Package state persists the last-good spec of every object of a domain.
//
// etcd holds only the latest generation, which may be the one that was rejected.
// Without a copy of what is actually running, a restart would forget it and fall
// back to "nothing" — turning a rejected edit into an outage at the next rollout
// rather than at the edit.
//
// The store is read once, at startup. In normal operation the objects are the
// source of truth and this is only the restart insurance, so it needs no informer
// and no cache.
package state

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

const (
	// namePrefix and DataKey name the ConfigMap of a domain and the entry inside
	// it.
	namePrefix = "ratelimit-state-"

	// DataKey is the binary entry holding the compressed bundle. It is binary
	// because the bundle is gzipped, and a gzip stream is not valid UTF-8.
	DataKey = "state.gz"

	// domainLabel records which domain a ConfigMap belongs to. A domain is at
	// most 63 characters of [a-z0-9.-], which is a valid label value.
	domainLabel = "ratelimit.netcracker.com/domain"
)

// Store reads and writes the last-good state of each domain.
type Store struct {
	client    client.Client
	namespace string
	labels    map[string]string
	log       logr.Logger
	recorder  events.EventRecorder
}

// New returns a Store writing into the given namespace. The client has to be an
// uncached one: caching ConfigMaps would need an informer over every ConfigMap of
// the namespace, for objects that are read once per process lifetime. The
// recorder may be nil; without it an overflow is only logged.
func New(
	uncached client.Client,
	namespace string,
	labels map[string]string,
	log logr.Logger,
	recorder events.EventRecorder,
) *Store {
	return &Store{client: uncached, namespace: namespace, labels: labels, log: log, recorder: recorder}
}

// Name is the ConfigMap holding the state of a domain.
func Name(domain string) string {
	return namePrefix + domain
}

// Load reads the state of the given domains. A domain with no ConfigMap yields no
// entry, which is the cold-start case: the latest specs are validated and there is
// nothing to fall back to.
//
// A ConfigMap that cannot be decoded is skipped rather than fatal. Its content is
// a cache, and refusing to start over a corrupt cache would turn a recoverable
// state into an outage.
func (s *Store) Load(ctx context.Context, domains []string) (map[string]policy.Bundle, error) {
	bundles := make(map[string]policy.Bundle, len(domains))
	for _, domain := range domains {
		var configMap corev1.ConfigMap
		key := client.ObjectKey{Namespace: s.namespace, Name: Name(domain)}
		if err := s.client.Get(ctx, key, &configMap); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("read state of domain %q: %w", domain, err)
		}

		raw, ok := configMap.BinaryData[DataKey]
		if !ok {
			continue
		}
		bundle, err := policy.DecodeBundle(raw)
		if err != nil {
			// One corrupt cache entry costs its own domain the fallback, not
			// the whole namespace: the other domains' state is intact and
			// there is no reason to forget it.
			s.log.Error(err, "skipping an unreadable state entry", "domain", domain)
			continue
		}
		bundles[domain] = bundle
	}
	return bundles, nil
}

// Save writes the state of one domain, creating the ConfigMap when it is missing.
//
// An oversized bundle raises a Warning event on the ConfigMap: the objects of
// the domain lose their last-good spec across a restart, and whoever
// investigates that starts at the ConfigMap that should have held it.
func (s *Store) Save(ctx context.Context, domain string, bundle policy.Bundle) error {
	encoded, err := policy.EncodeBundle(bundle)
	if err != nil {
		if errors.Is(err, policy.ErrBundleOverflow) && s.recorder != nil {
			s.recorder.Eventf(s.reference(domain), nil, corev1.EventTypeWarning,
				"PersistenceOverflow", "Save", "%s", err.Error())
		}
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.namespace,
			Name:      Name(domain),
			Labels:    s.labelsFor(domain),
		},
		BinaryData: map[string][]byte{DataKey: encoded},
	}

	if err := s.client.Create(ctx, configMap); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create state of domain %q: %w", domain, err)
	}

	var existing corev1.ConfigMap
	key := client.ObjectKey{Namespace: s.namespace, Name: Name(domain)}
	if err := s.client.Get(ctx, key, &existing); err != nil {
		return fmt.Errorf("read state of domain %q before writing it: %w", domain, err)
	}
	existing.Labels = s.labelsFor(domain)
	existing.BinaryData = map[string][]byte{DataKey: encoded}
	if err := s.client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("write state of domain %q: %w", domain, err)
	}
	return nil
}

// Delete drops the state of a domain that no longer has objects. Without it the
// ConfigMap of a retired gateway would stay forever, and a domain later recreated
// under the same name would inherit specs nobody wrote.
func (s *Store) Delete(ctx context.Context, domain string) error {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: s.namespace, Name: Name(domain)},
	}
	if err := s.client.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete state of domain %q: %w", domain, err)
	}
	return nil
}

// ListDomains names every domain with persisted state, found by the domain
// label. It is how a new leader discovers the ConfigMaps of domains retired
// while somebody else held the lease.
func (s *Store) ListDomains(ctx context.Context) ([]string, error) {
	var list corev1.ConfigMapList
	if err := s.client.List(ctx, &list,
		client.InNamespace(s.namespace), client.HasLabels{domainLabel}); err != nil {
		return nil, fmt.Errorf("list persisted domains: %w", err)
	}
	domains := make([]string, 0, len(list.Items))
	for i := range list.Items {
		domains = append(domains, list.Items[i].Labels[domainLabel])
	}
	sort.Strings(domains)
	return domains, nil
}

// reference names the ConfigMap of a domain for an event, without reading it.
func (s *Store) reference(domain string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: s.namespace, Name: Name(domain)},
	}
}

func (s *Store) labelsFor(domain string) map[string]string {
	labels := make(map[string]string, len(s.labels)+1)
	maps.Copy(labels, s.labels)
	labels[domainLabel] = domain
	return labels
}
