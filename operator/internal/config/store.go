// Package config writes the configuration of the namespace: one ConfigMap,
// ratelimit-config, that the operator owns and the service mounts.
//
// It replaces the per-domain ratelimit-state ConfigMaps of the one-binary
// packaging. The object is the whole channel between the two halves of the
// split and the last-good state of the namespace at once: under binaryData
// one <domain>.json.gz per domain, the validated spec in the resource's own
// format, and under data the manifest that indexes them. The operator writes
// the whole object on every reconcile, creates it with an ownerReference to
// its own Deployment so it goes with the operator and never with a policy,
// writes it even when the namespace holds no policy, and recreates it when
// it is deleted. No chart renders it.
package config

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// Store reads and writes the namespace's ConfigMap.
//
// It satisfies the status reconciler's StateReader, so the status is judged
// against what the service mounts and nothing else: the same object is the
// last-good state the compile falls back to and the configuration the
// replicas apply.
type Store struct {
	client    client.Client
	namespace string
	labels    map[string]string
	log       logr.Logger

	// owner is the operator's own Deployment, which the ConfigMap references
	// so that garbage collection removes it with the operator. Nil when the
	// operator cannot find itself, in which case the object is written
	// without an owner rather than not at all.
	owner *metav1.OwnerReference

	// version is what the manifest records as operatorVersion. Informational.
	version string
}

// New returns a Store over the namespace. The client has to be an uncached
// one: the object is read once per reconcile and written once, and an
// informer over every ConfigMap of the namespace would be the wrong price.
func New(uncached client.Client, namespace string, labels map[string]string, version string, log logr.Logger) *Store {
	return &Store{client: uncached, namespace: namespace, labels: labels, version: version, log: log}
}

// SetOwner names the Deployment the ConfigMap belongs to.
func (s *Store) SetOwner(deployment metav1.Object, apiVersion, kind string) {
	s.owner = &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       deployment.GetName(),
		UID:        deployment.GetUID(),
	}
}

// Load reads the last-good state of the given domains out of the ConfigMap.
// A domain without a payload yields no entry, which is the cold-start case.
// An absent ConfigMap yields nothing, which is the same case for every
// domain: the first reconcile of a fresh namespace.
//
// A payload that does not decode, or whose hash disagrees with the manifest,
// is skipped rather than fatal, and logged: the object is a cache of what
// compiled, and refusing to start over one corrupt entry would turn a
// recoverable state into an outage for every other domain.
func (s *Store) Load(ctx context.Context, domains []string) (map[string]policy.Bundle, error) {
	var object corev1.ConfigMap
	if err := s.client.Get(ctx, s.key(), &object); err != nil {
		if apierrors.IsNotFound(err) {
			return map[string]policy.Bundle{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", contract.ConfigMapName, err)
	}

	m, err := manifest.Decode([]byte(object.Data[contract.ManifestKey]))
	if err != nil {
		// The operator wrote this, or a newer operator did during a rollback.
		// Either way nothing here can read it, and the next write replaces
		// it: starting from no last-good is the honest state.
		s.log.Error(err, "the manifest of "+contract.ConfigMapName+" does not decode; starting without last-good specs")
		return map[string]policy.Bundle{}, nil
	}

	bundles := make(map[string]policy.Bundle, len(domains))
	for _, domain := range domains {
		entry, ok := m.Domains[domain]
		if !ok {
			continue
		}
		raw, ok := object.BinaryData[manifest.PayloadKey(domain)]
		if !ok {
			s.log.Error(nil, "the manifest names a domain without a payload", "domain", domain)
			continue
		}
		var spec v1alpha1.RateLimitPolicySpec
		hash, err := manifest.DecodePayload(raw, &spec)
		if err != nil {
			s.log.Error(err, "skipping an unreadable payload", "domain", domain)
			continue
		}
		if hash != entry.Hash {
			s.log.Error(nil, "skipping a payload whose hash disagrees with the manifest", "domain", domain)
			continue
		}
		bundles[domain] = policy.Bundle{UID: entry.UID, GoodGeneration: entry.Generation, GoodSpec: spec}
	}
	return bundles, nil
}

// Save writes the whole object from the state: every domain with a bundle
// gets its payload and its manifest entry, a domain without one gets neither,
// and the manifest is written even when there is nothing to index. It creates
// the object when it is missing and replaces it whole when it exists.
func (s *Store) Save(ctx context.Context, state map[string]policy.Bundle, limit int) error {
	data, binaryData, err := s.render(state, limit)
	if err != nil {
		return err
	}

	var existing corev1.ConfigMap
	err = s.client.Get(ctx, s.key(), &existing)
	switch {
	case apierrors.IsNotFound(err):
		object := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: s.namespace,
				Name:      contract.ConfigMapName,
				Labels:    s.labels,
			},
			Data:       data,
			BinaryData: binaryData,
		}
		if s.owner != nil {
			object.OwnerReferences = []metav1.OwnerReference{*s.owner}
		}
		if err := s.client.Create(ctx, object); err != nil {
			return fmt.Errorf("create %s: %w", contract.ConfigMapName, err)
		}
		s.log.Info("configuration written", "domains", len(binaryData), "created", true)
		return nil
	case err != nil:
		return fmt.Errorf("read %s: %w", contract.ConfigMapName, err)
	}

	// Replaced whole, not merged: a domain that retired has its payload
	// dropped by this write, and a key nobody wrote is not one the service
	// should find.
	existing.Labels = s.labels
	if s.owner != nil {
		existing.OwnerReferences = []metav1.OwnerReference{*s.owner}
	}
	existing.Data = data
	existing.BinaryData = binaryData
	if err := s.client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("update %s: %w", contract.ConfigMapName, err)
	}
	s.log.V(1).Info("configuration written", "domains", len(binaryData))
	return nil
}

// ErrTooLarge marks a state the ConfigMap cannot hold even after the fit:
// what was persisted before was already at the limit. The fit sets back
// only what moved, so this is the state of a namespace that filled up under
// a previous operator, and the write is refused rather than attempted.
var ErrTooLarge = errors.New(contract.ConfigMapName + " would exceed the ConfigMap limit")

// render turns the state into the two halves of the object.
func (s *Store) render(state map[string]policy.Bundle, limit int) (map[string]string, map[string][]byte, error) {
	m := manifest.Manifest{OperatorVersion: s.version, Domains: map[string]manifest.Domain{}}
	binaryData := map[string][]byte{}
	total := 0
	domains := make([]string, 0, len(state))
	for domain := range state {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		bundle := state[domain]
		if bundle.UID == "" {
			continue
		}
		compressed, hash, err := manifest.EncodePayload(bundle.GoodSpec)
		if err != nil {
			return nil, nil, fmt.Errorf("encode the payload of %s: %w", domain, err)
		}
		binaryData[manifest.PayloadKey(domain)] = compressed
		total += len(compressed)
		m.Domains[domain] = manifest.Domain{Generation: bundle.GoodGeneration, UID: bundle.UID, Hash: hash}
	}
	encoded, err := manifest.Encode(m)
	if err != nil {
		return nil, nil, err
	}
	if total+len(encoded) > limit {
		return nil, nil, fmt.Errorf("%w: %d bytes compressed, the limit is %d",
			ErrTooLarge, total+len(encoded), limit)
	}
	return map[string]string{contract.ManifestKey: string(encoded)}, binaryData, nil
}

func (s *Store) key() client.ObjectKey {
	return client.ObjectKey{Namespace: s.namespace, Name: contract.ConfigMapName}
}
