package controller

import (
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// CacheOptions is what the manager caches, and it is shared with the tests
// rather than written out at the call site.
//
// The reason is the class of mistake it prevents. Every read of a policy in
// this process has to ask for the unstructured kind, and one that asks for the
// typed kind fails only against a cache configured this way: with a plain
// client, which is what a test reaches for, both kinds read fine and the
// mistake is invisible until a real deployment stops reconciling. Building the
// test's manager from this same function is what makes that reachable.
func CacheOptions(namespace string) cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			// Unstructured, so that the objects reaching the compiler carry
			// every field they were stored with. A typed informer decodes
			// leniently and drops what this build's schema does not define,
			// which would enforce a newer object as the subset of itself this
			// build happens to understand. Registering the typed kind as well
			// would put a second informer and a second copy of every object
			// behind the same watch.
			policy.Object(): {
				Namespaces: map[string]cache.Config{namespace: {}},
			},
			// The leader reads the ready endpoints of its own Service to learn
			// which replicas enforce which generation.
			&discoveryv1.EndpointSlice{}: {
				Namespaces: map[string]cache.Config{namespace: {}},
			},
		},
		ReaderFailOnMissingInformer: true,
	}
}

// ClientOptions routes unstructured reads through the cache.
//
// The client sends them live by default, which for this process would mean a
// full list of the namespace's policies on every reconcile of every policy,
// once a minute each, for objects an informer already holds.
func ClientOptions() client.Options {
	return client.Options{
		Cache: &client.CacheOptions{Unstructured: true},
	}
}
