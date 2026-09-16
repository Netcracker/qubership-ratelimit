package policy

import (
	"fmt"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/manifest"
)

// ConfigMapLimit is what one ConfigMap holds: the API server refuses an
// object over 1 MiB, data and binaryData together. It is the one physical
// wall the split adds, and the fit below keeps the namespace under it.
const ConfigMapLimit = 1 << 20

// Fit keeps the namespace's configuration inside limit bytes, and says which
// generations it kept out to do so.
//
// It is a second pass over a compilation rather than part of it, because the
// question is about the namespace and not about one domain: every domain's
// payload compresses on its own, and the total is what the ConfigMap
// refuses. When the total is over, the generations that moved in this
// compilation are the ones that pushed it there, and they are set back to
// their last-good bundles, largest first, until the total fits. A domain set
// back is reported TooLarge: it compiles, and the namespace is full.
//
// The pass is deterministic and stateless, on purpose. The operator runs it
// in two places that must agree without sharing memory: the writer of the
// ConfigMap decides what to write, and the status reconciler decides what to
// report. Both compile the same objects against the same persisted state and
// run this same function, so they reach the same verdict.
//
// A total that was already over the limit before this compilation moved
// anything is left as it is: nothing here can shrink what was persisted, and
// the writer's failure to write is the signal in that case.
func Fit(in Input, result *Result, limit int) {
	if limit <= 0 {
		return
	}
	total, sizes, err := sizeOf(result.State)
	if err != nil || total <= limit {
		return
	}

	// The candidates: domains whose bundle this compilation changed. A domain
	// whose bundle is what was persisted cannot be set back any further.
	var moved []string
	for domain, bundle := range result.State {
		if bundle.UID == "" {
			continue
		}
		if previous, ok := in.State[domain]; ok &&
			previous.UID == bundle.UID && previous.GoodGeneration == bundle.GoodGeneration {
			continue
		}
		moved = append(moved, domain)
	}
	// Largest first, so the fewest generations are kept out; by name after,
	// so two runs over the same input keep the same ones.
	sort.Slice(moved, func(a, b int) bool {
		if sizes[moved[a]] != sizes[moved[b]] {
			return sizes[moved[a]] > sizes[moved[b]]
		}
		return moved[a] < moved[b]
	})

	objects := map[string]int{}
	for i := range in.Policies {
		objects[in.Policies[i].Spec.Domain] = i
	}
	for _, domain := range moved {
		i, ok := objects[domain]
		if !ok {
			continue
		}
		object := &in.Policies[i]
		reason := fmt.Sprintf("the namespace's configuration would be %d bytes compressed, over the limit of %d",
			total, limit)
		outcome, snapshot, bundle := compileDomainFitting(
			in.Namespace, object, in.State[domain], in.Skew[client.ObjectKeyFromObject(object)], reason)
		result.Policies[client.ObjectKeyFromObject(object)] = outcome
		result.Snapshots[domain] = snapshot
		result.State[domain] = bundle

		total, sizes, err = sizeOf(result.State)
		if err != nil || total <= limit {
			return
		}
	}
}

// sizeOf is the size the ConfigMap would have: every payload compressed,
// plus the manifest that indexes them.
func sizeOf(state map[string]Bundle) (total int, sizes map[string]int, err error) {
	sizes = make(map[string]int, len(state))
	m := manifest.Manifest{Domains: map[string]manifest.Domain{}}
	for domain, bundle := range state {
		if bundle.UID == "" {
			continue
		}
		compressed, hash, err := manifest.EncodePayload(bundle.GoodSpec)
		if err != nil {
			return 0, nil, err
		}
		sizes[domain] = len(compressed)
		total += len(compressed)
		m.Domains[domain] = manifest.Domain{Generation: bundle.GoodGeneration, UID: bundle.UID, Hash: hash}
	}
	encoded, err := manifest.Encode(m)
	if err != nil {
		return 0, nil, err
	}
	return total + len(encoded), sizes, nil
}
