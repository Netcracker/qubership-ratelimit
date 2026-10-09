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
//
// limit has to be positive, as it has to be for the writer's Save, and Fit
// panics on any other: the two would read it differently, one as no limit
// and the other as nothing fitting.
func Fit(in Input, result *Result, limit int) {
	if limit <= 0 {
		panic(fmt.Sprintf("policy: Fit with a limit of %d bytes; the limit has to be positive", limit))
	}
	rendered, err := Render(result.State, in.OperatorVersion)
	if err != nil || rendered.Size <= limit {
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
		if sizeA, sizeB := len(rendered.Payloads[moved[a]]), len(rendered.Payloads[moved[b]]); sizeA != sizeB {
			return sizeA > sizeB
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
			rendered.Size, limit)
		outcome, snapshot, bundle := compileDomainFitting(
			in.Namespace, object, in.State[domain], in.Skew[client.ObjectKeyFromObject(object)], reason)
		result.Policies[client.ObjectKeyFromObject(object)] = outcome
		result.Snapshots[domain] = snapshot
		result.State[domain] = bundle

		rendered, err = Render(result.State, in.OperatorVersion)
		if err != nil || rendered.Size <= limit {
			return
		}
	}
}

// Rendered is the content of the configuration ConfigMap.
type Rendered struct {
	// Manifest is the encoded manifest, stamped with the operator version.
	Manifest []byte

	// Payloads holds the compressed payload of every domain with a bundle,
	// keyed by domain.
	Payloads map[string][]byte

	// Size is what the ConfigMap limit bounds: the manifest and every
	// payload, in bytes.
	Size int
}

// Render builds the ConfigMap's content from state. A bundle without a UID
// has nothing to enforce and is left out. The writer of the ConfigMap and
// [Fit] both measure through it, so the two agree on the size to the byte.
func Render(state map[string]Bundle, operatorVersion string) (Rendered, error) {
	m := manifest.Manifest{OperatorVersion: operatorVersion, Domains: map[string]manifest.Domain{}}
	out := Rendered{Payloads: make(map[string][]byte, len(state))}
	for domain, bundle := range state {
		if bundle.UID == "" {
			continue
		}
		compressed, hash, err := manifest.EncodePayload(bundle.GoodSpec)
		if err != nil {
			return Rendered{}, fmt.Errorf("encode the payload of %s: %w", domain, err)
		}
		out.Payloads[domain] = compressed
		out.Size += len(compressed)
		m.Domains[domain] = manifest.Domain{Generation: bundle.GoodGeneration, UID: bundle.UID, Hash: hash}
	}
	encoded, err := manifest.Encode(m)
	if err != nil {
		return Rendered{}, err
	}
	out.Manifest = encoded
	out.Size += len(encoded)
	return out, nil
}
