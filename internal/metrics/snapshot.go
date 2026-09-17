package metrics

import (
	"github.com/netcracker/qubership-ratelimit/engine/compile"
)

// ActiveSetOf lists the label values a set of snapshots can produce, for the
// series pruner: domains, rule triples, and identity keys. Whatever is not
// here belongs to a renamed or deleted object and its series are leftovers.
func ActiveSetOf(snapshots map[string]*compile.Snapshot) *ActiveSet {
	active := &ActiveSet{
		Domains: make(map[string]struct{}, len(snapshots)),
		Rules:   map[string]struct{}{},
		Keys:    map[string]struct{}{},
	}
	for domain, snapshot := range snapshots {
		active.Domains[domain] = struct{}{}
		for _, key := range snapshot.EffectiveKeys {
			active.Keys[key] = struct{}{}
		}
		for i := range snapshot.Blocks {
			block := &snapshot.Blocks[i]
			for _, rule := range block.Rules {
				active.Rules[RuleID(block.Name, rule.Name)] = struct{}{}
			}
		}
	}
	return active
}

// ExtractionKeysOf lists the keys the snapshots extract from a token: the
// built-in client plus the mapped keys of every domain. Their series are
// seeded so that "declared but never extracted" is a visible zero rather
// than a missing series. path and method are resolved from the request, not
// extracted, and stay out.
func ExtractionKeysOf(snapshots map[string]*compile.Snapshot) []string {
	seen := map[string]struct{}{}
	var keys []string
	for _, snapshot := range snapshots {
		for i := range snapshot.Extraction {
			key := snapshot.Extraction[i].Key
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	return keys
}
