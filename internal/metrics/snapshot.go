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
		Keys:    make(map[string]map[string]struct{}, len(snapshots)),
	}
	for domain, snapshot := range snapshots {
		active.Domains[domain] = struct{}{}
		keys := make(map[string]struct{}, len(snapshot.EffectiveKeys))
		for _, key := range snapshot.EffectiveKeys {
			keys[key] = struct{}{}
		}
		active.Keys[domain] = keys
		for i := range snapshot.Blocks {
			block := &snapshot.Blocks[i]
			for _, rule := range block.Rules {
				active.Rules[RuleID(block.Name, rule.Name)] = struct{}{}
			}
		}
	}
	return active
}

// ExtractionKeysOf lists, per domain, the keys the snapshot extracts from a
// token: the built-in client plus the domain's mapped keys. Their series are
// seeded so that "declared but never extracted" is a visible zero rather
// than a missing series. path and method are resolved from the request, not
// extracted, and stay out.
func ExtractionKeysOf(snapshots map[string]*compile.Snapshot) map[string][]string {
	keys := make(map[string][]string, len(snapshots))
	for domain, snapshot := range snapshots {
		names := make([]string, 0, len(snapshot.Extraction))
		for i := range snapshot.Extraction {
			names = append(names, snapshot.Extraction[i].Key)
		}
		keys[domain] = names
	}
	return keys
}
