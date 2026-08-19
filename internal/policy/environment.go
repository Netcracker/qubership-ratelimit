package policy

import (
	"maps"
	"strings"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// environment is what a domain offers a policy: the keys it produces and the
// groups it shares.
//
// It is built from one mapping spec rather than from the mapping object, because
// the gate has to evaluate the same policies against two of them — the spec that
// is running and the spec being proposed.
type environment struct {
	keys   map[string]KeyKind
	shared map[string]map[string]struct{}

	// declared reports whether a mapping spec was given at all. It separates
	// "the domain has no mapping" from "the mapping does not declare this key",
	// which are different things to tell a rule author.
	declared bool
}

// newEnvironment builds the environment of a mapping spec. A nil spec is the
// domain running on its built-in keys, which is a normal state rather than a
// degraded one: the built-in client key works on its own.
func newEnvironment(spec *v1alpha1.RateLimitMappingSpec) *environment {
	// The built-in client key is what makes a policy over identity work with no
	// mapping present at all.
	env := &environment{
		keys: map[string]KeyKind{
			v1alpha1.KeyPath:   KeyScalar,
			v1alpha1.KeyMethod: KeyScalar,
			v1alpha1.KeyClient: KeyScalar,
		},
	}
	if spec == nil {
		return env
	}
	env.declared = true

	for i := range spec.Mappings {
		entry := &spec.Mappings[i]
		// The shape of the claim is what decides which operators apply to the key
		// and whether it can serve as a counter axis. An entry named client
		// overrides the built-in one rather than joining it, so the domain has
		// exactly one definition of every key.
		kind := KeyScalar
		if entry.Type == v1alpha1.ClaimTypeStringArray {
			kind = KeyArray
		}
		env.keys[entry.Key] = kind
	}

	env.shared = compileGroups(spec.Groups)
	return env
}

// compileGroups flattens group lists into membership sets. Members are
// lower-cased, and so is the value tested against them, which is how the
// case-insensitive comparison of the source policies is preserved.
func compileGroups(groups []v1alpha1.ClientGroup) map[string]map[string]struct{} {
	if len(groups) == 0 {
		return nil
	}
	out := make(map[string]map[string]struct{}, len(groups))
	for i := range groups {
		members := make(map[string]struct{}, len(groups[i].Clients))
		for _, member := range groups[i].Clients {
			members[strings.ToLower(member)] = struct{}{}
		}
		out[groups[i].Name] = members
	}
	return out
}

// groupsFor merges the private groups of a policy over the shared ones, which is
// what lets a policy shadow a group of the domain with one of its own.
func (e *environment) groupsFor(spec *v1alpha1.RateLimitPolicySpec) map[string]map[string]struct{} {
	private := compileGroups(spec.Groups)
	if len(e.shared) == 0 {
		return private
	}
	if len(private) == 0 {
		return e.shared
	}
	merged := make(map[string]map[string]struct{}, len(e.shared)+len(private))
	maps.Copy(merged, e.shared)
	maps.Copy(merged, private)
	return merged
}
