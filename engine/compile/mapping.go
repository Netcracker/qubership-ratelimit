package compile

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// keyName constrains declared key and capture names, mirroring the schema.
var keyName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// environment is what a policy resolves against: the domain's keys, key
// types, shared groups, and extraction plan.
type environment struct {
	// keys maps every domain-global descriptor key to whether it is
	// array-valued.
	keys map[string]bool

	sharedGroups map[string][]string

	extraction []KeyExtraction
}

func (e *environment) effectiveKeys() []string {
	out := make([]string, 0, len(e.keys))
	for k := range e.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compileMapping builds the environment. A structurally broken mapping entry
// is reported and skipped — the controller's no-regression gate keeps such a
// mapping from ever becoming active, and the engine stays defensive rather
// than trusting that.
func compileMapping(domain string, m *model.Mapping) (*environment, []Problem) {
	env := &environment{
		keys: map[string]bool{
			model.KeyPath:   false,
			model.KeyMethod: false,
			model.KeyClient: false,
		},
		sharedGroups: map[string][]string{},
	}
	builtinClient := KeyExtraction{
		Key:       model.KeyClient,
		Path:      []string{"sub"},
		Type:      model.ValueString,
		Normalize: model.NormalizeLowercase,
	}
	if m == nil {
		env.extraction = []KeyExtraction{builtinClient}
		return env, nil
	}

	var problems []Problem
	fail := func(format string, args ...any) {
		problems = append(problems, Problem{
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf(format, args...),
			Blocking: true,
		})
	}

	if m.Domain != domain {
		fail("mapping domain %q does not belong to domain %q", m.Domain, domain)
	}
	if len(m.Mappings) > model.MaxMappings {
		fail("mappings exceed the limit of %d", model.MaxMappings)
	}

	clientOverridden := false
	// declared tracks the mapping's own keys, separately from the seeded
	// built-ins: overriding the built-in client is legal, declaring any key —
	// client included — twice is not, or the winner would depend on which
	// entry finds its claim first.
	declared := map[string]struct{}{}
	for _, km := range m.Mappings {
		if _, dup := declared[km.Key]; dup {
			problems = append(problems, Problem{
				Reason:   ReasonInvalidSpec,
				Message:  fmt.Sprintf("mapping key %q is declared twice", km.Key),
				Blocking: true,
			})
			continue
		}
		declared[km.Key] = struct{}{}

		extraction, problem := compileKeyMapping(km)
		if problem != nil {
			problems = append(problems, *problem)
			continue
		}
		if km.Key == model.KeyClient {
			clientOverridden = true
		}
		env.keys[km.Key] = extraction.Type == model.ValueStringArray
		env.extraction = append(env.extraction, extraction)
	}
	if !clientOverridden {
		env.extraction = append([]KeyExtraction{builtinClient}, env.extraction...)
	}

	problems = append(problems, compileGroups(m.Groups, env.sharedGroups, "")...)
	return env, problems
}

func compileKeyMapping(km model.KeyMapping) (KeyExtraction, *Problem) {
	bad := func(format string, args ...any) (KeyExtraction, *Problem) {
		return KeyExtraction{}, &Problem{
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf(format, args...),
			Blocking: true,
		}
	}
	if !keyName.MatchString(km.Key) {
		return bad("mapping key %q does not match %s", km.Key, keyName)
	}
	if km.Key == model.KeyPath || km.Key == model.KeyMethod || km.Key == model.KeyToken {
		return bad("mapping key %q collides with a built-in", km.Key)
	}
	if (km.Claim == "") == (len(km.ClaimPath) == 0) {
		return bad("mapping key %q must set exactly one of claim and claimPath", km.Key)
	}
	if len(km.Fallbacks) > model.MaxFallbacks {
		return bad("mapping key %q carries more than %d fallbacks", km.Key, model.MaxFallbacks)
	}
	switch km.Type {
	case "", model.ValueString, model.ValueStringArray:
	default:
		return bad("mapping key %q carries an unknown type %q", km.Key, km.Type)
	}
	switch km.Normalize {
	case "", model.NormalizeNone, model.NormalizeLowercase:
	default:
		return bad("mapping key %q carries an unknown normalize %q", km.Key, km.Normalize)
	}

	// Cloned, not aliased: the extraction plan of a published snapshot must
	// not move when the caller mutates the model.
	path := slices.Clone(km.ClaimPath)
	if km.Claim != "" {
		path = strings.Split(km.Claim, ".")
	}
	if hasEmptySegment(path) {
		return bad("mapping key %q carries an empty claim path segment", km.Key)
	}
	out := KeyExtraction{
		Key:       km.Key,
		Path:      path,
		Type:      km.Type,
		Normalize: km.Normalize,
	}
	if out.Type == "" {
		out.Type = model.ValueString
	}
	if out.Normalize == "" {
		out.Normalize = model.NormalizeNone
	}
	for _, f := range km.Fallbacks {
		fallback := strings.Split(f, ".")
		if hasEmptySegment(fallback) {
			return bad("mapping key %q carries an empty fallback path segment", km.Key)
		}
		out.Fallbacks = append(out.Fallbacks, fallback)
	}
	return out, nil
}

// hasEmptySegment reports a claim path that could never resolve: an empty
// segment walks to nothing, silently, for every token.
func hasEmptySegment(path []string) bool {
	if len(path) == 0 {
		return true
	}
	return slices.Contains(path, "")
}

// compileGroups validates a group list into dst. The policy argument is empty
// for shared groups and names the owner for private ones.
func compileGroups(groups []model.Group, dst map[string][]string, policy string) []Problem {
	var problems []Problem
	fail := func(format string, args ...any) {
		problems = append(problems, Problem{
			Policy:   policy,
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf(format, args...),
			Blocking: true,
		})
	}
	if len(groups) > model.MaxGroups {
		fail("groups exceed the limit of %d", model.MaxGroups)
	}
	for _, g := range groups {
		if g.Name == "" {
			fail("a group without a name")
			continue
		}
		if _, dup := dst[g.Name]; dup {
			fail("group %q is declared twice", g.Name)
			continue
		}
		if len(g.Clients) > model.MaxClientsPerGroup {
			fail("group %q exceeds %d clients", g.Name, model.MaxClientsPerGroup)
			continue
		}
		dst[g.Name] = g.Clients
	}
	return problems
}
