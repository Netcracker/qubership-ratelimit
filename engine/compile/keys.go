package compile

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// keyName constrains every descriptor key name — mapping keys, template
// placeholders, predicate keys, and counter axes — mirroring the schema. It
// admits camelCase, so {orderId} is a valid placeholder.
var keyName = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]*$`)

// environment is what the rules of a domain resolve against: its keys, their
// types, its groups, and its extraction plan.
type environment struct {
	// keys maps every domain-global descriptor key to whether it is
	// array-valued.
	keys map[string]bool

	groups map[string][]string

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

// compileEnvironment builds the key set, the groups, and the extraction plan
// of one domain. A nil policy is the built-ins-only domain.
func compileEnvironment(domain string, p *model.Policy) (*environment, []Problem) {
	env := &environment{
		keys: map[string]bool{
			model.KeyPath:   false,
			model.KeyMethod: false,
			model.KeyClient: false,
		},
		groups: map[string][]string{},
	}
	builtinClient := KeyExtraction{
		Key:           model.KeyClient,
		Path:          []string{"sub"},
		Type:          model.ValueString,
		Normalization: model.NormalizeLowercase,
	}
	if p == nil {
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

	if p.Domain != domain {
		fail("policy domain %q does not belong to domain %q", p.Domain, domain)
	}

	clientOverridden := false
	// declared tracks the policy's own keys, separately from the seeded
	// built-ins: overriding the built-in client is legal, declaring any key —
	// client included — twice is not, or the winner would depend on which
	// entry finds its claim first.
	declared := map[string]struct{}{}
	for _, km := range p.Mappings {
		if _, dup := declared[km.Key]; dup {
			fail("mapping key %q is declared twice", km.Key)
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

	problems = append(problems, compileGroups(p.Groups, env.groups)...)
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
	if !keyName.MatchString(km.Key) || len(km.Key) > 63 {
		return bad("mapping key %q does not match %s or exceeds 63 characters", km.Key, keyName)
	}
	if km.Key == model.KeyPath || km.Key == model.KeyMethod || km.Key == model.KeyToken {
		return bad("mapping key %q collides with a built-in", km.Key)
	}
	if (km.Claim == "") == (len(km.ClaimPath) == 0) {
		return bad("mapping key %q must set exactly one of claim and claimPath", km.Key)
	}
	switch km.Type {
	case "", model.ValueString, model.ValueStringArray:
	default:
		return bad("mapping key %q carries an unknown type %q", km.Key, km.Type)
	}
	switch km.Normalization {
	case "", model.NormalizeNone, model.NormalizeLowercase:
	default:
		return bad("mapping key %q carries an unknown normalization %q", km.Key, km.Normalization)
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
		Key:           km.Key,
		Path:          path,
		Type:          km.Type,
		Normalization: km.Normalization,
	}
	if out.Type == "" {
		out.Type = model.ValueString
	}
	if out.Normalization == "" {
		out.Normalization = model.NormalizeNone
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

// compileGroups validates the policy's group list into dst.
func compileGroups(groups []model.Group, dst map[string][]string) []Problem {
	var problems []Problem
	fail := func(format string, args ...any) {
		problems = append(problems, Problem{
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf(format, args...),
			Blocking: true,
		})
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
		dst[g.Name] = g.Clients
	}
	return problems
}
