package compile

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

const (
	namespace = "core-1-core"
	domain    = "gateway.public"
)

func rate(requests int64, period time.Duration) model.Rate {
	return model.Rate{Requests: requests, Period: period}
}

// policyOf builds a minimal valid policy: one block, one per-client rule.
func policyOf() model.Policy {
	return model.Policy{
		Domain: domain,
		Blocks: []model.Block{{
			Name:   "api",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
			Rules: []model.Rule{{
				Name:     "per-user",
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{rate(100, time.Minute)},
			}},
		}},
	}
}

// withKeys adds the mappings and groups the rule-level tests resolve against.
func withKeys(p model.Policy) model.Policy {
	p.Mappings = []model.KeyMapping{
		{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalization: model.NormalizeLowercase},
	}
	p.Groups = append(p.Groups, model.Group{Name: "partners", Clients: []string{"a", "b"}})
	return p
}

// compileOne is the shape every test uses: one policy, which is one domain.
func compileOne(p model.Policy) (*Snapshot, []Problem) {
	return Compile(namespace, domain, &p)
}

func reasons(problems []Problem) map[Reason]int {
	out := map[Reason]int{}
	for _, p := range problems {
		out[p.Reason]++
	}
	return out
}

// TestCompileIsPure pins the property every replica depends on: the same spec
// compiles to the same snapshot, with nothing of the caller's context in it.
func TestCompileIsPure(t *testing.T) {
	first, p1 := compileOne(withKeys(policyOf()))
	second, p2 := compileOne(withKeys(policyOf()))

	if len(p1)+len(p2) != 0 {
		t.Fatalf("unexpected problems: %v %v", p1, p2)
	}
	if !reflect.DeepEqual(first, second) {
		t.Error("two compilations of one spec differ")
	}
}

// TestBlocksKeepAuthoredOrder pins the one place ordering is semantics: a
// FirstMatch cascade reads its rules in the order they were written, and the
// blocks around it keep theirs too.
func TestBlocksKeepAuthoredOrder(t *testing.T) {
	p := policyOf()
	p.Blocks = append(p.Blocks, model.Block{
		Name:  "zzz-total",
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{rate(1000, time.Minute)}}},
	})
	p.Blocks[0], p.Blocks[1] = p.Blocks[1], p.Blocks[0]

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if snap.Blocks[0].Name != "zzz-total" || snap.Blocks[1].Name != "api" {
		t.Errorf("blocks = %s, %s: compilation reordered them",
			snap.Blocks[0].Name, snap.Blocks[1].Name)
	}
}

func TestDefaultsResolve(t *testing.T) {
	snap, problems := compileOne(policyOf())
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	block := snap.Blocks[0]
	if block.Mode != model.ModeAll {
		t.Errorf("mode = %q, want the All default", block.Mode)
	}
	rule := block.Rules[0]
	if rule.Behavior != model.BehaviorEnforce {
		t.Errorf("behavior = %q, want the Enforce default", rule.Behavior)
	}
	window := rule.Rates[0]
	if window.Algorithm.Name() != "GCRA" {
		t.Errorf("algorithm = %q, want the GCRA default", window.Algorithm.Name())
	}
	if window.Window.Burst != 100 {
		t.Errorf("burst = %d, want the full-bucket default of requests", window.Window.Burst)
	}
	if !strings.HasPrefix(window.Prefix, "rl:v1:{"+namespace+"/"+domain+"}:api/per-user:") {
		t.Errorf("rate prefix = %q, want the namespace and the block/rule pair", window.Prefix)
	}
}

// TestOneBlockingProblemInvalidatesTheGeneration pins atomicity: a snapshot
// never carries part of a generation, because a FirstMatch cascade missing one
// rule hands its traffic to the neighbours.
func TestOneBlockingProblemInvalidatesTheGeneration(t *testing.T) {
	p := policyOf()
	p.Blocks = append(p.Blocks, model.Block{
		Name:   "second",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathExact, Value: "/x"}}}},
		Rules: []model.Rule{{
			Name:    "per-plan",
			Matches: []model.Predicate{{Key: "plan", Operator: model.OperatorEquals, Value: "gold"}},
			Rates:   []model.Rate{rate(10, time.Minute)},
		}},
	})

	snap, problems := compileOne(p)

	if reasons(problems)[ReasonUnresolvedKeyReference] != 1 {
		t.Fatalf("problems = %v, want one UnresolvedKeyReference", problems)
	}
	if len(snap.Blocks) != 0 {
		t.Errorf("blocks = %+v: the healthy block must not be enforced either", snap.Blocks)
	}
}

// TestSnapshotStillNamesTheDomain pins that an invalid generation leaves a
// usable snapshot: the domain is claimed, so its requests are allowed rather
// than reported as an unknown domain.
func TestSnapshotStillNamesTheDomain(t *testing.T) {
	p := policyOf()
	p.Blocks[0].Rules[0].Counters = []string{"ghost"}

	snap, problems := compileOne(p)
	if len(problems) == 0 {
		t.Fatal("an unresolved axis compiled without problems")
	}
	if snap.Domain != domain || snap.Namespace != namespace {
		t.Errorf("snapshot = %q/%q, want the domain named even when nothing compiles",
			snap.Namespace, snap.Domain)
	}
	if len(snap.EffectiveKeys) == 0 {
		t.Error("the built-in key set is missing from an invalid generation's snapshot")
	}
}

func TestBlockingReasons(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Policy)
		want   Reason
	}{
		{"unknown matches key", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{{Key: "plan", Operator: model.OperatorExists}}
		}, ReasonUnresolvedKeyReference},
		{"unknown counter axis", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Counters = []string{"plan"}
		}, ReasonUnresolvedKeyReference},
		{"unknown group", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "ghosts"}}
		}, ReasonUnresolvedGroupReference},
		{"replacedRules names a missing rule", func(p *model.Policy) {
			p.Blocks[0].Rules[0].ReplacedRules = []string{"ghost"}
		}, ReasonUnresolvedReplacedRules},
		{"replacedRules names itself", func(p *model.Policy) {
			p.Blocks[0].Rules[0].ReplacedRules = []string{"per-user"}
		}, ReasonUnresolvedReplacedRules},
		{"equals on an array key", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: "roles", Operator: model.OperatorEquals, Value: "admin"}}
		}, ReasonIncompatibleOperator},
		{"array key as an axis", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Counters = []string{"roles"}
		}, ReasonInvalidCounterAxis},
		{"window beyond gcra resolution", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(500_001, time.Second)}
		}, ReasonInvalidWindow},
		{"path in matches", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyPath, Operator: model.OperatorEquals, Value: "/x"}}
		}, ReasonInvalidSpec},
		{"token in matches", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyToken, Operator: model.OperatorExists}}
		}, ReasonInvalidSpec},
		{"bypass with rates", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
		}, ReasonInvalidSpec},
		{"replacedRules under FirstMatch", func(p *model.Policy) {
			p.Blocks[0].Mode = model.ModeFirstMatch
			p.Blocks[0].Rules[0].ReplacedRules = []string{"per-user"}
		}, ReasonInvalidSpec},
		{"duplicate periods", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(10, time.Minute), rate(20, time.Minute)}
		}, ReasonInvalidSpec},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := withKeys(policyOf())
			tc.mutate(&p)
			snap, problems := compileOne(p)
			if got := reasons(problems); got[tc.want] == 0 {
				t.Fatalf("problems = %v, want %s", problems, tc.want)
			}
			if len(snap.Blocks) != 0 {
				t.Errorf("the generation compiled despite a blocking problem: %+v", snap.Blocks)
			}
		})
	}
}

// TestInvalidSpecFamily walks the structural guards the schema no longer
// carries: with CEL reduced to the name rule, the compiler is the only judge of
// how the fields relate, and it answers with problems rather than with garbage.
func TestInvalidSpecFamily(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Policy)
	}{
		{"foreign domain", func(p *model.Policy) { p.Domain = "gateway.private" }},
		{"no blocks", func(p *model.Policy) { p.Blocks = nil }},
		{"duplicate block", func(p *model.Policy) { p.Blocks = append(p.Blocks, p.Blocks[0]) }},
		{"no rules", func(p *model.Policy) { p.Blocks[0].Rules = nil }},
		{"duplicate rule", func(p *model.Policy) {
			p.Blocks[0].Rules = append(p.Blocks[0].Rules, p.Blocks[0].Rules[0])
		}},
		{"unknown mode", func(p *model.Policy) { p.Blocks[0].Mode = "Sometimes" }},
		{"unknown behavior", func(p *model.Policy) { p.Blocks[0].Rules[0].Behavior = "Maybe" }},
		{"unknown operator", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyClient, Operator: "Matches", Value: "x"}}
		}},
		{"unknown path type", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Type = "Regex" }},
		{"relative path", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Value = "api/" }},
		{"unknown method", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Methods = []string{"FETCH"} }},
		{"duplicate method", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Methods = []string{"GET", "GET"}
		}},
		{"no rates on a counting rule", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates = nil }},
		{"unknown algorithm", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates[0].Algorithm = "SlidingLog" }},
		{"duplicate group", func(p *model.Policy) {
			p.Groups = []model.Group{{Name: "g", Clients: []string{"a"}}, {Name: "g", Clients: []string{"b"}}}
		}},
		{"unnamed group", func(p *model.Policy) { p.Groups = []model.Group{{Clients: []string{"a"}}} }},
		{"empty In values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorIn}}
		}},
		{"bypass under All without replacedRules", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
			p.Blocks[0].Rules[0].Rates = nil
		}},
		{"exists with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyClient, Operator: model.OperatorExists, Value: "alice"}}
		}},
		{"equals with values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "a", Values: []string{"b"}}}
		}},
		{"in with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyClient, Operator: model.OperatorIn, Value: "a", Values: []string{"b"}}}
		}},
		{"bad mapping key name", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "Bad-Name", Claim: "x"}}
		}},
		{"mapping over a built-in", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: model.KeyPath, Claim: "x"}}
		}},
		{"claim and claimPath together", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a", ClaimPath: []string{"b"}}}
		}},
		{"neither claim nor claimPath", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan"}}
		}},
		{"mapping key declared twice", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a"}, {Key: "plan", Claim: "b"}}
		}},
		{"client declared twice", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{
				{Key: model.KeyClient, Claim: "azp"}, {Key: model.KeyClient, Claim: "sub"}}
		}},
		{"empty claim segment", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a..b"}}
		}},
		{"empty fallback segment", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a", Fallbacks: []string{""}}}
		}},
		{"unknown value type", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a", Type: "Number"}}
		}},
		{"unknown normalization", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "plan", Claim: "a", Normalization: "Uppercase"}}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := policyOf()
			tc.mutate(&p)
			snap, problems := compileOne(p)
			if reasons(problems)[ReasonInvalidSpec] == 0 {
				t.Fatalf("problems = %v, want InvalidSpec", problems)
			}
			if len(snap.Blocks) != 0 {
				t.Error("the generation compiled despite a structural problem")
			}
		})
	}
}

// TestNoListIsBounded pins the removal of the schema's list caps: what binds a
// generation is the bucket budget and the object size, never a count of blocks,
// rules, axes, or windows.
func TestNoListIsBounded(t *testing.T) {
	p := model.Policy{Domain: domain}
	// 300 blocks of one bucket each: far past every bound the schema used to
	// carry, and well inside the one that remains.
	for i := range 100 {
		p.Blocks = append(p.Blocks, model.Block{
			Name:  fmt.Sprintf("b%d", i),
			Rules: []model.Rule{{Name: "all", Rates: []model.Rate{rate(100, time.Minute)}}},
		})
	}
	p.Groups = []model.Group{{Name: "big", Clients: make([]string, 4096)}}
	for i := range p.Groups[0].Clients {
		p.Groups[0].Clients[i] = fmt.Sprintf("c%d", i)
	}

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("a wide but budgeted generation must compile; problems: %v", problems)
	}
	if len(snap.Blocks) != 100 {
		t.Errorf("blocks = %d, want all 100", len(snap.Blocks))
	}
}

// TestTargetlessBlockCompiles pins the documented whole-domain form: no
// target means the block applies to the domain's entire traffic.
func TestTargetlessBlockCompiles(t *testing.T) {
	p := policyOf()
	p.Blocks[0].Target = model.Target{}
	snap, problems := compileOne(p)
	if len(problems) != 0 || len(snap.Blocks) != 1 || len(snap.Blocks[0].Routes) != 0 {
		t.Errorf("problems = %v, blocks = %+v: a target-less block is legal and route-less", problems, snap.Blocks)
	}
}

// TestInvalidDomainCompilesNothing pins the guard in front of the key
// builder's empty-hash-tag panic: an invalid domain is a compile problem,
// never a request-time crash.
func TestInvalidDomainCompilesNothing(t *testing.T) {
	for _, d := range []string{"", "Bad_Domain", "-x", "a/b", strings.Repeat("a", 64)} {
		p := policyOf()
		p.Domain = d
		snap, problems := Compile(namespace, d, &p)
		if len(snap.Blocks) != 0 || reasons(problems)[ReasonInvalidSpec] == 0 {
			t.Errorf("domain %q: blocks = %d, problems = %v; want a blocking InvalidSpec and no blocks",
				d, len(snap.Blocks), problems)
		}
	}
}

// TestEmptyNamespaceCompilesNothing pins the other half of the hash tag: the
// component's own namespace is a key segment, and an empty one would scatter a
// decision across cluster slots.
func TestEmptyNamespaceCompilesNothing(t *testing.T) {
	p := policyOf()
	snap, problems := Compile("", domain, &p)
	if len(snap.Blocks) != 0 || reasons(problems)[ReasonInvalidSpec] == 0 {
		t.Errorf("blocks = %d, problems = %v; want a blocking InvalidSpec", len(snap.Blocks), problems)
	}
}

// TestNilPolicyIsTheEmptyDomain pins what a domain with nothing enforced looks
// like: built-in keys, no blocks, no problems.
func TestNilPolicyIsTheEmptyDomain(t *testing.T) {
	snap, problems := Compile(namespace, domain, nil)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(snap.Blocks) != 0 {
		t.Errorf("blocks = %d, want none", len(snap.Blocks))
	}
	want := []string{model.KeyClient, model.KeyMethod, model.KeyPath}
	if !reflect.DeepEqual(snap.EffectiveKeys, want) {
		t.Errorf("effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
	if len(snap.Extraction) != 1 || snap.Extraction[0].Key != model.KeyClient {
		t.Errorf("extraction = %+v, want the built-in client alone", snap.Extraction)
	}
}

// TestSnapshotDoesNotAliasTheModel pins immutability: mutating the model
// after Compile must not reach the snapshot.
func TestSnapshotDoesNotAliasTheModel(t *testing.T) {
	p := policyOf()
	p.Mappings = []model.KeyMapping{{Key: "plan", ClaimPath: []string{"a", "b"}}}

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	p.Blocks[0].Rules[0].Counters[0] = "mutated"
	if snap.Blocks[0].Rules[0].Counters[0] != model.KeyClient {
		t.Error("the snapshot aliased the model's counters slice")
	}
	p.Mappings[0].ClaimPath[0] = "mutated"
	if snap.Extraction[1].Path[0] != "a" {
		t.Error("the extraction plan aliased the model's claimPath slice")
	}
}

func TestCaptureShadowingIsInformational(t *testing.T) {
	p := withKeys(policyOf())
	p.Blocks[0].Target.Routes = append(p.Blocks[0].Target.Routes, model.Route{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/tenants/{tenant}/orders"},
	})

	snap, problems := compileOne(p)

	if len(problems) != 1 || problems[0].Reason != ReasonCaptureShadowsMappedKey || problems[0].Blocking {
		t.Fatalf("problems = %v, want one non-blocking CaptureShadowsMappedKey", problems)
	}
	if len(snap.Blocks) != 1 {
		t.Fatal("an informational problem must not invalidate the generation")
	}
	if got := snap.Blocks[0].Captures; len(got) != 1 || got[0] != "tenant" {
		t.Errorf("captures = %v, want [tenant]", got)
	}
}

func TestCapturesAreBlockScopedKeys(t *testing.T) {
	p := policyOf()
	p.Blocks[0].Target.Routes = []model.Route{{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/orders/{orderId}/items"},
	}}
	p.Blocks[0].Rules[0].Counters = []string{"orderId"}

	snap, problems := compileOne(p)
	if len(problems) != 0 || len(snap.Blocks) != 1 {
		t.Fatalf("problems = %v: a capture must resolve as a counter axis in its own block", problems)
	}
	if got := snap.EffectiveKeys; len(got) != 3 {
		t.Errorf("effective keys = %v: a capture is block-scoped and must not be listed", got)
	}

	// A second block does not see the first block's capture.
	p.Blocks = append(p.Blocks, model.Block{
		Name:  "stranger",
		Rules: []model.Rule{{Name: "r", Counters: []string{"orderId"}, Rates: []model.Rate{rate(1, time.Minute)}}},
	})
	_, problems = compileOne(p)
	if reasons(problems)[ReasonUnresolvedKeyReference] == 0 {
		t.Error("a capture leaked outside its block: another block resolved it")
	}
}

// TestCamelCaseKeysAreAdmitted pins the widened key pattern: {orderId} is the
// shape the specification's own examples use.
func TestCamelCaseKeysAreAdmitted(t *testing.T) {
	p := policyOf()
	p.Mappings = []model.KeyMapping{{Key: "tenantId", Claim: "org_id"}}
	p.Blocks[0].Rules[0].Counters = []string{"tenantId"}
	p.Blocks[0].Target.Routes = []model.Route{{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/orders/{orderId}"},
	}}

	snap, problems := compileOne(p)
	if len(problems) != 0 || len(snap.Blocks) != 1 {
		t.Fatalf("camelCase keys must compile; problems: %v", problems)
	}
	if got := snap.Blocks[0].Captures; len(got) != 1 || got[0] != "orderId" {
		t.Errorf("captures = %v, want [orderId]", got)
	}
}

func TestGroupsResolveAtCompileTime(t *testing.T) {
	p := withKeys(policyOf())
	p.Blocks[0].Rules[0].Matches = []model.Predicate{
		{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "partners"},
	}

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	got := snap.Blocks[0].Rules[0].Matches[0].Values
	if len(got) != 2 {
		t.Errorf("resolved group = %v, want the client list baked in", got)
	}
}

func TestExtractionPlan(t *testing.T) {
	snap, problems := compileOne(withKeys(policyOf()))
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	if snap.Extraction[0].Key != model.KeyClient || snap.Extraction[0].Path[0] != "sub" {
		t.Errorf("extraction[0] = %+v, want the built-in client from sub", snap.Extraction[0])
	}
	roles := snap.Extraction[1]
	if !reflect.DeepEqual(roles.Path, []string{"realm_access", "roles"}) {
		t.Errorf("roles path = %v, want the dot path split", roles.Path)
	}
	tenant := snap.Extraction[2]
	if len(tenant.Fallbacks) != 1 || tenant.Fallbacks[0][0] != "sub" {
		t.Errorf("tenant fallbacks = %v, want [[sub]]", tenant.Fallbacks)
	}

	want := []string{model.KeyClient, model.KeyMethod, model.KeyPath, "roles", "tenant"}
	if !reflect.DeepEqual(snap.EffectiveKeys, want) {
		t.Errorf("effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
}

func TestClientOverrideReplacesBuiltin(t *testing.T) {
	p := policyOf()
	p.Mappings = []model.KeyMapping{{Key: model.KeyClient, Claim: "azp"}}

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(snap.Extraction) != 1 || snap.Extraction[0].Path[0] != "azp" {
		t.Errorf("extraction = %+v, want the override only, no built-in duplicate", snap.Extraction)
	}
}

func TestUndeclaredKeyBlocksTheGeneration(t *testing.T) {
	p := policyOf()
	p.Blocks[0].Rules[0].Matches = []model.Predicate{
		{Key: "roles", Operator: model.OperatorContains, Value: "admin"}}

	snap, problems := compileOne(p)
	if reasons(problems)[ReasonUnresolvedKeyReference] == 0 || len(snap.Blocks) != 0 {
		t.Errorf("problems = %v, blocks = %d: without the mapping the generation must be invalid whole",
			problems, len(snap.Blocks))
	}
}

// TestSpecCascadeCompiles is the specification's two-block example in
// miniature: a FirstMatch cascade with Bypass and Shadow steps over an additive
// block.
func TestSpecCascadeCompiles(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Clients: []string{"t1", "t2"}}},
		Blocks: []model.Block{
			{
				Name: "cascade",
				Mode: model.ModeFirstMatch,
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/quotes/"}}}},
				Rules: []model.Rule{
					{Name: "internal", Behavior: model.BehaviorBypass,
						Matches: []model.Predicate{
							{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "prometheus"}}},
					{Name: "trial",
						Matches:  []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "trial"}},
						Behavior: model.BehaviorShadow, Counters: []string{model.KeyClient},
						Rates: []model.Rate{rate(10, time.Minute)}},
					{Name: "everyone", Counters: []string{model.KeyClient},
						Rates: []model.Rate{
							rate(100, time.Minute),
							{Requests: 10000, Period: 24 * time.Hour, Algorithm: "FixedWindow"}}},
				},
			},
			{
				Name: "total",
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "all", Rates: []model.Rate{rate(5000, time.Minute)}}},
			},
		},
	}

	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(snap.Blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(snap.Blocks))
	}
	cascade := snap.Blocks[0]
	if cascade.Mode != model.ModeFirstMatch || len(cascade.Rules) != 3 {
		t.Fatalf("cascade = %+v", cascade)
	}
	if cascade.Rules[0].Behavior != model.BehaviorBypass || cascade.Rules[0].Rates != nil {
		t.Error("bypass rule must compile without rates")
	}
	daily := cascade.Rules[2].Rates[1]
	if daily.Algorithm.Name() != "FixedWindow" || daily.Window.Burst != 0 {
		t.Errorf("daily quota = %+v, want FixedWindow without burst", daily)
	}
}

// fourRates is one rule's worth of windows for the budget arithmetic.
func fourRates() []model.Rate {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	out := make([]model.Rate, 0, len(periods))
	for _, p := range periods {
		out = append(out, model.Rate{Requests: 100, Period: p})
	}
	return out
}

// counting builds n counting rules of four windows each.
func counting(n int, behavior model.Behavior) []model.Rule {
	out := make([]model.Rule, 0, n)
	for i := range n {
		out = append(out, model.Rule{
			Name: fmt.Sprintf("r%d", i), Behavior: behavior, Rates: fourRates()})
	}
	return out
}

func budgetPolicy(mode model.Mode, rules []model.Rule) model.Policy {
	return model.Policy{Domain: domain,
		Blocks: []model.Block{{Name: "b", Mode: mode, Rules: rules}}}
}

// TestDecisionBucketBudget pins the worst-case formula and the fact that going
// over it is blocking: the alternative is a generation whose widest paths the
// runtime backstop refuses outright.
func TestDecisionBucketBudget(t *testing.T) {
	t.Run("All sums every rule", func(t *testing.T) {
		snap, problems := compileOne(budgetPolicy(model.ModeAll, counting(33, "")))
		if reasons(problems)[ReasonDomainBudgetExceeded] == 0 {
			t.Fatalf("33 rules x 4 rates = 132 must exceed the budget of %d; problems: %v",
				model.MaxDomainDecisionBuckets, problems)
		}
		if len(snap.Blocks) != 0 {
			t.Fatal("a generation over the budget must be enforced nowhere")
		}
	})
	t.Run("the boundary itself passes", func(t *testing.T) {
		snap, problems := compileOne(budgetPolicy(model.ModeAll, counting(32, "")))
		if len(problems) != 0 || len(snap.Blocks) != 1 {
			t.Fatalf("32 rules x 4 rates = 128 is exactly the budget; problems: %v", problems)
		}
		if snap.DecisionBuckets != 128 {
			t.Errorf("DecisionBuckets = %d, want 128", snap.DecisionBuckets)
		}
	})
	t.Run("FirstMatch settles on its widest rule", func(t *testing.T) {
		_, problems := compileOne(budgetPolicy(model.ModeFirstMatch, counting(33, "")))
		if len(problems) != 0 {
			t.Fatalf("FirstMatch worst case is one rule of 4 buckets; problems: %v", problems)
		}
	})
	t.Run("FirstMatch counts every shadow rule", func(t *testing.T) {
		rules := counting(32, model.BehaviorShadow)
		rules = append(rules, model.Rule{Name: "last", Rates: fourRates()})
		_, problems := compileOne(budgetPolicy(model.ModeFirstMatch, rules))
		if reasons(problems)[ReasonDomainBudgetExceeded] == 0 {
			t.Fatalf("32 shadow rules count before the terminating rule; problems: %v", problems)
		}
	})
	t.Run("blocks add up", func(t *testing.T) {
		p := budgetPolicy(model.ModeAll, counting(17, ""))
		second := budgetPolicy(model.ModeAll, counting(17, "")).Blocks[0]
		second.Name = "b2"
		p.Blocks = append(p.Blocks, second)

		_, problems := compileOne(p)
		if reasons(problems)[ReasonDomainBudgetExceeded] == 0 {
			t.Fatalf("two blocks of 68 buckets must exceed the budget; problems: %v", problems)
		}
	})
}
