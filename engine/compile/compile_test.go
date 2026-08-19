package compile

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

const domain = "gateway.public"

const healthyName = "healthy"

func rate(requests int64, period time.Duration) model.Rate {
	return model.Rate{Requests: requests, Period: period}
}

// policyOf builds a minimal valid policy: one block, one per-client rule.
func policyOf(name string) model.Policy {
	return model.Policy{
		Name:   name,
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

func mappingOf() *model.Mapping {
	return &model.Mapping{
		Domain: domain,
		Mappings: []model.KeyMapping{
			{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
			{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalize: model.NormalizeLowercase},
		},
		Groups: []model.Group{{Name: "partners", Clients: []string{"a", "b"}}},
	}
}

func reasons(problems []Problem) map[Reason]int {
	out := map[Reason]int{}
	for _, p := range problems {
		out[p.Reason]++
	}
	return out
}

func TestCompileIsAPureFunctionOfTheSet(t *testing.T) {
	a, b, c := policyOf("alpha"), policyOf("beta"), policyOf("gamma")
	m := mappingOf()

	first, p1 := Compile(domain, []model.Policy{a, b, c}, m)
	second, p2 := Compile(domain, []model.Policy{c, a, b}, m)
	third, p3 := Compile(domain, []model.Policy{b, c, a}, m)

	if len(p1)+len(p2)+len(p3) != 0 {
		t.Fatalf("unexpected problems: %v %v %v", p1, p2, p3)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(second, third) {
		t.Error("apply order reached the snapshot: permuted inputs compiled differently")
	}
	got := []string{first.Blocks[0].Policy, first.Blocks[1].Policy, first.Blocks[2].Policy}
	if got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Errorf("blocks are not ordered by policy name: %v", got)
	}
}

func TestDefaultsResolve(t *testing.T) {
	snap, problems := Compile(domain, []model.Policy{policyOf("p")}, nil)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	block := snap.Blocks[0]
	if block.Mode != model.ModeAll {
		t.Errorf("mode = %q, want the All default", block.Mode)
	}
	r := block.Rules[0]
	if r.Behavior != model.BehaviorEnforce {
		t.Errorf("behavior = %q, want the Enforce default", r.Behavior)
	}
	w := r.Rates[0]
	if w.Algorithm.Name() != "GCRA" {
		t.Errorf("algorithm = %q, want the GCRA default", w.Algorithm.Name())
	}
	if w.Window.Burst != 100 {
		t.Errorf("burst = %d, want the full-bucket default of 100", w.Window.Burst)
	}
}

func TestOneBlockingProblemInvalidatesTheWholePolicy(t *testing.T) {
	broken := policyOf("broken")
	broken.Blocks = append(broken.Blocks, model.Block{
		Name:   "second",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathExact, Value: "/x"}}}},
		Rules: []model.Rule{{
			Name:  "per-plan",
			When:  []model.Condition{{Key: "plan", Operator: model.OperatorEquals, Value: "gold"}},
			Rates: []model.Rate{rate(10, time.Minute)},
		}},
	})
	healthy := policyOf(healthyName)

	snap, problems := Compile(domain, []model.Policy{broken, healthy}, nil)

	if reasons(problems)[ReasonUnresolvedKeyReference] != 1 {
		t.Fatalf("problems = %v, want one UnresolvedKeyReference", problems)
	}
	if len(snap.Blocks) != 1 || snap.Blocks[0].Policy != healthyName {
		t.Fatalf("snapshot blocks = %+v: the broken policy must be excluded whole, its healthy block included nowhere",
			snap.Blocks)
	}
}

func TestBlockingReasons(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Policy)
		want   Reason
	}{
		{"unknown when key", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{{Key: "plan", Operator: model.OperatorExists}}
		}, ReasonUnresolvedKeyReference},
		{"unknown counter axis", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Counters = []string{"plan"}
		}, ReasonUnresolvedKeyReference},
		{"unknown group", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{
				{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "ghosts"}}
		}, ReasonUnresolvedGroupReference},
		{"equals on an array key", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{{Key: "roles", Operator: model.OperatorEquals, Value: "admin"}}
		}, ReasonIncompatibleOperator},
		{"array key as an axis", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Counters = []string{"roles"}
		}, ReasonInvalidCounterAxis},
		{"window beyond gcra resolution", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(500_001, time.Second)}
		}, ReasonInvalidWindow},
		{"path in when", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{{Key: model.KeyPath, Operator: model.OperatorEquals, Value: "/x"}}
		}, ReasonInvalidSpec},
		{"bypass with rates", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
		}, ReasonInvalidSpec},
		{"replaces under FirstMatch", func(p *model.Policy) {
			p.Blocks[0].Mode = model.ModeFirstMatch
			p.Blocks[0].Rules[0].Replaces = []string{"per-user"}
		}, ReasonInvalidSpec},
		{"duplicate periods", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(10, time.Minute), rate(20, time.Minute)}
		}, ReasonInvalidSpec},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := policyOf("p")
			tc.mutate(&p)
			snap, problems := Compile(domain, []model.Policy{p}, mappingOf())
			if got := reasons(problems); got[tc.want] == 0 {
				t.Fatalf("problems = %v, want %s", problems, tc.want)
			}
			if len(snap.Blocks) != 0 {
				t.Errorf("the policy compiled despite a blocking problem: %+v", snap.Blocks)
			}
		})
	}
}

// TestInvalidSpecFamily walks the structural guards the schema normally
// enforces upstream: the library re-checks them and answers with problems,
// never with garbage compilation.
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
			p.Blocks[0].Rules[0].When = []model.Condition{{Key: model.KeyClient, Operator: "Matches", Value: "x"}}
		}},
		{"unknown path type", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Type = "Regex" }},
		{"relative path", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Value = "api/" }},
		{"unknown method", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Methods = []string{"FETCH"} }},
		{"duplicate method", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Methods = []string{"GET", "GET"}
		}},
		{"no rates on a counting rule", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates = nil }},
		{"unknown algorithm", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates[0].Algorithm = "SlidingLog" }},
		{"replaces a missing rule", func(p *model.Policy) { p.Blocks[0].Rules[0].Replaces = []string{"ghost"} }},
		{"replaces itself", func(p *model.Policy) { p.Blocks[0].Rules[0].Replaces = []string{"per-user"} }},
		{"duplicate private group", func(p *model.Policy) {
			p.Groups = []model.Group{{Name: "g", Clients: []string{"a"}}, {Name: "g", Clients: []string{"b"}}}
		}},
		{"unnamed group", func(p *model.Policy) { p.Groups = []model.Group{{Clients: []string{"a"}}} }},
		{"empty In values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{{Key: model.KeyClient, Operator: model.OperatorIn}}
		}},
		{"bypass under All without replaces", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
			p.Blocks[0].Rules[0].Rates = nil
		}},
		{"exists with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{
				{Key: model.KeyClient, Operator: model.OperatorExists, Value: "alice"}}
		}},
		{"equals with values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{
				{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "a", Values: []string{"b"}}}
		}},
		{"in with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].When = []model.Condition{
				{Key: model.KeyClient, Operator: model.OperatorIn, Value: "a", Values: []string{"b"}}}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := policyOf("p")
			tc.mutate(&p)
			snap, problems := Compile(domain, []model.Policy{p}, nil)
			if reasons(problems)[ReasonInvalidSpec] == 0 {
				t.Fatalf("problems = %v, want InvalidSpec", problems)
			}
			if len(snap.Blocks) != 0 {
				t.Errorf("the policy compiled despite a structural problem")
			}
		})
	}
}

// TestTargetlessBlockCompiles pins the documented whole-domain form: no
// target means the block applies to the domain's entire traffic.
func TestTargetlessBlockCompiles(t *testing.T) {
	p := policyOf("p")
	p.Blocks[0].Target = model.Target{}
	snap, problems := Compile(domain, []model.Policy{p}, nil)
	if len(problems) != 0 || len(snap.Blocks) != 1 || len(snap.Blocks[0].Routes) != 0 {
		t.Errorf("problems = %v, blocks = %+v: a target-less block is legal and route-less", problems, snap.Blocks)
	}
}

// TestInvalidDomainCompilesNothing pins the guard in front of the key
// builder's empty-hash-tag panic: an invalid domain is a compile problem,
// never a request-time crash.
func TestInvalidDomainCompilesNothing(t *testing.T) {
	for _, d := range []string{"", "Bad_Domain", "-x", strings.Repeat("a", 64)} {
		snap, problems := Compile(d, []model.Policy{policyOf("p")}, nil)
		if len(snap.Blocks) != 0 || reasons(problems)[ReasonInvalidSpec] == 0 {
			t.Errorf("domain %q: blocks = %d, problems = %v; want a blocking InvalidSpec and no blocks",
				d, len(snap.Blocks), problems)
		}
	}
}

// TestDuplicatePolicyNamesExcludeAllBearers pins that colliding counter
// identities never reach the snapshot.
func TestDuplicatePolicyNamesExcludeAllBearers(t *testing.T) {
	twin := policyOf("twin")
	snap, problems := Compile(domain, []model.Policy{twin, policyOf(healthyName), twin}, nil)

	if reasons(problems)[ReasonInvalidSpec] != 2 {
		t.Fatalf("problems = %v, want one InvalidSpec per bearer of the name", problems)
	}
	if len(snap.Blocks) != 1 || snap.Blocks[0].Policy != healthyName {
		t.Errorf("blocks = %+v, want the healthy policy alone", snap.Blocks)
	}
}

// TestSnapshotDoesNotAliasTheModel pins immutability: mutating the model
// after Compile must not reach the snapshot.
func TestSnapshotDoesNotAliasTheModel(t *testing.T) {
	p := policyOf("p")
	p.Blocks[0].Rules[0].Replaces = nil
	snap, _ := Compile(domain, []model.Policy{p}, nil)

	p.Blocks[0].Rules[0].Counters[0] = "mutated"
	if snap.Blocks[0].Rules[0].Counters[0] != model.KeyClient {
		t.Error("the snapshot aliased the model's counters slice")
	}

	m := &model.Mapping{Domain: domain, Mappings: []model.KeyMapping{
		{Key: "plan", ClaimPath: []string{"a", "b"}},
	}}
	snap, problems := Compile(domain, nil, m)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	m.Mappings[0].ClaimPath[0] = "mutated"
	if snap.Extraction[1].Path[0] != "a" {
		t.Error("the extraction plan aliased the model's claimPath slice")
	}
}

// TestMappingProblems pins the defensive path: a broken mapping is reported
// with policy-less problems, and its broken entries contribute nothing.
func TestMappingProblems(t *testing.T) {
	cases := []struct {
		name string
		m    *model.Mapping
	}{
		{"foreign domain", &model.Mapping{Domain: "other"}},
		{"bad key name", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "Bad-Name", Claim: "x"}}}},
		{"built-in collision", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: model.KeyPath, Claim: "x"}}}},
		{"claim and claimPath together", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a", ClaimPath: []string{"b"}}}}},
		{"neither claim nor claimPath", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan"}}}},
		{"key declared twice", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a"}, {Key: "plan", Claim: "b"}}}},
		{"duplicate shared group", &model.Mapping{Domain: domain,
			Groups: []model.Group{{Name: "g", Clients: []string{"a"}}, {Name: "g"}}}},
		{"empty claim segment", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a..b"}}}},
		{"empty fallback segment", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a", Fallbacks: []string{""}}}}},
		{"client declared twice", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "client", Claim: "azp"}, {Key: "client", Claim: "sub"}}}},
		{"unknown value type", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a", Type: "Number"}}}},
		{"unknown normalize", &model.Mapping{Domain: domain,
			Mappings: []model.KeyMapping{{Key: "plan", Claim: "a", Normalize: "Uppercase"}}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, problems := Compile(domain, nil, tc.m)
			if len(problems) == 0 {
				t.Fatal("a broken mapping compiled without problems")
			}
			for _, p := range problems {
				if p.Policy != "" {
					t.Errorf("mapping problem carries a policy name: %+v", p)
				}
			}
		})
	}
}

func TestCaptureShadowingIsInformational(t *testing.T) {
	p := policyOf("p")
	p.Blocks[0].Target.Routes = append(p.Blocks[0].Target.Routes, model.Route{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/tenants/{tenant}/orders"},
	})

	snap, problems := Compile(domain, []model.Policy{p}, mappingOf())

	if len(problems) != 1 || problems[0].Reason != ReasonCaptureShadowsMappedKey || problems[0].Blocking {
		t.Fatalf("problems = %v, want one non-blocking CaptureShadowsMappedKey", problems)
	}
	if len(snap.Blocks) != 1 {
		t.Fatal("an informational problem must not exclude the policy")
	}
	if got := snap.Blocks[0].Captures; len(got) != 1 || got[0] != "tenant" {
		t.Errorf("captures = %v, want [tenant]", got)
	}
}

func TestCapturesAreBlockScopedKeys(t *testing.T) {
	p := policyOf("p")
	p.Blocks[0].Target.Routes = []model.Route{{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/orders/{order_id}/items"},
	}}
	p.Blocks[0].Rules[0].Counters = []string{"order_id"}

	snap, problems := Compile(domain, []model.Policy{p}, nil)
	if len(problems) != 0 || len(snap.Blocks) != 1 {
		t.Fatalf("problems = %v: a capture must resolve as a counter axis in its own block", problems)
	}

	stranger := policyOf("stranger")
	stranger.Blocks[0].Rules[0].Counters = []string{"order_id"}
	_, problems = Compile(domain, []model.Policy{stranger}, nil)
	if reasons(problems)[ReasonUnresolvedKeyReference] == 0 {
		t.Error("a capture leaked outside its block: another block resolved it")
	}
}

func TestPrivateGroupShadowsShared(t *testing.T) {
	p := policyOf("p")
	p.Groups = []model.Group{{Name: "partners", Clients: []string{"local-only"}}}
	p.Blocks[0].Rules[0].When = []model.Condition{
		{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "partners"},
	}

	snap, problems := Compile(domain, []model.Policy{p}, mappingOf())
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	got := snap.Blocks[0].Rules[0].When[0].Values
	if _, ok := got["local-only"]; !ok || len(got) != 1 {
		t.Errorf("resolved group = %v, want the private list shadowing the shared one", got)
	}
}

func TestExtractionPlan(t *testing.T) {
	snap, problems := Compile(domain, nil, mappingOf())
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
	m := &model.Mapping{Domain: domain, Mappings: []model.KeyMapping{
		{Key: model.KeyClient, Claim: "azp"},
	}}
	snap, problems := Compile(domain, nil, m)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(snap.Extraction) != 1 || snap.Extraction[0].Path[0] != "azp" {
		t.Errorf("extraction = %+v, want the override only, no built-in duplicate", snap.Extraction)
	}
}

func TestMappedKeyWithoutMappingBlocksThePolicy(t *testing.T) {
	p := policyOf("p")
	p.Blocks[0].Rules[0].When = []model.Condition{{Key: "roles", Operator: model.OperatorContains, Value: "admin"}}

	snap, problems := Compile(domain, []model.Policy{p}, nil)
	if reasons(problems)[ReasonUnresolvedKeyReference] == 0 || len(snap.Blocks) != 0 {
		t.Errorf("problems = %v, blocks = %d: without the mapping the policy must be invalid whole",
			problems, len(snap.Blocks))
	}
}

// TestSpecCascadeCompiles is the spec's two-block example in miniature: a
// FirstMatch cascade with Bypass and Shadow steps over an additive block.
func TestSpecCascadeCompiles(t *testing.T) {
	p := model.Policy{
		Name:   "quote-api",
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Clients: []string{"t1", "t2"}}},
		Blocks: []model.Block{
			{
				Name:   "cascade",
				Mode:   model.ModeFirstMatch,
				Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/quotes/"}}}},
				Rules: []model.Rule{
					{Name: "internal", Behavior: model.BehaviorBypass,
						When: []model.Condition{
							{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "prometheus"}}},
					{Name: "trial", When: []model.Condition{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "trial"}},
						Behavior: model.BehaviorShadow, Counters: []string{model.KeyClient},
						Rates: []model.Rate{rate(10, time.Minute)}},
					{Name: "everyone", Counters: []string{model.KeyClient},
						Rates: []model.Rate{rate(100, time.Minute), {Requests: 10000, Period: 24 * time.Hour, Algorithm: "FixedWindow"}}},
				},
			},
			{
				Name:   "total",
				Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules:  []model.Rule{{Name: "all", Rates: []model.Rate{rate(5000, time.Minute)}}},
			},
		},
	}

	snap, problems := Compile(domain, []model.Policy{p}, nil)
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

// TestDecisionBucketBudget pins the worst-case formula: All sums every
// counting rule, FirstMatch settles on its widest counting rule after every
// shadow rule, and a policy over the budget is excluded whole.
func TestDecisionBucketBudget(t *testing.T) {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	fourRates := func() []model.Rate {
		out := make([]model.Rate, 0, len(periods))
		for _, p := range periods {
			out = append(out, model.Rate{Requests: 100, Period: p})
		}
		return out
	}
	policy := func(mode model.Mode, rules []model.Rule) model.Policy {
		return model.Policy{Name: "p", Domain: "d",
			Blocks: []model.Block{{Name: "b", Mode: mode, Rules: rules}}}
	}
	counting := func(n int, behavior model.Behavior) []model.Rule {
		out := make([]model.Rule, 0, n)
		for i := range n {
			out = append(out, model.Rule{
				Name: fmt.Sprintf("r%d", i), Behavior: behavior, Rates: fourRates()})
		}
		return out
	}

	t.Run("All sums every rule", func(t *testing.T) {
		snap, problems := Compile("d", []model.Policy{policy(model.ModeAll, counting(17, ""))}, nil)
		if reasons(problems)[ReasonDecisionBudgetExceeded] == 0 {
			t.Fatalf("17 rules x 4 rates = 68 must exceed the budget of %d; problems: %v",
				model.MaxDecisionBucketsPerPolicy, problems)
		}
		if len(snap.Blocks) != 0 {
			t.Fatal("a policy over the budget must be excluded whole")
		}
	})
	t.Run("the boundary itself passes", func(t *testing.T) {
		snap, problems := Compile("d", []model.Policy{policy(model.ModeAll, counting(16, ""))}, nil)
		if len(problems) != 0 || len(snap.Blocks) != 1 {
			t.Fatalf("16 rules x 4 rates = 64 is exactly the budget; problems: %v", problems)
		}
	})
	t.Run("FirstMatch settles on its widest rule", func(t *testing.T) {
		_, problems := Compile("d", []model.Policy{policy(model.ModeFirstMatch, counting(17, ""))}, nil)
		if len(problems) != 0 {
			t.Fatalf("FirstMatch worst case is one rule of 4 buckets; problems: %v", problems)
		}
	})
	t.Run("FirstMatch counts every shadow rule", func(t *testing.T) {
		rules := counting(16, model.BehaviorShadow)
		rules = append(rules, model.Rule{Name: "last", Rates: fourRates()})
		_, problems := Compile("d", []model.Policy{policy(model.ModeFirstMatch, rules)}, nil)
		if reasons(problems)[ReasonDecisionBudgetExceeded] == 0 {
			t.Fatalf("16 shadow rules count before the terminating rule; problems: %v", problems)
		}
	})
}

// domainProblems filters the domain-level budget records, failing the test
// on any that is blocking or policy-bound.
func domainProblems(t *testing.T, problems []Problem) []Problem {
	t.Helper()
	var out []Problem
	for _, p := range problems {
		if p.Reason == ReasonDomainBudgetExceeded {
			if p.Blocking || p.Policy != "" {
				t.Fatalf("domain record must be informational and domain-level: %+v", p)
			}
			out = append(out, p)
		}
	}
	return out
}

// widePolicy builds one policy at exactly the per-policy budget: one block
// of 16 rules, four windows each.
func widePolicy(name string) model.Policy {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	rules := make([]model.Rule, 0, 16)
	for i := range 16 {
		rates := make([]model.Rate, 0, len(periods))
		for _, pd := range periods {
			rates = append(rates, model.Rate{Requests: 100, Period: pd})
		}
		rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", i), Rates: rates})
	}
	return model.Policy{Name: name, Domain: "d",
		Blocks: []model.Block{{Name: "b", Rules: rules}}}
}

// TestDomainBucketBudgetRecord pins the domain-level record for the bucket
// bound: an oversized set compiles whole — no policy is excluded — but not
// silently.
func TestDomainBucketBudgetRecord(t *testing.T) {
	policies := []model.Policy{widePolicy("p1"), widePolicy("p2"), widePolicy("p3")}
	snap, problems := Compile("d", policies, nil)
	if got := domainProblems(t, problems); len(got) != 1 {
		t.Fatalf("problems = %v, want one domain bucket record for 192 > %d",
			problems, model.MaxDomainDecisionBuckets)
	}
	if len(snap.Blocks) != 3 {
		t.Fatalf("blocks = %d: an informational record must exclude nobody", len(snap.Blocks))
	}
}

// bypassOnlyPolicy builds MaxBlocksPerPolicy FirstMatch blocks of one bypass
// rule each: blocks without buckets, so the block bound can fire alone.
func bypassOnlyPolicy(name string) model.Policy {
	p := model.Policy{Name: name, Domain: "d"}
	for bi := range model.MaxBlocksPerPolicy {
		p.Blocks = append(p.Blocks, model.Block{
			Name: fmt.Sprintf("b%d", bi), Mode: model.ModeFirstMatch,
			Rules: []model.Rule{{Name: "lift", Behavior: model.BehaviorBypass}},
		})
	}
	return p
}

// TestDomainBlockBudgetRecord isolates the scan bound: bypass-only blocks
// carry no buckets, proving the two domain bounds are independent.
func TestDomainBlockBudgetRecord(t *testing.T) {
	policies := make([]model.Policy, 0, 5)
	for pi := range 5 {
		policies = append(policies, bypassOnlyPolicy(fmt.Sprintf("p%d", pi)))
	}
	snap, problems := Compile("d", policies, nil)
	got := domainProblems(t, problems)
	if len(got) != 1 || !strings.Contains(got[0].Message, "blocks") {
		t.Fatalf("problems = %v, want one domain block record for 320 > %d",
			problems, model.MaxDomainBlocks)
	}
	if len(snap.Blocks) != 320 {
		t.Fatalf("blocks = %d, want all 320 compiled", len(snap.Blocks))
	}
}

// TestDomainWithinBoundsIsSilent keeps the record from firing on sets that
// fit: exactly at the per-policy budget twice over is still inside.
func TestDomainWithinBoundsIsSilent(t *testing.T) {
	_, problems := Compile("d", []model.Policy{widePolicy("p1"), widePolicy("p2")}, nil)
	if got := domainProblems(t, problems); len(got) != 0 {
		t.Fatalf("128 buckets and 2 blocks are within bounds; problems: %v", got)
	}
}
