package compile

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
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

// validPolicy builds the smallest policy that compiles: block "api" on the
// prefix /api/, with one rule "per-user" that counts 100 requests a minute by
// sub. A test writes its changes to the policy in its own body.
func validPolicy() model.Policy {
	return model.Policy{
		Domain: domain,
		Blocks: []model.Block{{
			Name:   "api",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
			Rules: []model.Rule{{
				Name:     "per-user",
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{rate(100, time.Minute)},
			}},
		}},
	}
}

// compileOne compiles p as the one policy of the test domain.
func compileOne(p model.Policy) (*Snapshot, []Problem) {
	return Compile(namespace, domain, &p)
}

// reasonsOf lists the reasons of problems in the order Compile reported them.
func reasonsOf(problems []Problem) []Reason {
	out := make([]Reason, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.Reason)
	}
	return out
}

func blockNames(blocks []Block) []string {
	out := make([]string, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, b.Name)
	}
	return out
}

// assertRejectedWhole checks the outcome of a generation with one defect: one
// problem, under the reason want, and no block in the snapshot. The diagnostics
// carry only root causes, so a second problem for one defect fails here too.
func assertRejectedWhole(t *testing.T, snap *Snapshot, problems []Problem, want Reason) {
	t.Helper()
	if got := reasonsOf(problems); !slices.Equal(got, []Reason{want}) {
		t.Errorf("Compile reasons = %v, want [%s]; problems: %v", got, want, problems)
	}
	if got := blockNames(snap.Blocks); len(got) != 0 {
		t.Errorf("Compile blocks = %v, want none: a blocking problem keeps the whole generation out", got)
	}
}

// Every replica compiling the same spec has to produce the same snapshot. The
// spec carries mappings, a fallback, and a group, so the key set and the
// extraction plan take part in the comparison.
func TestCompilingOneSpecTwiceGivesEqualSnapshots(t *testing.T) {
	spec := func() model.Policy {
		p := validPolicy()
		p.Mappings = []model.KeyMapping{
			{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
			{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalization: model.NormalizeLowercase},
		}
		p.Groups = []model.Group{{Name: "partners", Values: []string{"a", "b"}}}
		return p
	}

	first, firstProblems := compileOne(spec())
	second, secondProblems := compileOne(spec())

	if len(firstProblems)+len(secondProblems) != 0 {
		t.Fatalf("Compile problems = %v and %v, want none", firstProblems, secondProblems)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("Compile twice on one spec:\n first = %+v\nsecond = %+v", *first, *second)
	}
}

// The blocks are written in reverse alphabetical order, so a compiler that
// sorted them by name would put "api" first.
func TestCompileKeepsTheBlocksInAuthoredOrder(t *testing.T) {
	p := validPolicy()
	p.Blocks = []model.Block{
		{Name: "zzz-total", Rules: []model.Rule{{Name: "all", Rates: []model.Rate{rate(1000, time.Minute)}}}},
		p.Blocks[0],
	}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got, want := blockNames(snap.Blocks), []string{"zzz-total", "api"}; !slices.Equal(got, want) {
		t.Errorf("Compile blocks = %v, want %v", got, want)
	}
}

// The block and the rule of validPolicy set no mode, behavior, algorithm, or
// burst, so each of them takes its documented default, and the rate prefix
// names the GCRA default with the 60-second period.
func TestCompileResolvesTheDefaultsOfAMinimalRule(t *testing.T) {
	snap, problems := compileOne(validPolicy())

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if len(snap.Blocks) != 1 || len(snap.Blocks[0].Rules) != 1 || len(snap.Blocks[0].Rules[0].Rates) != 1 {
		t.Fatalf("Compile blocks = %+v, want one block with one rule of one rate", snap.Blocks)
	}
	block := snap.Blocks[0]
	if block.Mode != model.ModeAll {
		t.Errorf("Compile: mode of api = %q, want %q", block.Mode, model.ModeAll)
	}
	rule := block.Rules[0]
	if rule.Behavior != model.BehaviorEnforce {
		t.Errorf("Compile: behavior of api/per-user = %q, want %q", rule.Behavior, model.BehaviorEnforce)
	}
	window := rule.Rates[0]
	if got := window.Algorithm.Name(); got != "GCRA" {
		t.Errorf("Compile: algorithm of 100/min = %q, want GCRA", got)
	}
	if window.Window.Burst != 100 {
		t.Errorf("Compile: burst of 100/min = %d, want 100, a full bucket", window.Window.Burst)
	}
	if want := "rl:v1:{core-1-core/gateway.public}:api/per-user:gcra:60:"; window.Prefix != want {
		t.Errorf("Compile: prefix of 100/min = %q, want %q", window.Prefix, want)
	}
}

// A generation compiles whole or not at all: a FirstMatch cascade missing one
// rule would hand its traffic to the rules after it. So the healthy block "api"
// stays out of the snapshot beside the block "second" that names an unknown key.
func TestOneBlockingProblemKeepsEveryBlockOutOfTheSnapshot(t *testing.T) {
	p := validPolicy()
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

	assertRejectedWhole(t, snap, problems, ReasonUnresolvedKeyReference)
}

// The snapshot of an invalid generation still claims its domain, with the
// built-in keys, so the domain's requests are allowed rather than reported as
// an unknown domain.
func TestAnInvalidGenerationStillYieldsAUsableSnapshot(t *testing.T) {
	p := validPolicy()
	p.Blocks[0].Rules[0].Counters = []string{"ghost"}

	snap, problems := compileOne(p)

	if len(problems) == 0 {
		t.Fatal("Compile problems = none, want the unresolved counter axis ghost")
	}
	if snap.Domain != domain {
		t.Errorf("Compile: snapshot domain = %q, want %q", snap.Domain, domain)
	}
	if want := []string{"method", "path", "sub"}; !slices.Equal(snap.EffectiveKeys, want) {
		t.Errorf("Compile: effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
}

// Each row gives validPolicy one defect: a reference, a type, or a window the
// compiler cannot accept. A row with an unresolved name declares another entry
// of the same kind, so the name is refused beside a declared one.
func TestCompileRejectsADefectUnderItsReason(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Policy)
		want   Reason
	}{
		{"a matches key no mapping declares", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "tenant", Claim: "org_id"}}
			p.Blocks[0].Rules[0].Matches = []model.Predicate{{Key: "plan", Operator: model.OperatorExists}}
		}, ReasonUnresolvedKeyReference},
		{"a Contains predicate on a key no mapping declares", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: "roles", Operator: model.OperatorContains, Value: "admin"}}
		}, ReasonUnresolvedKeyReference},
		{"a counter axis no mapping declares", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "tenant", Claim: "org_id"}}
			p.Blocks[0].Rules[0].Counters = []string{"plan"}
		}, ReasonUnresolvedKeyReference},
		{"InGroup on a group the policy does not declare", func(p *model.Policy) {
			p.Groups = []model.Group{{Name: "partners", Values: []string{"a", "b"}}}
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "ghosts"}}
		}, ReasonUnresolvedGroupReference},
		{"replacedRules naming a rule the block lacks", func(p *model.Policy) {
			p.Blocks[0].Rules[0].ReplacedRules = []string{"ghost"}
		}, ReasonUnresolvedReplacedRules},
		{"replacedRules naming its own rule", func(p *model.Policy) {
			p.Blocks[0].Rules[0].ReplacedRules = []string{"per-user"}
		}, ReasonUnresolvedReplacedRules},
		{"Equals on an array-valued key", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray}}
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: "roles", Operator: model.OperatorEquals, Value: "admin"}}
		}, ReasonIncompatibleOperator},
		{"an array-valued key as a counter axis", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray}}
			p.Blocks[0].Rules[0].Counters = []string{"roles"}
		}, ReasonInvalidCounterAxis},
		// A second does not divide into 500001 whole microseconds.
		{"a GCRA rate of 500001 a second", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(500_001, time.Second)}
		}, ReasonInvalidWindow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(&p)

			snap, problems := compileOne(p)

			assertRejectedWhole(t, snap, problems, tc.want)
		})
	}
}

// With CEL limited to the name rule, the compiler is the only judge of how the
// fields of a policy relate. Each row gives validPolicy one structural defect,
// and the compiler answers with InvalidSpec rather than with a snapshot.
func TestCompileRejectsAStructuralDefectAsInvalidSpec(t *testing.T) {
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
				{Key: model.KeySub, Operator: "Matches", Value: "x"}}
		}},
		{"path in matches", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyPath, Operator: model.OperatorEquals, Value: "/x"}}
		}},
		{"token in matches", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyToken, Operator: model.OperatorExists}}
		}},
		{"method in matches", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeyMethod, Operator: model.OperatorEquals, Value: "GET"}}
		}},
		{"unknown path type", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Type = "Regex" }},
		{"relative path", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Path.Value = "api/" }},
		{"unknown method", func(p *model.Policy) { p.Blocks[0].Target.Routes[0].Methods = []string{"FETCH"} }},
		{"duplicate method", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Methods = []string{"GET", "GET"}
		}},
		{"no rates on a counting rule", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates = nil }},
		// FirstMatch, where a bypass names no replacedRules, so the rates are
		// the only defect of the rule.
		{"rates on a Bypass rule", func(p *model.Policy) {
			p.Blocks[0].Mode = model.ModeFirstMatch
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
		}},
		{"two rates with one period", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Rates = []model.Rate{rate(10, time.Minute), rate(20, time.Minute)}
		}},
		{"unknown algorithm", func(p *model.Policy) { p.Blocks[0].Rules[0].Rates[0].Algorithm = "SlidingLog" }},
		{"replacedRules under FirstMatch", func(p *model.Policy) {
			p.Blocks[0].Mode = model.ModeFirstMatch
			p.Blocks[0].Rules[0].ReplacedRules = []string{"per-user"}
		}},
		{"duplicate group", func(p *model.Policy) {
			p.Groups = []model.Group{{Name: "g", Values: []string{"a"}}, {Name: "g", Values: []string{"b"}}}
		}},
		{"unnamed group", func(p *model.Policy) { p.Groups = []model.Group{{Values: []string{"a"}}} }},
		{"empty In values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{{Key: model.KeySub, Operator: model.OperatorIn}}
		}},
		{"bypass under All without replacedRules", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass
			p.Blocks[0].Rules[0].Rates = nil
		}},
		{"exists with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeySub, Operator: model.OperatorExists, Value: "alice"}}
		}},
		{"equals with values", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeySub, Operator: model.OperatorEquals, Value: "a", Values: []string{"b"}}}
		}},
		{"in with a value", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Matches = []model.Predicate{
				{Key: model.KeySub, Operator: model.OperatorIn, Value: "a", Values: []string{"b"}}}
		}},
		{"bad mapping key name", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: "Bad-Name", Claim: "x"}}
		}},
		// 64 characters, one over the limit of 63.
		{"overlong mapping key", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: strings.Repeat("k", 64), Claim: "a"}}
		}},
		// A capture is a descriptor key and can serve as a counter axis, so it
		// carries the same cap as a mapping key: the name becomes a segment of
		// the counter key.
		{"overlong placeholder", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{
				Type:  model.PathTemplate,
				Value: "/api/{" + strings.Repeat("k", 64) + "}",
			}
		}},
		// A capture named after a built-in key is refused: the caller controls
		// the path, and {sub} would let it pick its own identity within the
		// block.
		{"placeholder named after the built-in sub", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{sub}"}
		}},
		{"placeholder named after the built-in path", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{path}"}
		}},
		{"placeholder named after the built-in method", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{method}"}
		}},
		{"placeholder named token", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{token}"}
		}},
		{"placeholder repeated within one template", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{id}/items/{id}"}
		}},
		// A segment is a literal or a single placeholder. A brace outside a
		// placeholder used to compile into a literal that only a request
		// carrying the braces verbatim matched, and the rule behind it was
		// silently never applied.
		{"placeholder with a prefix", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/x{id}"}
		}},
		{"placeholder with a suffix", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{id}x"}
		}},
		{"unclosed placeholder", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{id"}
		}},
		{"unopened placeholder", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/id}"}
		}},
		// A slash at the end or two in a row is refused as an empty segment.
		// It used to compile into an empty literal, and the template then
		// matched only a path with an empty segment in the same place.
		{"template with a trailing slash", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/orders/{id}/"}
		}},
		{"template with a double slash", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/a//b"}
		}},
		// The root alone is one empty segment; the root path is an Exact route.
		{"template of the root alone", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{Type: model.PathTemplate, Value: "/"}
		}},
		{"mapping over a built-in", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: model.KeyPath, Claim: "x"}}
		}},
		{"mapping over the built-in method", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: model.KeyMethod, Claim: "x"}}
		}},
		{"mapping named token", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: model.KeyToken, Claim: "x"}}
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
		{"sub declared twice", func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{
				{Key: model.KeySub, Claim: "azp"}, {Key: model.KeySub, Claim: "sub"}}
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
		{"unknown cost source", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{Source: "Header", Name: "limit"}
		}},
		{"empty cost parameter", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{Source: model.CostQueryParameter}
		}},
		{"cost parameter with a space", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{Source: model.CostQueryParameter, Name: "page size"}
		}},
		{"cost parameter of 65 characters", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{
				Source: model.CostQueryParameter, Name: strings.Repeat("l", 65)}
		}},
		{"negative default cost", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{
				Source: model.CostQueryParameter, Name: "limit", Default: -1}
		}},
		{"default cost above the ceiling", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{
				Source: model.CostQueryParameter, Name: "limit", Default: model.MaxCost + 1}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(&p)

			snap, problems := compileOne(p)

			assertRejectedWhole(t, snap, problems, ReasonInvalidSpec)
		})
	}
}

// Compile reports every problem it finds. A Bypass rule under All that carries
// rates and names no replacedRules has two defects, and each one is reported.
func TestCompileReportsEachDefectOfABypassRuleUnderAll(t *testing.T) {
	p := validPolicy()
	p.Blocks[0].Rules[0].Behavior = model.BehaviorBypass

	snap, problems := compileOne(p)

	if got, want := reasonsOf(problems), []Reason{ReasonInvalidSpec, ReasonInvalidSpec}; !slices.Equal(got, want) {
		t.Errorf("Compile reasons = %v, want %v; problems: %v", got, want, problems)
	}
	if got := blockNames(snap.Blocks); len(got) != 0 {
		t.Errorf("Compile blocks = %v, want none", got)
	}
}

// address is where a problem points: its block, its rule, and its reason.
type address struct {
	Block, Rule string
	Reason      Reason
}

func addressesOf(problems []Problem) []address {
	out := make([]address, 0, len(problems))
	for _, p := range problems {
		out = append(out, address{Block: p.Block, Rule: p.Rule, Reason: p.Reason})
	}
	return out
}

// A problem carries the address the status shows the author: a problem of a
// rule names its block and the rule, a problem of a block names the block
// alone, and a problem of the policy as a whole, such as the decision budget,
// names neither.
func TestCompileAddressesAProblemToItsBlockAndRule(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Policy)
		want   address
	}{
		{"a problem of a rule", func(p *model.Policy) {
			p.Blocks[0].Rules[0].Counters = []string{"ghost"}
		}, address{Block: "api", Rule: "per-user", Reason: ReasonUnresolvedKeyReference}},
		{"a problem of a block", func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path.Value = "api/"
		}, address{Block: "api", Reason: ReasonInvalidSpec}},
		// 33 rules of four windows each, 132 buckets.
		{"a problem of the policy", func(p *model.Policy) {
			*p = budgetPolicy(model.ModeAll, counting(33, ""))
		}, address{Reason: ReasonDomainBudgetExceeded}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(&p)

			_, problems := compileOne(p)

			if got := addressesOf(problems); !slices.Equal(got, []address{tc.want}) {
				t.Errorf("Compile problems point at %+v, want [%+v]; problems: %v", got, tc.want, problems)
			}
		})
	}
}

// No list of a policy is capped: what binds a generation is the bucket budget
// and the object size, not a count of blocks or of group values. The 100
// blocks have no target and one bucket each, so a decision collects all 100,
// inside the budget of 128.
func TestCompileAcceptsLongListsWithinTheBucketBudget(t *testing.T) {
	p := model.Policy{Domain: domain}
	for i := range 100 {
		p.Blocks = append(p.Blocks, model.Block{
			Name:  fmt.Sprintf("b%d", i),
			Rules: []model.Rule{{Name: "all", Rates: []model.Rate{rate(100, time.Minute)}}},
		})
	}
	p.Groups = []model.Group{{Name: "big", Values: make([]string, 4096)}}
	for i := range p.Groups[0].Values {
		p.Groups[0].Values[i] = fmt.Sprintf("c%d", i)
	}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if len(snap.Blocks) != 100 {
		t.Errorf("Compile: %d blocks, want 100", len(snap.Blocks))
	}
}

// A block without a target is the documented whole-domain form: it applies to
// the domain's entire traffic.
func TestABlockWithoutATargetCompilesWithNoRoutes(t *testing.T) {
	p := validPolicy()
	p.Blocks[0].Target = model.Target{}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
		t.Fatalf("Compile blocks = %v, want [api]", got)
	}
	if got := snap.Blocks[0].Routes; len(got) != 0 {
		t.Errorf("Compile: routes of api = %+v, want none", got)
	}
}

// The domain check stands in front of the key builder, which panics on an empty
// hash tag: an invalid domain is a compile problem, never a crash at request
// time.
func TestCompileRejectsAMalformedDomain(t *testing.T) {
	cases := []struct {
		name, domain string
	}{
		{"empty", ""},
		{"uppercase letters and an underscore", "Bad_Domain"},
		{"uppercase letters", "Gateway.public"},
		{"an underscore", "gateway_public"},
		{"a leading hyphen", "-x"},
		{"a slash", "a/b"},
		{"64 characters", strings.Repeat("a", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			p.Domain = tc.domain

			snap, problems := Compile(namespace, tc.domain, &p)

			assertRejectedWhole(t, snap, problems, ReasonInvalidSpec)
		})
	}
}

// A domain, a mapping key, and a placeholder of 63 characters sit on the bound
// the schema and the compiler share, and compile. TestCompileRejectsAMalformedDomain
// and TestCompileRejectsAStructuralDefectAsInvalidSpec refuse one character more.
func TestCompileAcceptsANameOfExactly63Characters(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		mutate func(*model.Policy)
	}{
		{"a domain", strings.Repeat("a", 63), func(*model.Policy) {}},
		{"a mapping key", domain, func(p *model.Policy) {
			p.Mappings = []model.KeyMapping{{Key: strings.Repeat("k", 63), Claim: "a"}}
		}},
		{"a placeholder", domain, func(p *model.Policy) {
			p.Blocks[0].Target.Routes[0].Path = model.PathMatch{
				Type:  model.PathTemplate,
				Value: "/api/{" + strings.Repeat("k", 63) + "}",
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			p.Domain = tc.domain
			tc.mutate(&p)

			snap, problems := Compile(namespace, tc.domain, &p)

			if len(problems) != 0 {
				t.Errorf("Compile problems = %v, want none", problems)
			}
			if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
				t.Errorf("Compile blocks = %v, want [api]", got)
			}
		})
	}
}

// The component's own namespace is the other half of the hash tag, and an
// empty one would scatter a decision across cluster slots.
func TestCompileRejectsAnEmptyNamespace(t *testing.T) {
	p := validPolicy()

	snap, problems := Compile("", domain, &p)

	assertRejectedWhole(t, snap, problems, ReasonInvalidSpec)
}

// A nil policy is a domain with nothing enforced: the built-in keys, no
// blocks, and no problems.
func TestCompileOfANilPolicyYieldsTheBuiltInKeysAlone(t *testing.T) {
	snap, problems := Compile(namespace, domain, nil)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got := blockNames(snap.Blocks); len(got) != 0 {
		t.Errorf("Compile blocks = %v, want none", got)
	}
	if want := []string{"method", "path", "sub"}; !slices.Equal(snap.EffectiveKeys, want) {
		t.Errorf("Compile: effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
	want := []KeyExtraction{
		{Key: "sub", Path: []string{"sub"}, Type: model.ValueString, Normalization: model.NormalizeLowercase},
	}
	if !reflect.DeepEqual(snap.Extraction, want) {
		t.Errorf("Compile: extraction = %+v, want %+v", snap.Extraction, want)
	}
}

// The snapshot is immutable: the model's counters and claimPath slices are
// copied, not shared, so a write to the model after Compile reaches neither.
func TestMutatingThePolicyAfterCompileLeavesTheSnapshotUnchanged(t *testing.T) {
	p := validPolicy()
	p.Mappings = []model.KeyMapping{{Key: "plan", ClaimPath: []string{"a", "b"}}}
	snap, problems := compileOne(p)
	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if len(snap.Blocks) != 1 || len(snap.Blocks[0].Rules) != 1 || len(snap.Extraction) != 2 {
		t.Fatalf("Compile = %+v, want one block of one rule and the extraction of sub and plan", *snap)
	}

	p.Blocks[0].Rules[0].Counters[0] = "mutated"
	p.Mappings[0].ClaimPath[0] = "mutated"

	if got := snap.Blocks[0].Rules[0].Counters; !slices.Equal(got, []string{"sub"}) {
		t.Errorf("snapshot counters of api/per-user = %v, want [sub]", got)
	}
	if got := snap.Extraction[1].Path; !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("snapshot extraction path of plan = %v, want [a b]", got)
	}
}

// Inside its block a capture wins over the mapped key of the same name, and
// the author is told so without the generation being refused. The other
// mapping and the group stay silent, so the one problem is the shadowing.
func TestACaptureShadowingAMappedKeyIsReportedWithoutBlocking(t *testing.T) {
	p := validPolicy()
	p.Mappings = []model.KeyMapping{
		{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalization: model.NormalizeLowercase},
	}
	p.Groups = []model.Group{{Name: "partners", Values: []string{"a", "b"}}}
	p.Blocks[0].Target.Routes = append(p.Blocks[0].Target.Routes, model.Route{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/tenants/{tenant}/orders"},
	})

	snap, problems := compileOne(p)

	if len(problems) != 1 {
		t.Fatalf("Compile problems = %v, want one CaptureShadowsMappedKey", problems)
	}
	if got := problems[0].Reason; got != ReasonCaptureShadowsMappedKey {
		t.Errorf("Compile: problem reason = %s, want %s", got, ReasonCaptureShadowsMappedKey)
	}
	if problems[0].Blocking {
		t.Errorf("Compile: problem %+v is blocking, want informational", problems[0])
	}
	if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
		t.Fatalf("Compile blocks = %v, want [api]", got)
	}
	if got := snap.Blocks[0].Captures; !slices.Equal(got, []string{"tenant"}) {
		t.Errorf("Compile: captures of api = %v, want [tenant]", got)
	}
}

// policyCountingByOrderID returns validPolicy with block "api" on the template
// /api/v1/orders/{orderId}/items and its rule counting by the capture orderId.
func policyCountingByOrderID() model.Policy {
	p := validPolicy()
	p.Blocks[0].Target.Routes = []model.Route{{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/orders/{orderId}/items"},
	}}
	p.Blocks[0].Rules[0].Counters = []string{"orderId"}
	return p
}

// A capture is a key of the block whose route declares it, and the
// domain-wide key set does not list it.
func TestACaptureResolvesAsACounterAxisOfItsOwnBlock(t *testing.T) {
	snap, problems := compileOne(policyCountingByOrderID())

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
		t.Errorf("Compile blocks = %v, want [api]", got)
	}
	if want := []string{"method", "path", "sub"}; !slices.Equal(snap.EffectiveKeys, want) {
		t.Errorf("Compile: effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
}

// One compilation holds block api, whose template declares orderId, and block
// stranger, which only counts by it. The single problem names stranger, and
// api stands as its control.
func TestACaptureDoesNotResolveInAnotherBlock(t *testing.T) {
	p := policyCountingByOrderID()
	p.Blocks = append(p.Blocks, model.Block{
		Name:  "stranger",
		Rules: []model.Rule{{Name: "r", Counters: []string{"orderId"}, Rates: []model.Rate{rate(1, time.Minute)}}},
	})

	_, problems := compileOne(p)

	if len(problems) != 1 {
		t.Fatalf("Compile problems = %v, want one UnresolvedKeyReference in block stranger", problems)
	}
	if got := problems[0]; got.Block != "stranger" || got.Reason != ReasonUnresolvedKeyReference {
		t.Errorf("Compile problem = %+v, want an UnresolvedKeyReference in block stranger", got)
	}
}

// A capture shadows the array-valued mapping of its name inside its block,
// where the key is a scalar and Equals applies to it. One compilation holds
// block api, whose template captures roles, and block stranger, which has no
// such capture: Equals on roles is refused in stranger alone, and api reports
// only the informational shadowing.
func TestEqualsAppliesToAnArrayKeyInTheBlockWhoseCaptureShadowsIt(t *testing.T) {
	equalsAdmin := []model.Predicate{{Key: "roles", Operator: model.OperatorEquals, Value: "admin"}}
	p := validPolicy()
	p.Mappings = []model.KeyMapping{{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray}}
	p.Blocks[0].Target.Routes = []model.Route{{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/{roles}"}}}
	p.Blocks[0].Rules[0].Matches = equalsAdmin
	p.Blocks = append(p.Blocks, model.Block{
		Name:  "stranger",
		Rules: []model.Rule{{Name: "r", Matches: equalsAdmin, Rates: []model.Rate{rate(1, time.Minute)}}},
	})

	_, problems := compileOne(p)

	want := []address{
		{Block: "api", Reason: ReasonCaptureShadowsMappedKey},
		{Block: "stranger", Rule: "r", Reason: ReasonIncompatibleOperator},
	}
	if got := addressesOf(problems); !slices.Equal(got, want) {
		t.Errorf("Compile problems point at %+v, want %+v; problems: %v", got, want, problems)
	}
}

// The key pattern admits camelCase: {orderId} is the shape the
// specification's own examples use.
func TestCompileAdmitsCamelCaseKeyNames(t *testing.T) {
	p := validPolicy()
	p.Mappings = []model.KeyMapping{{Key: "tenantId", Claim: "org_id"}}
	p.Blocks[0].Rules[0].Counters = []string{"tenantId"}
	p.Blocks[0].Target.Routes = []model.Route{{
		Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/orders/{orderId}"},
	}}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
		t.Fatalf("Compile blocks = %v, want [api]", got)
	}
	if got := snap.Blocks[0].Captures; !slices.Equal(got, []string{"orderId"}) {
		t.Errorf("Compile: captures of api = %v, want [orderId]", got)
	}
}

// Group indirection ends at compile time: the predicate itself carries the
// values, so a request never looks a group up.
func TestAnInGroupPredicateCarriesTheValuesOfItsGroup(t *testing.T) {
	p := validPolicy()
	p.Groups = []model.Group{{Name: "partners", Values: []string{"a", "b"}}}
	p.Blocks[0].Rules[0].Matches = []model.Predicate{
		{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "partners"},
	}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if len(snap.Blocks) != 1 || len(snap.Blocks[0].Rules) != 1 || len(snap.Blocks[0].Rules[0].Matches) != 1 {
		t.Fatalf("Compile blocks = %+v, want one block of one rule with one predicate", snap.Blocks)
	}
	want := map[string]struct{}{"a": {}, "b": {}}
	if got := snap.Blocks[0].Rules[0].Matches[0].Values; !maps.Equal(got, want) {
		t.Errorf("Compile: values of InGroup partners = %v, want %v", got, want)
	}
}

// The extraction plan reads the built-in sub first and the mapped keys after
// it in authored order, with the claim and fallback paths split on dots and
// the unset type and normalization at their defaults. The domain key set holds
// the built-ins and the mapped keys, sorted.
func TestCompileDerivesTheDomainKeysFromTheMappings(t *testing.T) {
	p := validPolicy()
	p.Mappings = []model.KeyMapping{
		{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalization: model.NormalizeLowercase},
	}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	wantExtraction := []KeyExtraction{
		{Key: "sub", Path: []string{"sub"}, Type: model.ValueString, Normalization: model.NormalizeLowercase},
		{Key: "roles", Path: []string{"realm_access", "roles"}, Type: model.ValueStringArray,
			Normalization: model.NormalizeNone},
		{Key: "tenant", Path: []string{"org_id"}, Type: model.ValueString, Normalization: model.NormalizeLowercase,
			Fallbacks: [][]string{{"sub"}}},
	}
	if !reflect.DeepEqual(snap.Extraction, wantExtraction) {
		t.Errorf("Compile: extraction =\n%+v\nwant\n%+v", snap.Extraction, wantExtraction)
	}
	if want := []string{"method", "path", "roles", "sub", "tenant"}; !slices.Equal(snap.EffectiveKeys, want) {
		t.Errorf("Compile: effective keys = %v, want %v", snap.EffectiveKeys, want)
	}
}

// A mapping of sub replaces the built-in extraction rather than adding a
// second one, and its own normalization applies, None by default.
func TestAMappingOfSubReplacesTheBuiltInExtraction(t *testing.T) {
	p := validPolicy()
	p.Mappings = []model.KeyMapping{{Key: model.KeySub, Claim: "azp"}}

	snap, problems := compileOne(p)

	if len(problems) != 0 {
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	want := []KeyExtraction{
		{Key: "sub", Path: []string{"azp"}, Type: model.ValueString, Normalization: model.NormalizeNone},
	}
	if !reflect.DeepEqual(snap.Extraction, want) {
		t.Errorf("Compile: extraction = %+v, want %+v", snap.Extraction, want)
	}
}

// The specification's two-block example in miniature: a FirstMatch cascade
// with Bypass and Shadow steps over an additive block.
func TestTheSpecificationCascadeExampleCompiles(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Values: []string{"t1", "t2"}}},
		Blocks: []model.Block{
			{
				Name: "cascade",
				Mode: model.ModeFirstMatch,
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/invoices/"}}}},
				Rules: []model.Rule{
					{Name: "internal", Behavior: model.BehaviorBypass,
						Matches: []model.Predicate{
							{Key: model.KeySub, Operator: model.OperatorEquals, Value: "prometheus"}}},
					{Name: "trial",
						Matches:  []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "trial"}},
						Behavior: model.BehaviorShadow, Counters: []string{model.KeySub},
						Rates: []model.Rate{rate(10, time.Minute)}},
					{Name: "everyone", Counters: []string{model.KeySub},
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
		t.Fatalf("Compile problems = %v, want none", problems)
	}
	if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"cascade", "total"}) {
		t.Fatalf("Compile blocks = %v, want [cascade total]", got)
	}
	cascade := snap.Blocks[0]
	if cascade.Mode != model.ModeFirstMatch {
		t.Errorf("Compile: mode of cascade = %q, want %q", cascade.Mode, model.ModeFirstMatch)
	}
	if len(cascade.Rules) != 3 || len(cascade.Rules[2].Rates) != 2 {
		t.Fatalf("Compile: rules of cascade = %+v, want three, the last with two rates", cascade.Rules)
	}
	if bypass := cascade.Rules[0]; bypass.Behavior != model.BehaviorBypass || bypass.Rates != nil {
		t.Errorf("Compile: rule internal = %+v, want a Bypass rule without rates", bypass)
	}
	daily := cascade.Rules[2].Rates[1]
	if got := daily.Algorithm.Name(); got != "FixedWindow" {
		t.Errorf("Compile: algorithm of the daily quota = %q, want FixedWindow", got)
	}
	if daily.Window.Burst != 0 {
		t.Errorf("Compile: burst of the daily quota = %d, want 0, since a fixed window has no burst", daily.Window.Burst)
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

// The worst case of a decision is bounded by 128 buckets, and a generation
// over it is refused: the alternative is a generation whose widest paths the
// runtime backstop refuses outright.
func TestCompileEnforcesTheDecisionBucketBudget(t *testing.T) {
	t.Run("All over the budget is refused", func(t *testing.T) {
		// 33 rules x 4 rates = 132 buckets.
		snap, problems := compileOne(budgetPolicy(model.ModeAll, counting(33, "")))

		assertRejectedWhole(t, snap, problems, ReasonDomainBudgetExceeded)
	})
	t.Run("All one bucket over the budget is refused", func(t *testing.T) {
		// 32 rules x 4 rates + 1 = 129 buckets.
		rules := append(counting(32, ""), model.Rule{Name: "extra", Rates: []model.Rate{rate(100, time.Minute)}})

		snap, problems := compileOne(budgetPolicy(model.ModeAll, rules))

		assertRejectedWhole(t, snap, problems, ReasonDomainBudgetExceeded)
	})
	t.Run("All at exactly the budget compiles", func(t *testing.T) {
		// 32 rules x 4 rates = 128 buckets.
		snap, problems := compileOne(budgetPolicy(model.ModeAll, counting(32, "")))

		if len(problems) != 0 {
			t.Fatalf("Compile problems = %v, want none", problems)
		}
		if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"b"}) {
			t.Errorf("Compile blocks = %v, want [b]", got)
		}
		if snap.DecisionBuckets != 128 {
			t.Errorf("Compile: DecisionBuckets = %d, want 128", snap.DecisionBuckets)
		}
	})
	t.Run("FirstMatch counts its widest rule alone", func(t *testing.T) {
		// 33 rules of 4 rates, of which one decision applies one.
		snap, problems := compileOne(budgetPolicy(model.ModeFirstMatch, counting(33, "")))

		if len(problems) != 0 {
			t.Fatalf("Compile problems = %v, want none", problems)
		}
		if snap.DecisionBuckets != 4 {
			t.Errorf("Compile: DecisionBuckets = %d, want 4", snap.DecisionBuckets)
		}
	})
	t.Run("FirstMatch counts every shadow rule ahead of the widest", func(t *testing.T) {
		// 32 shadow rules x 4 rates + 4 for the terminating rule = 132 buckets.
		rules := append(counting(32, model.BehaviorShadow), model.Rule{Name: "last", Rates: fourRates()})

		snap, problems := compileOne(budgetPolicy(model.ModeFirstMatch, rules))

		assertRejectedWhole(t, snap, problems, ReasonDomainBudgetExceeded)
	})
	t.Run("blocks add up past the budget", func(t *testing.T) {
		// Two blocks of 17 rules x 4 rates = 136 buckets.
		p := budgetPolicy(model.ModeAll, counting(17, ""))
		second := budgetPolicy(model.ModeAll, counting(17, "")).Blocks[0]
		second.Name = "b2"
		p.Blocks = append(p.Blocks, second)

		snap, problems := compileOne(p)

		assertRejectedWhole(t, snap, problems, ReasonDomainBudgetExceeded)
	})
}

// policyWithCost returns validPolicy with the cost entry on its one route and
// the window of its one rule a fixed window as large as the ceiling of a
// cost, so that no default is above the window's capacity.
func policyWithCost(cost model.RouteCost) model.Policy {
	p := validPolicy()
	p.Blocks[0].Target.Routes[0].Cost = &cost
	p.Blocks[0].Rules[0].Rates = []model.Rate{{Requests: model.MaxCost, Period: time.Hour, Algorithm: "FixedWindow"}}
	return p
}

// A cost entry at the edge of what the schema admits compiles into the route,
// with an absent default resolved to one.
func TestCompileCarriesTheCostEntryOfARoute(t *testing.T) {
	cases := []struct {
		name  string
		entry model.RouteCost
		want  Cost
	}{
		{"no default", model.RouteCost{Source: model.CostQueryParameter, Name: "limit"},
			Cost{Parameter: "limit", Default: 1}},
		{"brackets in the name", model.RouteCost{Source: model.CostQueryParameter, Name: "page[size]", Default: 20},
			Cost{Parameter: "page[size]", Default: 20}},
		{"a name of 64 characters", model.RouteCost{Source: model.CostQueryParameter, Name: strings.Repeat("l", 64)},
			Cost{Parameter: strings.Repeat("l", 64), Default: 1}},
		{"the ceiling as the default", model.RouteCost{
			Source: model.CostQueryParameter, Name: "page.size", Default: model.MaxCost},
			Cost{Parameter: "page.size", Default: model.MaxCost}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap, problems := compileOne(policyWithCost(tc.entry))

			if len(problems) != 0 {
				t.Fatalf("Compile(cost %+v) problems = %v, want none", tc.entry, problems)
			}
			if got := snap.Blocks[0].Routes[0].Cost; got == nil || *got != tc.want {
				t.Errorf("Compile(cost %+v): route cost = %+v, want %+v", tc.entry, got, tc.want)
			}
		})
	}
}

// A route whose default cost is above the capacity of a window of its block
// is reported under CostExceedsCapacity, at the block and the rule of the
// window, and the generation stays valid. The capacity is the burst of a GCRA
// window and the requests of a fixed one; a default equal to it is no
// problem.
func TestADefaultCostAboveAWindowCapacityIsReportedWithoutBlocking(t *testing.T) {
	cases := []struct {
		name         string
		defaultCost  int64
		rate         model.Rate
		wantProblems []Reason
	}{
		{"a default equal to the burst", 5,
			model.Rate{Requests: 100, Period: time.Minute, Burst: 5}, []Reason{}},
		{"a default one above the burst", 6,
			model.Rate{Requests: 100, Period: time.Minute, Burst: 5}, []Reason{ReasonCostExceedsCapacity}},
		{"a default equal to the requests of a fixed window", 100,
			model.Rate{Requests: 100, Period: time.Minute, Algorithm: "FixedWindow"}, []Reason{}},
		{"a default one above the requests of a fixed window", 101,
			model.Rate{Requests: 100, Period: time.Minute, Algorithm: "FixedWindow"},
			[]Reason{ReasonCostExceedsCapacity}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			p.Blocks[0].Target.Routes[0].Cost = &model.RouteCost{
				Source: model.CostQueryParameter, Name: "limit", Default: tc.defaultCost}
			p.Blocks[0].Rules[0].Rates = []model.Rate{tc.rate}

			snap, problems := compileOne(p)

			if got := reasonsOf(problems); !slices.Equal(got, tc.wantProblems) {
				t.Errorf("Compile reasons = %v, want %v; problems: %v", got, tc.wantProblems, problems)
			}
			for _, problem := range problems {
				if problem.Blocking || problem.Block != "api" || problem.Rule != "per-user" {
					t.Errorf("Compile problem %+v, want an informational one at api/per-user", problem)
				}
			}
			if got := blockNames(snap.Blocks); !slices.Equal(got, []string{"api"}) {
				t.Errorf("Compile blocks = %v, want [api]", got)
			}
		})
	}
}
