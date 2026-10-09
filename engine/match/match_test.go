package match

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

const domain = "gateway.public"

// mustCompile builds a snapshot and fails the test on any problem: matcher
// tests run on valid domains only.
func mustCompile(t *testing.T, p model.Policy) *compile.Snapshot {
	t.Helper()
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	return snap
}

func minuteRate() []model.Rate {
	return []model.Rate{{Requests: 100, Period: time.Minute}}
}

// request and evaluate run both phases in one call: every scenario in this
// file exercises the target phase and the rule phase together.
type request struct {
	Path   string
	Method string
	Keys   map[string][]string

	// Cost is the request's own cost; zero reads as one.
	Cost int64
}

func evaluate(snap *compile.Snapshot, r request) Result {
	cost := r.Cost
	if cost == 0 {
		cost = 1
	}
	return Match(snap, r.Path, r.Method).Evaluate(r.Keys, cost)
}

func ruleNames(r Result) []string {
	out := make([]string, len(r.Rules))
	for i, m := range r.Rules {
		out[i] = m.Rule
	}
	return out
}

// matchedBlocks lists the block of every applied rule, in result order.
func matchedBlocks(r Result) []string {
	out := make([]string, len(r.Rules))
	for i, m := range r.Rules {
		out[i] = m.Block
	}
	return out
}

func blockNames(blocks []*compile.Block) []string {
	out := make([]string, 0, len(blocks))
	for _, block := range blocks {
		out = append(out, block.Name)
	}
	return out
}

func targetNames(targets []Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.Block.Name)
	}
	return out
}

// Each block carries one rule, so the blocks of the applied rules are the
// blocks the target phase selected.
func TestMatchTargetsABlockByItsRoute(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{
			{Name: "exact", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathExact, Value: "/health"}}}},
				Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
			{Name: "prefix", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}, Methods: []string{"POST"}}}},
				Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
			{Name: "tpl", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}"}}}},
				Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
		},
	}
	snap := mustCompile(t, p)

	cases := []struct {
		name   string
		req    request
		blocks []string
	}{
		{"exact hit", request{Path: "/health", Method: "GET"}, []string{"exact"}},
		{"exact miss on suffix", request{Path: "/healthz", Method: "GET"}, nil},
		{"query is stripped", request{Path: "/health?verbose=1", Method: "GET"}, []string{"exact"}},
		{"prefix with method", request{Path: "/api/x", Method: "POST"}, []string{"prefix"}},
		{"prefix wrong method", request{Path: "/api/x", Method: "GET"}, nil},
		{"template hit", request{Path: "/api/orders/42", Method: "GET"}, []string{"tpl"}},
		{"template empty segment", request{Path: "/api/orders/", Method: "GET"}, nil},
		{"template extra segment", request{Path: "/api/orders/42/items", Method: "GET"}, nil},
		{"additive blocks", request{Path: "/api/orders/42", Method: "POST"}, []string{"prefix", "tpl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchedBlocks(evaluate(snap, tc.req))

			if !slices.Equal(got, tc.blocks) {
				t.Errorf("%s %s matched blocks %v, want %v", tc.req.Method, tc.req.Path, got, tc.blocks)
			}
		})
	}
}

// prefixTargets reports whether a block whose only route is a Prefix route of
// value targets a GET request for path.
func prefixTargets(t *testing.T, value, path string) bool {
	t.Helper()
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name:   "b",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: value}}}},
		Rules:  []model.Rule{{Name: "r", Rates: minuteRate()}},
	}}})
	return !Match(snap, path, "GET").Empty()
}

// Prefix is a prefix on a segment boundary, the contract the CRD and the spec
// state: a value without a trailing slash covers itself and its sub-paths, and
// never a neighboring resource that happens to share its first characters.
func TestPrefixMatchesOnASegmentBoundary(t *testing.T) {
	cases := []struct {
		value, path string
		want        bool
	}{
		{"/api/v1/orders", "/api/v1/orders", true},
		{"/api/v1/orders", "/api/v1/orders/42", true},
		{"/api/v1/orders", "/api/v1/orders/", true},
		{"/api/v1/orders", "/api/v1/orders-archive", false},
		{"/api/v1/orders", "/api/v1/ordersXYZ", false},
		{"/api/v1/orders", "/api/v1/orders.json", false},
		{"/api/v1/orders", "/api/v1/order", false},
		{"/api/v1/orders/", "/api/v1/orders/42", true},
		{"/api/v1/orders/", "/api/v1/orders", false},
		{"/", "/anything/at/all", true},
		{"/", "/", true},
	}
	for _, tc := range cases {
		if got := prefixTargets(t, tc.value, tc.path); got != tc.want {
			t.Errorf("Prefix %q targets %q = %t, want %t", tc.value, tc.path, got, tc.want)
		}
	}
}

// The blocks of two neighboring resources share their first characters, and a
// request under the second one reaches its block alone.
func TestARequestUnderANeighboringPrefixReachesOnlyItsOwnBlock(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{Name: "orders", Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/v1/orders"}}}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
		{Name: "archive", Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/v1/orders-archive"}}}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
	}})

	got := matchedBlocks(evaluate(snap, request{Path: "/api/v1/orders-archive/7", Method: "GET"}))

	if want := []string{"archive"}; !slices.Equal(got, want) {
		t.Errorf("GET /api/v1/orders-archive/7 matched blocks %v, want %v", got, want)
	}
}

func TestAPredicateHoldsPerItsOperator(t *testing.T) {
	mappings := []model.KeyMapping{
		{Key: "roles", Claim: "roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org"},
	}
	withPredicate := func(c model.Predicate) model.Policy {
		return model.Policy{
			Domain:   domain,
			Mappings: mappings,
			Groups:   []model.Group{{Name: "vip", Values: []string{"alice", "bob"}}},
			Blocks: []model.Block{{Name: "b",
				Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
				Rules:  []model.Rule{{Name: "r", Matches: []model.Predicate{c}, Rates: minuteRate()}}}},
		}
	}

	cases := []struct {
		name string
		cond model.Predicate
		keys map[string][]string
		want []string
	}{
		{"equals hit", model.Predicate{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{model.KeySub: {"alice"}}, []string{"r"}},
		{"equals miss", model.Predicate{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{model.KeySub: {"bob"}}, nil},
		{"equals on absent key", model.Predicate{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{}, nil},
		{"equals on two values", model.Predicate{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{model.KeySub: {"alice", "bob"}}, nil},
		{"in hit", model.Predicate{Key: model.KeySub, Operator: model.OperatorIn, Values: []string{"a", "b"}},
			map[string][]string{model.KeySub: {"b"}}, []string{"r"}},
		{"in miss", model.Predicate{Key: model.KeySub, Operator: model.OperatorIn, Values: []string{"a", "b"}},
			map[string][]string{model.KeySub: {"c"}}, nil},
		{"ingroup hit", model.Predicate{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "vip"},
			map[string][]string{model.KeySub: {"bob"}}, []string{"r"}},
		{"ingroup miss", model.Predicate{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "vip"},
			map[string][]string{model.KeySub: {"eve"}}, nil},
		{"ingroup on absent key", model.Predicate{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "vip"},
			map[string][]string{}, nil},
		{"contains on array", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			map[string][]string{"roles": {"user", "admin"}}, []string{"r"}},
		{"contains never substring", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			map[string][]string{"roles": {"administrator"}}, nil},
		{"contains on absent key", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			map[string][]string{}, nil},
		{"exists", model.Predicate{Key: "tenant", Operator: model.OperatorExists},
			map[string][]string{"tenant": {"acme"}}, []string{"r"}},
		{"exists on absent", model.Predicate{Key: "tenant", Operator: model.OperatorExists},
			map[string][]string{}, nil},
		{"notexists on absent", model.Predicate{Key: "tenant", Operator: model.OperatorDoesNotExist},
			map[string][]string{}, []string{"r"}},
		{"notexists on present", model.Predicate{Key: "tenant", Operator: model.OperatorDoesNotExist},
			map[string][]string{"tenant": {"acme"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := mustCompile(t, withPredicate(tc.cond))

			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: tc.keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(%v) matched %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}

// A counter axis keys the bucket, so a rule matches only when each of its axes
// carries exactly one value: an absent axis is the mechanism by which a
// per-client rule skips anonymous traffic, and an axis with several values is
// an ambiguity the matcher refuses to resolve by guessing. The axis-less rule
// "total" matches every request and is the control of each row.
func TestARuleMatchesOnlyWhenEachCounterAxisHasOneValue(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "per-user", Counters: []string{model.KeySub}, Rates: minuteRate()},
				{Name: "total", Rates: minuteRate()},
			}}},
	})

	cases := []struct {
		name string
		keys map[string][]string
		want []string
	}{
		{"no sub", nil, []string{"total"}},
		{"one sub", map[string][]string{model.KeySub: {"alice"}}, []string{"per-user", "total"}},
		{"two sub values", map[string][]string{model.KeySub: {"a", "b"}}, []string{"total"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: tc.keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(%v) matched %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}

// The override "enterprise" replaces "base" only for the requests it matches
// itself.
func TestUnderAllAMatchedRuleSuppressesTheRulesItReplaces(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "enterprise", Values: []string{"corp"}}},
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "base", Counters: []string{model.KeySub}, Rates: minuteRate()},
				{Name: "enterprise",
					Matches:       []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "enterprise"}},
					Counters:      []string{model.KeySub},
					Rates:         []model.Rate{{Requests: 1000, Period: time.Minute}},
					ReplacedRules: []string{"base"}},
			}}},
	})

	cases := []struct {
		name, sub string
		want      []string
	}{
		{"a client in the group of the override", "corp", []string{"enterprise"}},
		{"a client outside it", "alice", []string{"base"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := map[string][]string{model.KeySub: {tc.sub}}

			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(sub=%s) matched %v, want %v", tc.sub, got, tc.want)
			}
		})
	}
}

// A group is bound to no key: the predicate that names it decides which
// key's value is looked up in it.
func TestInGroupMatchesTheKeyOfItsPredicate(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain:   domain,
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org_id", Normalization: model.NormalizeLowercase}},
		Groups:   []model.Group{{Name: "partners", Values: []string{"acme"}}},
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "partners",
					Matches:  []model.Predicate{{Key: "tenant", Operator: model.OperatorInGroup, Value: "partners"}},
					Counters: []string{model.KeySub},
					Rates:    minuteRate()},
			}}},
	})

	cases := []struct {
		name string
		keys map[string][]string
		want []string
	}{
		{"a tenant in the group", map[string][]string{model.KeySub: {"alice"}, "tenant": {"acme"}},
			[]string{"partners"}},
		{"a sub in the group with a tenant outside it", map[string][]string{model.KeySub: {"acme"}, "tenant": {"globex"}},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: tc.keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(%v) matched %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}

// A shadow rule never changes the verdict, so its replacedRules suppresses
// nothing: the enforcing rule it names stays matched beside it. The shadow
// used to remove the rule it named, and a trial of a narrower limit switched
// the live one off.
func TestAShadowRuleSuppressesNoneOfTheRulesItReplaces(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Rules: []model.Rule{
				{Name: "base", Counters: []string{model.KeySub}, Rates: minuteRate()},
				{Name: "trial", Behavior: model.BehaviorShadow, Counters: []string{model.KeySub},
					Rates: []model.Rate{{Requests: 10, Period: time.Minute}}, ReplacedRules: []string{"base"}},
			}}},
	})

	got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET",
		Keys: map[string][]string{model.KeySub: {"alice"}}}))

	if want := []string{"base", "trial"}; !slices.Equal(got, want) {
		t.Errorf("Evaluate(sub=alice) matched %v, want %v", got, want)
	}
}

// A block without a target is the whole-domain form: it matches any path under
// any method.
func TestABlockWithoutATargetMatchesEveryRequest(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Rules: []model.Rule{{Name: "total", Rates: minuteRate()}}}},
	})

	for _, req := range []request{
		{Path: "/anything", Method: "GET"},
		{Path: "/", Method: "DELETE"},
	} {
		if got := ruleNames(evaluate(snap, req)); !slices.Equal(got, []string{"total"}) {
			t.Errorf("%s %s matched %v, want [total]", req.Method, req.Path, got)
		}
	}
}

// A matched bypass under All is a targeted exemption: it frees the request
// from the rules it names and from nothing else.
func TestBypassUnderAllExemptsNamedRulesOnly(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "vip", Values: []string{"corp"}}},
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "base", Counters: []string{model.KeySub}, Rates: minuteRate()},
				{Name: "guard", Rates: minuteRate()},
				{Name: "vip-exempt", Behavior: model.BehaviorBypass, ReplacedRules: []string{"base"},
					Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "vip"}}},
			}}},
	})

	cases := []struct {
		name, sub string
		want      []string
	}{
		{"a client the bypass matches", "corp", []string{"guard"}},
		{"a client it does not match", "alice", []string{"base", "guard"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := map[string][]string{model.KeySub: {tc.sub}}

			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(sub=%s) matched %v, want %v", tc.sub, got, tc.want)
			}
		})
	}
}

// appliedRule is the part of a matched rule a cascade decides: which rule
// applies, and whether it only shadows.
type appliedRule struct {
	Rule   string
	Shadow bool
}

func appliedRules(r Result) []appliedRule {
	out := make([]appliedRule, len(r.Rules))
	for i, m := range r.Rules {
		out[i] = appliedRule{Rule: m.Rule, Shadow: m.Shadow}
	}
	return out
}

// A FirstMatch cascade walks its rules in authored order: a matched bypass ends
// it with nothing counted, a matched shadow rule counts without ending it, and
// a matched enforcing rule counts and ends it.
func TestAFirstMatchCascadeEndsAtTheFirstMatchedRuleThatIsNotShadow(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Values: []string{"t1"}}},
		Blocks: []model.Block{{Name: "cascade", Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "internal", Behavior: model.BehaviorBypass,
					Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorEquals, Value: "prometheus"}}},
				{Name: "trial", Behavior: model.BehaviorShadow, Counters: []string{model.KeySub},
					Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "trial"}},
					Rates:   []model.Rate{{Requests: 10, Period: time.Minute}}},
				{Name: "everyone", Counters: []string{model.KeySub}, Rates: minuteRate()},
			}}},
	})

	cases := []struct {
		name, sub string
		want      []appliedRule
	}{
		{"a client the bypass matches", "prometheus", nil},
		{"a client the shadow rule matches", "t1", []appliedRule{{"trial", true}, {"everyone", false}}},
		{"any other client", "alice", []appliedRule{{"everyone", false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := map[string][]string{model.KeySub: {tc.sub}}

			got := appliedRules(evaluate(snap, request{Path: "/q", Method: "GET", Keys: keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(sub=%s) applied %+v, want %+v", tc.sub, got, tc.want)
			}
		})
	}
}

// A rule whose counter axis is absent does not match, so a FirstMatch cascade
// passes the request on to the next rule instead of ending there.
func TestAFirstMatchRuleWithoutItsCounterAxisPassesTheRequestOn(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "cascade", Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "per-user", Counters: []string{model.KeySub}, Rates: minuteRate()},
				{Name: "anonymous", Rates: minuteRate()},
			}}},
	})

	cases := []struct {
		name string
		keys map[string][]string
		want []string
	}{
		{"a request without a sub", nil, []string{"anonymous"}},
		{"a request with a sub", map[string][]string{model.KeySub: {"alice"}}, []string{"per-user"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleNames(evaluate(snap, request{Path: "/x", Method: "GET", Keys: tc.keys}))

			if !slices.Equal(got, tc.want) {
				t.Errorf("Evaluate(%v) matched %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}

// The method is a counter axis like any other built-in key: the request's
// method keys the bucket, so each method counts apart.
func TestTheMethodAxisKeysTheBucketByTheRequestsMethod(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules:  []model.Rule{{Name: "per-method", Counters: []string{model.KeyMethod}, Rates: minuteRate()}}}},
	})

	for _, tc := range []struct{ method, axis string }{
		{"GET", ":GET:"},
		{"POST", ":POST:"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			got := evaluate(snap, request{Path: "/x", Method: tc.method})

			if names := ruleNames(got); !slices.Equal(names, []string{"per-method"}) {
				t.Fatalf("%s /x matched %v, want [per-method]", tc.method, names)
			}
			if key := got.Rules[0].Buckets[0].Key; !strings.HasSuffix(key, tc.axis) {
				t.Errorf("bucket key of b/per-method for %s = %q, want it to end in the axis %q", tc.method, key, tc.axis)
			}
		})
	}
}

// The path axis takes the template string in a block whose template route
// matched, which bounds the axis cardinality, and the raw path elsewhere. A
// capture is an axis value of its block. The key ends with the axes, each
// escaped and terminated.
func TestThePathAxisIsTheTemplateOnlyWhereATemplateRouteMatched(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{
			{Name: "tpl", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}/items"}}}},
				Rules: []model.Rule{{Name: "per-order", Counters: []string{"order_id", model.KeyPath}, Rates: minuteRate()}}},
			{Name: "raw", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "per-path", Counters: []string{model.KeyPath}, Rates: minuteRate()}}},
		},
	})

	got := evaluate(snap, request{Path: "/api/orders/42/items", Method: "GET"})

	if names := ruleNames(got); !slices.Equal(names, []string{"per-order", "per-path"}) {
		t.Fatalf("GET /api/orders/42/items matched %v, want [per-order per-path]", names)
	}
	templateAxes := ":42:%2Fapi%2Forders%2F%7Border_id%7D%2Fitems:"
	if key := got.Rules[0].Buckets[0].Key; !strings.HasSuffix(key, templateAxes) {
		t.Errorf("bucket key of tpl/per-order = %q, want it to end in the axes %q", key, templateAxes)
	}
	rawAxis := ":%2Fapi%2Forders%2F42%2Fitems:"
	if key := got.Rules[1].Buckets[0].Key; !strings.HasSuffix(key, rawAxis) {
		t.Errorf("bucket key of raw/per-path = %q, want it to end in the axis %q", key, rawAxis)
	}
}

func TestAMatchedRuleContributesOneBucketPerWindow(t *testing.T) {
	snap := mustCompile(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{{Name: "r", Counters: []string{model.KeySub}, Rates: []model.Rate{
				{Requests: 100, Period: time.Minute},
				{Requests: 10000, Period: 24 * time.Hour, Algorithm: "FixedWindow"},
			}}}}},
	})

	buckets := evaluate(snap, request{Path: "/x", Method: "GET",
		Keys: map[string][]string{model.KeySub: {"alice"}}}).Buckets()

	if len(buckets) != 2 {
		t.Fatalf("Buckets() = %+v, want one per window, 2", buckets)
	}
	if key := buckets[0].Key; !strings.Contains(key, ":gcra:60:") {
		t.Errorf("bucket key of 100/min = %q, want the segments gcra:60", key)
	}
	if key := buckets[1].Key; !strings.Contains(key, ":fixedwindow:86400:") {
		t.Errorf("bucket key of 10000/day = %q, want the segments fixedwindow:86400", key)
	}
	if buckets[0].Window.Burst != 100 {
		t.Errorf("burst of 100/min = %d, want 100, the resolved full-bucket default", buckets[0].Window.Burst)
	}
}

// BlocksByPath answers the introspection question Match cannot: which blocks
// guard a path under any method. Match decides for one request, and a request
// always carries a method, so a route restricting itself to GET and POST can
// never admit the empty one.
func TestBlocksByPath_ignoresTheMethodsARouteRestrictsItselfTo(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "orders",
		Target: model.Target{Routes: []model.Route{{
			Path:    model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"},
			Methods: []string{"GET", "POST"},
		}}},
		Rules: []model.Rule{{Name: "per-client", Rates: minuteRate()}},
	}}})
	if got := blockNames(Match(snap, "/api/orders", "").Blocks()); len(got) != 0 {
		t.Fatalf("precondition: Match(/api/orders, no method) = %v, want no block", got)
	}

	got := blockNames(BlocksByPath(snap, "/api/orders"))

	if want := []string{"orders"}; !slices.Equal(got, want) {
		t.Errorf("BlocksByPath(/api/orders) = %v, want %v", got, want)
	}
}

// The path half is the same matcher, so the two answers cannot drift apart on
// prefixes, exact paths, or templates.
func TestBlocksByPath_appliesTheSamePathRules(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{
			Name: "exact",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathExact, Value: "/api/login"},
			}}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
		{
			Name: "template",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}"},
			}}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
		{
			Name:  "everything",
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
	}})

	cases := map[string][]string{
		"/api/login":             {"exact", "everything"},
		"/api/orders/4711":       {"template", "everything"},
		"/api/orders/4711/lines": {"everything"},
		// The query string never reaches a path predicate.
		"/api/login?next=/home": {"exact", "everything"},
	}
	for path, want := range cases {
		if got := blockNames(BlocksByPath(snap, path)); !slices.Equal(got, want) {
			t.Errorf("BlocksByPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// A block's captures are decided by the route the request matches, so a
// request reaching the block through a prefix route carries none of them.
// Under any method the routes that can decide the request are compared: a
// capture they all produce with one value is decided, one they disagree on is
// left for the method to settle, and a route with no method restriction ahead
// of the others decides every method by itself.
func TestTargetsByPath_decidesCapturesByTheRoutesThatCanDecide(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{
			Name: "orders",
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"}, Methods: []string{"POST", "PUT"}},
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}/items"}},
			}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
		{
			Name: "items",
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/items/{item_id}"}},
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/items"}, Methods: []string{"POST"}},
			}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
		{
			Name: "pairs",
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/pairs/{a}/{b}"}, Methods: []string{"GET"}},
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/pairs/{b}/{a}"}, Methods: []string{"POST"}},
			}},
			Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
		},
	}})

	cases := map[string]struct {
		path      string
		block     string
		captures  map[string]string
		undecided []string
	}{
		"only the prefix route admits the path": {
			path: "/api/orders", block: "orders",
		},
		"the prefix route decides its methods and the template the rest": {
			path: "/api/orders/42/items", block: "orders", undecided: []string{"order_id"},
		},
		"an unrestricted template ahead decides every method": {
			path: "/api/items/7", block: "items", captures: map[string]string{"item_id": "7"},
		},
		"two templates on disjoint methods produce different values": {
			path: "/pairs/1/2", block: "pairs", undecided: []string{"a", "b"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			targets := TargetsByPath(snap, tc.path)

			if got := targetNames(targets); !slices.Equal(got, []string{tc.block}) {
				t.Fatalf("TargetsByPath(%q) = %v, want [%s]", tc.path, got, tc.block)
			}
			if got := targets[0].Captures; !maps.Equal(got, tc.captures) {
				t.Errorf("TargetsByPath(%q) captures = %v, want %v", tc.path, got, tc.captures)
			}
			if got := targets[0].Undecided; !slices.Equal(got, tc.undecided) {
				t.Errorf("TargetsByPath(%q) undecided = %v, want %v", tc.path, got, tc.undecided)
			}
		})
	}
}

// For one request the target phase picks one route, and the captures are that
// route's: the prefix route produces none, and the template route behind it
// produces the capture for the methods the prefix route does not name.
func TestTargets_carryTheCapturesOfTheMatchedRoute(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "orders",
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"}, Methods: []string{"POST", "PUT"}},
			{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}/items"}},
		}},
		Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
	}}})

	cases := map[string]struct {
		path, method string
		captures     map[string]string
	}{
		"a path the template admits": {
			path: "/api/orders/42/items", method: "GET", captures: map[string]string{"order_id": "42"},
		},
		"a path only the prefix admits": {path: "/api/orders", method: "POST"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			targets := Match(snap, tc.path, tc.method).Targets()

			if got := targetNames(targets); !slices.Equal(got, []string{"orders"}) {
				t.Fatalf("Match(%q, %s).Targets() = %v, want [orders]", tc.path, tc.method, got)
			}
			if got := targets[0].Captures; !maps.Equal(got, tc.captures) {
				t.Errorf("Match(%q, %s).Targets()[0].Captures = %v, want %v", tc.path, tc.method, got, tc.captures)
			}
		})
	}
}

// bucketCosts lists the cost of every bucket of the result, in bucket order.
func bucketCosts(r Result) []int64 {
	buckets := r.Buckets()
	out := make([]int64, len(buckets))
	for i, b := range buckets {
		out[i] = b.Cost
	}
	return out
}

// costSnapshot compiles one block on the prefix /api/items whose route reads
// the cost from parameter, with a default of 20, and whose one rule carries
// two windows.
func costSnapshot(t *testing.T, parameter string) *compile.Snapshot {
	t.Helper()
	return mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "items",
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/items"},
			Cost: &model.RouteCost{Source: model.CostQueryParameter, Name: parameter, Default: 20},
		}}},
		Rules: []model.Rule{{Name: "r", Rates: []model.Rate{
			{Requests: model.MaxCost, Period: time.Hour, Algorithm: "FixedWindow"},
			{Requests: model.MaxCost, Period: 24 * time.Hour, Algorithm: "FixedWindow"},
		}}},
	}}})
}

// A route with a cost charges every window of the block the value of its
// parameter: a positive decimal integer as it stands, lowered to the
// ceiling, and the default of 20 for anything else. The request's own cost
// of 7 never applies.
func TestARouteChargesTheCostItsParameterCarries(t *testing.T) {
	cases := []struct {
		name      string
		parameter string
		query     string
		want      int64
	}{
		{"no query string", "limit", "", 20},
		{"a query without the parameter", "limit", "?offset=40", 20},
		{"a value", "limit", "?offset=40&limit=100", 100},
		{"leading zeros", "limit", "?limit=007", 7},
		{"zero", "limit", "?limit=0", 20},
		{"an empty value", "limit", "?limit=", 20},
		{"the name without =", "limit", "?limit", 20},
		{"letters", "limit", "?limit=abc", 20},
		{"a negative value", "limit", "?limit=-5", 20},
		{"an exponent", "limit", "?limit=1e3", 20},
		{"a plus sign, which decodes to a space", "limit", "?limit=+100", 20},
		{"the ceiling", "limit", "?limit=1000000000", model.MaxCost},
		{"one above the ceiling", "limit", "?limit=1000000001", model.MaxCost},
		{"twenty digits", "limit", "?limit=99999999999999999999", model.MaxCost},
		{"a repeat, the larger last", "limit", "?limit=5&limit=50", 50},
		{"a repeat, the larger first", "limit", "?limit=50&limit=5", 50},
		{"a repeat whose malformed occurrence costs the default", "limit", "?limit=5&limit=abc", 20},
		{"a name in another case", "limit", "?LIMIT=100", 20},
		{"a percent-encoded value", "limit", "?limit=%31%30", 10},
		{"a malformed escape", "limit", "?limit=%zz", 20},
		{"brackets in the name", "page[size]", "?page[size]=30", 30},
		{"percent-encoded brackets in the name", "page[size]", "?page%5Bsize%5D=30", 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := costSnapshot(t, tc.parameter)
			path := "/api/items" + tc.query

			result := evaluate(snap, request{Path: path, Method: "GET", Cost: 7})

			if got, want := bucketCosts(result), []int64{tc.want, tc.want}; !slices.Equal(got, want) {
				t.Errorf("GET %s with cost on %s: bucket costs = %v, want %v", path, tc.parameter, got, want)
			}
			if len(result.Rules) != 1 || result.Rules[0].Cost != tc.want {
				t.Errorf("GET %s with cost on %s: rules = %+v, want one at cost %d",
					path, tc.parameter, result.Rules, tc.want)
			}
		})
	}
}

// The first route that matches decides the cost, the way it decides the path
// axis: the collection route charges its parameter, and the single-object
// route and the prefix behind them, which read no cost, leave the request's
// own cost of 3.
func TestTheFirstMatchingRouteDecidesTheCost(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "api",
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/{resource}"}, Methods: []string{"GET"},
				Cost: &model.RouteCost{Source: model.CostQueryParameter, Name: "limit", Default: 20}},
			{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/v1/{resource}/{id}"}, Methods: []string{"GET"}},
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/v1"}},
		}},
		Rules: []model.Rule{{Name: "r", Rates: minuteRate()}},
	}}})

	cases := []struct {
		name   string
		method string
		path   string
		want   int64
	}{
		{"a collection", "GET", "/api/v1/items?limit=100", 100},
		{"a single object", "GET", "/api/v1/items/42?limit=100", 3},
		{"a collection under a method the cost route does not name", "POST", "/api/v1/items?limit=100", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluate(snap, request{Path: tc.path, Method: tc.method, Cost: 3})

			if got := bucketCosts(result); !slices.Equal(got, []int64{tc.want}) {
				t.Errorf("%s %s: bucket costs = %v, want [%d]", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// One request charges each block the cost of that block: the block whose
// route reads limit charges its value, and a block whose route reads no cost
// and a block without a target charge the request's own cost of 3.
func TestEachBlockOfARequestChargesItsOwnCost(t *testing.T) {
	snap := mustCompile(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{Name: "items", Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/items"},
			Cost: &model.RouteCost{Source: model.CostQueryParameter, Name: "limit"},
		}}}, Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
		{Name: "calls", Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/items"},
		}}}, Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
		{Name: "domain", Rules: []model.Rule{{Name: "r", Rates: minuteRate()}}},
	}})

	result := evaluate(snap, request{Path: "/api/items?limit=50", Method: "GET", Cost: 3})

	if got := matchedBlocks(result); !slices.Equal(got, []string{"items", "calls", "domain"}) {
		t.Fatalf("GET /api/items?limit=50 matched blocks %v, want [items calls domain]", got)
	}
	if got, want := bucketCosts(result), []int64{50, 3, 3}; !slices.Equal(got, want) {
		t.Errorf("GET /api/items?limit=50: bucket costs of items, calls, domain = %v, want %v", got, want)
	}
}
