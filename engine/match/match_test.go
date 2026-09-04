package match

import (
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

func ruleNames(r Result) []string {
	out := make([]string, len(r.Rules))
	for i, m := range r.Rules {
		out[i] = m.Rule
	}
	return out
}

func TestRouteMatching(t *testing.T) {
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
			got := evaluate(snap, tc.req)
			names := make([]string, len(got.Rules))
			for i, m := range got.Rules {
				names[i] = m.Block
			}
			if len(names) != len(tc.blocks) {
				t.Fatalf("matched blocks = %v, want %v", names, tc.blocks)
			}
			for i := range names {
				if names[i] != tc.blocks[i] {
					t.Fatalf("matched blocks = %v, want %v", names, tc.blocks)
				}
			}
		})
	}
}

func TestOperators(t *testing.T) {
	mappings := []model.KeyMapping{
		{Key: "roles", Claim: "roles", Type: model.ValueStringArray},
		{Key: "tenant", Claim: "org"},
	}
	withPredicate := func(c model.Predicate) model.Policy {
		return model.Policy{
			Domain:   domain,
			Mappings: mappings,
			Groups:   []model.Group{{Name: "vip", Clients: []string{"alice", "bob"}}},
			Blocks: []model.Block{{Name: "b",
				Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
				Rules:  []model.Rule{{Name: "r", Matches: []model.Predicate{c}, Rates: minuteRate()}}}},
		}
	}

	cases := []struct {
		name    string
		cond    model.Predicate
		keys    map[string][]string
		matches bool
	}{
		{"equals hit", model.Predicate{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{model.KeyClient: {"alice"}}, true},
		{"equals miss", model.Predicate{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "alice"},
			map[string][]string{model.KeyClient: {"bob"}}, false},
		{"in hit", model.Predicate{Key: model.KeyClient, Operator: model.OperatorIn, Values: []string{"a", "b"}},
			map[string][]string{model.KeyClient: {"b"}}, true},
		{"ingroup hit", model.Predicate{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "vip"},
			map[string][]string{model.KeyClient: {"bob"}}, true},
		{"ingroup miss", model.Predicate{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "vip"},
			map[string][]string{model.KeyClient: {"eve"}}, false},
		{"contains on array", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			map[string][]string{"roles": {"user", "admin"}}, true},
		{"contains never substring", model.Predicate{Key: "roles", Operator: model.OperatorContains, Value: "admin"},
			map[string][]string{"roles": {"administrator"}}, false},
		{"exists", model.Predicate{Key: "tenant", Operator: model.OperatorExists},
			map[string][]string{"tenant": {"acme"}}, true},
		{"notexists on absent", model.Predicate{Key: "tenant", Operator: model.OperatorDoesNotExist},
			map[string][]string{}, true},
		{"notexists on present", model.Predicate{Key: "tenant", Operator: model.OperatorDoesNotExist},
			map[string][]string{"tenant": {"acme"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := mustCompile(t, withPredicate(tc.cond))
			got := evaluate(snap, request{Path: "/x", Method: "GET", Keys: tc.keys})
			if (len(got.Rules) == 1) != tc.matches {
				t.Errorf("matched = %v, want %v", ruleNames(got), tc.matches)
			}
		})
	}
}

func TestMissingAxisSkipsRule(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "per-user", Counters: []string{model.KeyClient}, Rates: minuteRate()},
				{Name: "total", Rates: minuteRate()},
			}}},
	}
	snap := mustCompile(t, p)

	anonymous := evaluate(snap, request{Path: "/x", Method: "GET"})
	if got := ruleNames(anonymous); len(got) != 1 || got[0] != "total" {
		t.Errorf("anonymous matched %v, want [total]: per-user has nothing to key its bucket with", got)
	}

	authed := evaluate(snap, request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeyClient: {"alice"}}})
	if got := ruleNames(authed); len(got) != 2 {
		t.Errorf("authenticated matched %v, want both rules", got)
	}
}

// TestAxisRefusesAmbiguity pins that a scalar axis sent with several values —
// a direct consumer breaking the typing — makes the rule not match rather
// than guessing which value keys the bucket.
func TestAxisRefusesAmbiguity(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules:  []model.Rule{{Name: "per-user", Counters: []string{model.KeyClient}, Rates: minuteRate()}}}},
	}
	snap := mustCompile(t, p)

	got := evaluate(snap, request{Path: "/x", Method: "GET",
		Keys: map[string][]string{model.KeyClient: {"a", "b"}}})
	if len(got.Rules) != 0 {
		t.Errorf("matched %v: an ambiguous axis must not match", ruleNames(got))
	}
}

func TestReplacesSuppressesUnderAll(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "enterprise", Clients: []string{"corp"}}},
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "base", Counters: []string{model.KeyClient}, Rates: minuteRate()},
				{Name: "enterprise",
					Matches:       []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "enterprise"}},
					Counters:      []string{model.KeyClient},
					Rates:         []model.Rate{{Requests: 1000, Period: time.Minute}},
					ReplacedRules: []string{"base"}},
			}}},
	}
	snap := mustCompile(t, p)

	corp := evaluate(snap, request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeyClient: {"corp"}}})
	if got := ruleNames(corp); len(got) != 1 || got[0] != "enterprise" {
		t.Errorf("enterprise client matched %v, want the override only", got)
	}

	plain := evaluate(snap, request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeyClient: {"alice"}}})
	if got := ruleNames(plain); len(got) != 1 || got[0] != "base" {
		t.Errorf("plain client matched %v, want [base]: replaces of an unmatched rule must not fire", got)
	}
}

// TestTargetlessBlockMatchesEverything pins the whole-domain form at match
// time: any path, any method.
func TestTargetlessBlockMatchesEverything(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Rules: []model.Rule{{Name: "total", Rates: minuteRate()}}}},
	}
	snap := mustCompile(t, p)
	for _, req := range []request{
		{Path: "/anything", Method: "GET"},
		{Path: "/", Method: "DELETE"},
	} {
		if got := evaluate(snap, req); len(got.Rules) != 1 {
			t.Errorf("request %+v matched %v, want the total rule", req, ruleNames(got))
		}
	}
}

// TestBypassUnderAllExemptsNamedRulesOnly pins the targeted-exemption
// semantics: a matched bypass frees the request from the rules it names and
// from nothing else.
func TestBypassUnderAllExemptsNamedRulesOnly(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "vip", Clients: []string{"corp"}}},
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "base", Counters: []string{model.KeyClient}, Rates: minuteRate()},
				{Name: "guard", Rates: minuteRate()},
				{Name: "vip-exempt", Behavior: model.BehaviorBypass, ReplacedRules: []string{"base"},
					Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "vip"}}},
			}}},
	}
	snap := mustCompile(t, p)

	corp := evaluate(snap, request{Path: "/x", Method: "GET",
		Keys: map[string][]string{model.KeyClient: {"corp"}}})
	if got := ruleNames(corp); len(got) != 1 || got[0] != "guard" {
		t.Errorf("vip matched %v, want [guard]: exempt from base only, guard still counts", got)
	}

	plain := evaluate(snap, request{Path: "/x", Method: "GET",
		Keys: map[string][]string{model.KeyClient: {"alice"}}})
	if got := ruleNames(plain); len(got) != 2 {
		t.Errorf("plain client matched %v, want base and guard", got)
	}
}

func TestFirstMatchCascade(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Clients: []string{"t1"}}},
		Blocks: []model.Block{{Name: "cascade", Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{
				{Name: "internal", Behavior: model.BehaviorBypass,
					Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "prometheus"}}},
				{Name: "trial", Behavior: model.BehaviorShadow, Counters: []string{model.KeyClient},
					Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "trial"}},
					Rates:   []model.Rate{{Requests: 10, Period: time.Minute}}},
				{Name: "everyone", Counters: []string{model.KeyClient}, Rates: minuteRate()},
			}}},
	}
	snap := mustCompile(t, p)
	client := func(id string) request {
		return request{Path: "/q", Method: "GET", Keys: map[string][]string{model.KeyClient: {id}}}
	}

	if got := evaluate(snap, client("prometheus")); len(got.Rules) != 0 {
		t.Errorf("bypass client matched %v, want nothing counted", ruleNames(got))
	}

	trial := evaluate(snap, client("t1"))
	if got := ruleNames(trial); len(got) != 2 || got[0] != "trial" || got[1] != "everyone" {
		t.Fatalf("trial client matched %v, want shadow then the enforcing rule", got)
	}
	if !trial.Rules[0].Shadow || trial.Rules[1].Shadow {
		t.Error("shadow flags did not follow behavior through the cascade")
	}

	if got := ruleNames(evaluate(snap, client("alice"))); len(got) != 1 || got[0] != "everyone" {
		t.Errorf("plain client matched %v, want [everyone]", got)
	}
}

func TestPathAxisAndCaptures(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{
			{Name: "tpl", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}/items"}}}},
				Rules: []model.Rule{{Name: "per-order", Counters: []string{"order_id", model.KeyPath}, Rates: minuteRate()}}},
			{Name: "raw", Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "per-path", Counters: []string{model.KeyPath}, Rates: minuteRate()}}},
		},
	}
	snap := mustCompile(t, p)

	got := evaluate(snap, request{Path: "/api/orders/42/items", Method: "GET"})
	if len(got.Rules) != 2 {
		t.Fatalf("matched %v, want both blocks", ruleNames(got))
	}

	tplKey := got.Rules[0].Buckets[0].Key
	if !strings.Contains(tplKey, ":42:") || !strings.Contains(tplKey, "%2Fapi%2Forders%2F%7Border_id%7D%2Fitems") {
		t.Errorf("template bucket key = %q: want the captured 42 and the template string as the path axis", tplKey)
	}
	rawKey := got.Rules[1].Buckets[0].Key
	if !strings.Contains(rawKey, "%2Fapi%2Forders%2F42%2Fitems") {
		t.Errorf("raw bucket key = %q: want the raw path as the axis outside template blocks", rawKey)
	}
}

func TestBucketsPerWindow(t *testing.T) {
	p := model.Policy{
		Domain: domain,
		Blocks: []model.Block{{Name: "b",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/"}}}},
			Rules: []model.Rule{{Name: "r", Counters: []string{model.KeyClient}, Rates: []model.Rate{
				{Requests: 100, Period: time.Minute},
				{Requests: 10000, Period: 24 * time.Hour, Algorithm: "FixedWindow"},
			}}}}},
	}
	snap := mustCompile(t, p)

	got := evaluate(snap, request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeyClient: {"alice"}}})
	buckets := got.Buckets()
	if len(buckets) != 2 {
		t.Fatalf("buckets = %d, want one per window", len(buckets))
	}
	if !strings.Contains(buckets[0].Key, ":gcra:60:") || !strings.Contains(buckets[1].Key, ":fixedwindow:86400:") {
		t.Errorf("bucket keys = %q, %q: want the algorithm and window segments", buckets[0].Key, buckets[1].Key)
	}
	if buckets[0].Window.Burst != 100 {
		t.Errorf("burst = %d, want the resolved full-bucket default", buckets[0].Window.Burst)
	}
}

// request and evaluate run both phases in one call: every scenario in this
// file exercises the target phase and the rule phase together.
type request struct {
	Path   string
	Method string
	Keys   map[string][]string
}

func evaluate(snap *compile.Snapshot, r request) Result {
	return Match(snap, r.Path, r.Method).Evaluate(r.Keys)
}
