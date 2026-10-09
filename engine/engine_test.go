package engine_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/identity"
	"github.com/netcracker/qubership-ratelimit/engine/match"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

const domain = "gateway.public"

// compiled compiles one policy of the domain and fails the test on any
// compile problem.
func compiled(tb testing.TB, p model.Policy) *compile.Snapshot {
	tb.Helper()
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		tb.Fatalf("compile problems: %v", problems)
	}
	return snap
}

// engineFor compiles one synthetic policy, which is one domain, over a fresh
// store.
func engineFor(t *testing.T, p model.Policy, opts ...engine.Option) *engine.Engine {
	t.Helper()
	return engine.New(compiled(t, p), memory.New(), opts...)
}

// newEngine compiles the specification's cascade example — a FirstMatch
// cascade with Bypass and Shadow steps plus an additive total block — over a
// fresh in-memory store.
func newEngine(t *testing.T, opts ...engine.Option) *engine.Engine {
	t.Helper()
	return engineFor(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Values: []string{"t1"}}},
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
					{Name: "trial", Behavior: model.BehaviorShadow, Counters: []string{model.KeySub},
						Matches: []model.Predicate{
							{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "trial"}},
						Rates: []model.Rate{{Requests: 10, Period: time.Minute}}},
					{Name: "everyone", Counters: []string{model.KeySub},
						Rates: []model.Rate{
							{Requests: 100, Period: time.Minute},
							{Requests: 10000, Period: 24 * time.Hour, Algorithm: "FixedWindow"}}},
				},
			},
			{
				Name: "total",
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 5000, Period: time.Minute}}}},
			},
		},
	}, opts...)
}

// claimsToken builds an unsigned test token from synthetic claims.
func claimsToken(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
}

func token(t *testing.T, sub string) string {
	t.Helper()
	return claimsToken(t, map[string]any{"sub": sub})
}

func orderRequest(t *testing.T, sub string) engine.Request {
	return engine.Request{Path: "/api/invoices/1", Method: "GET", Token: token(t, sub)}
}

func decide(t *testing.T, e *engine.Engine, req engine.Request) engine.Decision {
	t.Helper()
	d, err := e.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return d
}

func peek(t *testing.T, e *engine.Engine, req engine.Request) engine.Decision {
	t.Helper()
	d, err := e.Peek(t.Context(), req)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	return d
}

// appliedRules lists the rules a decision applied as block/rule, sorted: a
// decision defines no order of its rule outcomes.
func appliedRules(d engine.Decision) []string {
	out := make([]string, 0, len(d.Rules))
	for _, r := range d.Rules {
		out = append(out, r.Block+"/"+r.Rule)
	}
	slices.Sort(out)
	return out
}

// outcomeOf returns the outcome of one applied rule and fails the test when
// the decision did not apply it.
func outcomeOf(t *testing.T, d engine.Decision, block, rule string) engine.RuleOutcome {
	t.Helper()
	for _, r := range d.Rules {
		if r.Block == block && r.Rule == rule {
			return r
		}
	}
	t.Fatalf("the decision applied %q, want %s/%s among them", appliedRules(d), block, rule)
	return engine.RuleOutcome{}
}

// headersOf returns the headers of a decision and fails the test when it
// carries none.
func headersOf(t *testing.T, d engine.Decision) *engine.Headers {
	t.Helper()
	if d.Headers == nil {
		t.Fatalf("the decision (allowed %t, rules %q) carries no headers", d.Allowed, appliedRules(d))
	}
	return d.Headers
}

// window identifies the window a set of headers reports on.
type window struct {
	Block, Rule   string
	Limit         int64
	PeriodSeconds int64
}

func windowOf(h *engine.Headers) window {
	return window{Block: h.Block, Rule: h.Rule, Limit: h.Limit, PeriodSeconds: h.PeriodSeconds}
}

// assertNear checks a duration the store derived from the process clock. Each
// decision reads the clock anew and sees the bucket a few microseconds
// drained, so the duration may fall short of want by less than a second.
func assertNear(t *testing.T, what string, got, want time.Duration) {
	t.Helper()
	if got > want || got <= want-time.Second {
		t.Errorf("%s = %s, want %s or less than a second short of it", what, got, want)
	}
}

// A group is compared with the key of the predicate that names it after that
// key's normalization, and the group values are compared as written: a token
// whose org_id is ACME lands in a group that lists acme, because extraction
// lowercases the key, and a group that lists Acme matches no token, because
// nothing lowercases the group.
func TestInGroupComparesTheGroupAsWrittenWithTheNormalizedKey(t *testing.T) {
	engineWithGroupOf := func(t *testing.T, member string) *engine.Engine {
		t.Helper()
		return engineFor(t, model.Policy{
			Domain:   domain,
			Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org_id", Normalization: model.NormalizeLowercase}},
			Groups:   []model.Group{{Name: "partners", Values: []string{member}}},
			Blocks: []model.Block{{
				Name: "api",
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "partners",
					Matches:  []model.Predicate{{Key: "tenant", Operator: model.OperatorInGroup, Value: "partners"}},
					Counters: []string{model.KeySub},
					Rates:    []model.Rate{{Requests: 100, Period: time.Minute}}}},
			}},
		})
	}
	requestOf := func(t *testing.T, orgID string) engine.Request {
		t.Helper()
		return engine.Request{Path: "/api/orders", Method: "GET",
			Token: claimsToken(t, map[string]any{"sub": "alice", "org_id": orgID})}
	}

	t.Run("a group listing acme matches org_id ACME", func(t *testing.T) {
		d := decide(t, engineWithGroupOf(t, "acme"), requestOf(t, "ACME"))
		if got, want := appliedRules(d), []string{"api/partners"}; !slices.Equal(got, want) {
			t.Errorf("org_id ACME against the group [acme]: applied %q, want %q", got, want)
		}
	})
	t.Run("a group listing Acme matches no org_id", func(t *testing.T) {
		d := decide(t, engineWithGroupOf(t, "Acme"), requestOf(t, "acme"))
		if got := appliedRules(d); len(got) != 0 {
			t.Errorf("org_id acme against the group [Acme]: applied %q, want none", got)
		}
	})
}

// Bypass lifts only its block: the additive total still counts.
func TestBypassLiftsItsBlockOnly(t *testing.T) {
	d := decide(t, newEngine(t), orderRequest(t, "prometheus"))
	if !d.Allowed {
		t.Errorf("Decide(prometheus).Allowed = false, want true")
	}
	if got, want := appliedRules(d), []string{"total/all"}; !slices.Equal(got, want) {
		t.Errorf("Decide(prometheus) applied %q, want %q", got, want)
	}
	if got := headersOf(t, d).Limit; got != 5000 {
		t.Errorf("Decide(prometheus) headers limit = %d, want the total's 5000", got)
	}
}

// The cascade applies three windows to alice: the minute window of 100 and the
// day window of 10000 of everyone, and the minute window of 5000 of the total.
func TestHeadersComeFromTheStrictestRule(t *testing.T) {
	h := headersOf(t, decide(t, newEngine(t), orderRequest(t, "alice")))
	if got, want := windowOf(h), (window{Block: "cascade", Rule: "everyone", Limit: 100, PeriodSeconds: 60}); got != want {
		t.Errorf("Decide(alice) headers report %+v, want %+v", got, want)
	}
	if h.Remaining != 99 {
		t.Errorf("Decide(alice) headers remaining = %d, want 99", h.Remaining)
	}
}

// The names of the declared keys a request carried feed the per-key success
// counters of the "key declared, tokens arriving, zero extractions" detector.
func TestDecide_namesTheExtractedKeys(t *testing.T) {
	d := decide(t, newEngine(t), orderRequest(t, "alice"))
	if got, want := d.ExtractedKeys, []string{model.KeySub}; !slices.Equal(got, want) {
		t.Errorf("Decide(alice).ExtractedKeys = %q, want %q", got, want)
	}
}

// An explicit key the policy does not declare is the caller's own name, not an
// identity key, so the names list the declared sub alone.
func TestDecide_namesOnlyTheDeclaredKeysAmongTheExtractedOnes(t *testing.T) {
	req := orderRequest(t, "alice")
	req.Keys = map[string][]string{"own": {"x"}}

	d := decide(t, newEngine(t), req)
	if got, want := d.ExtractedKeys, []string{model.KeySub}; !slices.Equal(got, want) {
		t.Errorf("Decide(token of alice, keys own=x).ExtractedKeys = %q, want %q", got, want)
	}
}

// everyone has a minute window of 100 and a day window of 10000, and its
// outcome carries the numbers of the minute window, its own strictest.
func TestRuleOutcomeCarriesTheNumbersOfItsOwnStrictestBucket(t *testing.T) {
	everyone := outcomeOf(t, decide(t, newEngine(t), orderRequest(t, "alice")), "cascade", "everyone")
	if everyone.Limit != 100 {
		t.Errorf("the outcome of everyone has limit %d, want 100", everyone.Limit)
	}
	if everyone.Remaining != 99 {
		t.Errorf("the outcome of everyone has remaining %d, want 99", everyone.Remaining)
	}
}

func TestDecide_commitsTheChargeOfAnAdmission(t *testing.T) {
	e := newEngine(t)
	decide(t, e, orderRequest(t, "alice"))

	if got := headersOf(t, decide(t, e, orderRequest(t, "alice"))).Remaining; got != 98 {
		t.Errorf("remaining after the second request of alice = %d, want 98", got)
	}
}

// The headers name the rule whose window they report, as block and rule.
// The binding window here belongs to the second matched rule, behind a rule
// of two windows, so the bucket the headers come from has to be traced back
// across the first rule's buckets, on an admission, on a refusal that
// waiting cures, and on one it does not.
func TestHeaders_nameTheRuleOfTheStrictestWindow(t *testing.T) {
	snap := compiled(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{Name: "api", Rules: []model.Rule{{Name: "loose", Rates: []model.Rate{
			{Requests: 1000, Period: time.Minute}, {Requests: 10000, Period: time.Hour}}}}},
		{Name: "exports", Rules: []model.Rule{{Name: "tight", Rates: []model.Rate{
			{Requests: 2, Period: time.Minute}}}}},
	}})
	req := engine.Request{Path: "/x", Method: "GET"}
	want := window{Block: "exports", Rule: "tight", Limit: 2, PeriodSeconds: 60}

	t.Run("on an admission", func(t *testing.T) {
		d := decide(t, engine.New(snap, memory.New()), req)
		if got := windowOf(headersOf(t, d)); got != want {
			t.Errorf("headers report %+v, want %+v", got, want)
		}
	})
	t.Run("on a refusal that waiting cures", func(t *testing.T) {
		e := engine.New(snap, memory.New())
		decide(t, e, req)
		decide(t, e, req)
		d := decide(t, e, req)
		h := headersOf(t, d)
		if d.Allowed || h.RetryAfter <= 0 {
			t.Fatalf("the third request: allowed %t, retry after %s; want a refusal with a retry hint",
				d.Allowed, h.RetryAfter)
		}
		if got := windowOf(h); got != want {
			t.Errorf("headers report %+v, want %+v", got, want)
		}
	})
	t.Run("on a refusal that no waiting cures", func(t *testing.T) {
		d := decide(t, engine.New(snap, memory.New()), engine.Request{Path: "/x", Method: "GET", Cost: 3})
		if !d.CostExceedsCapacity {
			t.Fatalf("Decide(cost 3): allowed %t, cost exceeds capacity false; want a refusal no waiting cures",
				d.Allowed)
		}
		if got := windowOf(headersOf(t, d)); got != want {
			t.Errorf("headers report %+v, want %+v", got, want)
		}
	})
}

// EffectiveWindow is the time until the window admits one request more, the
// t of the ratelimit field. For a GCRA counter within its capacity it is one
// emission interval or less, not the time until the bucket drains: at two per
// hour, a client that spent both requests gets the next one 1800 s later,
// while the bucket is empty only after 3600 s. A fixed window returns its
// quota at the boundary, and a window at its full capacity has nothing to
// return.
func TestHeaders_effectiveWindowIsTheTimeToTheNextRequest(t *testing.T) {
	twoPerHour := func(algorithm string) model.Policy {
		return model.Policy{Domain: domain, Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "exports", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Algorithm: algorithm}}}}}}}
	}
	req := engine.Request{Path: "/x", Method: "GET"}

	t.Run("GCRA after the first admission", func(t *testing.T) {
		h := headersOf(t, decide(t, engineFor(t, twoPerHour("")), req))
		assertNear(t, "effective window", h.EffectiveWindow, 30*time.Minute)
		assertNear(t, "reset", h.ResetAfter, 30*time.Minute)
	})
	t.Run("GCRA after the second admission", func(t *testing.T) {
		e := engineFor(t, twoPerHour(""))
		decide(t, e, req)
		h := headersOf(t, decide(t, e, req))
		assertNear(t, "effective window", h.EffectiveWindow, 30*time.Minute)
		assertNear(t, "reset", h.ResetAfter, time.Hour)
	})
	t.Run("GCRA on a refusal", func(t *testing.T) {
		e := engineFor(t, twoPerHour(""))
		decide(t, e, req)
		decide(t, e, req)
		h := headersOf(t, decide(t, e, req))
		assertNear(t, "effective window", h.EffectiveWindow, 30*time.Minute)
		assertNear(t, "reset", h.ResetAfter, time.Hour)
		if h.RetryAfter < h.EffectiveWindow {
			t.Errorf("retry after %s is shorter than the effective window %s", h.RetryAfter, h.EffectiveWindow)
		}
	})
	t.Run("a fixed window", func(t *testing.T) {
		h := headersOf(t, decide(t, engineFor(t, twoPerHour("FixedWindow")), req))
		if h.EffectiveWindow <= 0 {
			t.Errorf("effective window = %s, want positive", h.EffectiveWindow)
		}
		if h.EffectiveWindow != h.ResetAfter {
			t.Errorf("effective window = %s, want the reset %s", h.EffectiveWindow, h.ResetAfter)
		}
	})
	t.Run("a GCRA window at its full capacity", func(t *testing.T) {
		d := decide(t, engineFor(t, twoPerHour("")), engine.Request{Path: "/x", Method: "GET", Cost: 3})
		if got := headersOf(t, d).EffectiveWindow; got >= 0 {
			t.Errorf("effective window = %s, want negative", got)
		}
	})
}

// A policy change that lowers burst keeps the counter's depth, so the
// effective window counts until that depth drains to one request below the
// new capacity and can exceed one emission interval: at two per hour, four
// requests under burst 4 leave a depth of 7200 s, and under burst 1 the next
// request returns 7200 s later, four intervals. retry-after and
// x-ratelimit-reset carry the same wait.
func TestHeaders_effectiveWindowCarriesTheDebtOfALoweredBurst(t *testing.T) {
	twoPerHour := func(burst int64) *compile.Snapshot {
		return compiled(t, model.Policy{Domain: domain, Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "exports", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Burst: burst}}}}}}})
	}
	req := engine.Request{Path: "/x", Method: "GET"}
	counters := memory.New()
	wide := engine.New(twoPerHour(4), counters)
	for i := range 4 {
		if d := decide(t, wide, req); !d.Allowed {
			t.Fatalf("request %d under burst 4 was refused with headers %+v, want an admission", i+1, d.Headers)
		}
	}

	h := headersOf(t, decide(t, engine.New(twoPerHour(1), counters), req))
	assertNear(t, "effective window under burst 1", h.EffectiveWindow, 2*time.Hour)
	assertNear(t, "retry after under burst 1", h.RetryAfter, 2*time.Hour)
	assertNear(t, "reset under burst 1", h.ResetAfter, 2*time.Hour)
}

// The trial rule allows t1 ten requests a minute in Shadow, and everyone
// enforces a hundred.
func TestShadowReportsWithoutVetoing(t *testing.T) {
	e := newEngine(t)
	for i := range 10 {
		if d := decide(t, e, orderRequest(t, "t1")); !d.Allowed {
			t.Fatalf("request %d of t1 was refused within both limits", i+1)
		}
	}

	last := decide(t, e, orderRequest(t, "t1"))
	if !last.Allowed {
		t.Errorf("the 11th request of t1 was refused: the exhausted shadow rule vetoed it")
	}
	trial := outcomeOf(t, last, "cascade", "trial")
	type verdict struct {
		Shadow, Allowed  bool
		Limit, Remaining int64
	}
	got := verdict{trial.Shadow, trial.Allowed, trial.Limit, trial.Remaining}
	if want := (verdict{Shadow: true, Allowed: false, Limit: 10, Remaining: 0}); got != want {
		t.Errorf("the 11th request: the trial outcome is %+v, want %+v", got, want)
	}
	if trial.RetryAfter <= 0 {
		t.Errorf("the 11th request: the trial outcome retries after %s, want a positive wait", trial.RetryAfter)
	}
	if everyone := outcomeOf(t, last, "cascade", "everyone"); !everyone.Allowed {
		t.Errorf("the 11th request: the outcome of everyone, far from its limit, is %+v, want allowed", everyone)
	}
}

// The headers come from the strictest applied enforcing rule. A shadow rule
// never contributes to the verdict, so a request that applies shadow rules
// alone carries no headers, and the same rule enforcing names itself in them.
func TestHeaders_comeFromAnEnforcingRuleOnly(t *testing.T) {
	decideUnder := func(t *testing.T, behavior model.Behavior) engine.Decision {
		t.Helper()
		e := engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{
			Name: "trial", Behavior: behavior, Rates: []model.Rate{{Requests: 10, Period: time.Minute}}}}}}})
		return decide(t, e, engine.Request{Path: "/x", Method: "GET"})
	}

	t.Run("a shadow rule alone", func(t *testing.T) {
		d := decideUnder(t, model.BehaviorShadow)
		if got, want := appliedRules(d), []string{"b/trial"}; !slices.Equal(got, want) {
			t.Fatalf("precondition: Decide applied %q, want %q", got, want)
		}
		if d.Headers != nil {
			t.Errorf("Decide under the shadow rule b/trial alone: headers %+v, want none", *d.Headers)
		}
	})
	t.Run("the same rule enforcing", func(t *testing.T) {
		h := headersOf(t, decideUnder(t, model.BehaviorEnforce))
		if got, want := windowOf(h), (window{Block: "b", Rule: "trial", Limit: 10, PeriodSeconds: 60}); got != want {
			t.Errorf("Decide under the enforcing rule b/trial: headers report %+v, want %+v", got, want)
		}
	})
}

func TestHeaders_aRefusalNamesTheRefusingWindowWithARetryHint(t *testing.T) {
	e := newEngine(t)
	for i := range 100 {
		if d := decide(t, e, orderRequest(t, "alice")); !d.Allowed {
			t.Fatalf("request %d of alice was refused under a limit of 100", i+1)
		}
	}

	d := decide(t, e, orderRequest(t, "alice"))
	if d.Allowed {
		t.Fatal("request 101 of alice was admitted past a 100-per-minute window")
	}
	h := headersOf(t, d)
	if got, want := windowOf(h), (window{Block: "cascade", Rule: "everyone", Limit: 100, PeriodSeconds: 60}); got != want {
		t.Errorf("headers report %+v, want %+v", got, want)
	}
	if h.RetryAfter <= 0 {
		t.Errorf("headers retry after %s, want a positive wait", h.RetryAfter)
	}
}

func TestDecide_chargesTheRequestCost(t *testing.T) {
	req := orderRequest(t, "alice")
	req.Cost = 5
	if got := headersOf(t, decide(t, newEngine(t), req)).Remaining; got != 95 {
		t.Errorf("remaining after a cost of 5 against 100 = %d, want 95", got)
	}
}

// A zero cost is the protocol's default of one.
func TestDecide_aZeroCostChargesOne(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")
	req.Cost = 5
	decide(t, e, req)

	req.Cost = 0
	if got := headersOf(t, decide(t, e, req)).Remaining; got != 94 {
		t.Errorf("remaining after a cost of 0 against 95 = %d, want 94", got)
	}
}

func TestDecide_refusesACostThatNeverFitsWithoutARetryHint(t *testing.T) {
	req := orderRequest(t, "alice")
	req.Cost = 200 // beyond the 100-burst minute window, within the others

	d := decide(t, newEngine(t), req)
	if d.Allowed || !d.CostExceedsCapacity {
		t.Fatalf("Decide(cost 200): allowed %t, cost exceeds capacity %t; want a refusal no waiting cures",
			d.Allowed, d.CostExceedsCapacity)
	}
	if got := headersOf(t, d).RetryAfter; got >= 0 {
		t.Errorf("Decide(cost 200) headers retry after %s, want negative: no retry hint may reach the response", got)
	}
}

// itemsAndCalls is a domain of two blocks over /api/items: items reads the
// cost from limit and counts 1000 items an hour, and calls reads no cost and
// counts calls requests an hour.
func itemsAndCalls(calls int64) model.Policy {
	route := model.Route{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/items"}}
	costRoute := route
	costRoute.Cost = &model.RouteCost{Source: model.CostQueryParameter, Name: "limit", Default: 20}
	return model.Policy{Domain: domain, Blocks: []model.Block{
		{Name: "items", Target: model.Target{Routes: []model.Route{costRoute}},
			Rules: []model.Rule{{Name: "per-hour", Rates: []model.Rate{{Requests: 1000, Period: time.Hour}}}}},
		{Name: "calls", Target: model.Target{Routes: []model.Route{route}},
			Rules: []model.Rule{{Name: "per-hour", Rates: []model.Rate{{Requests: calls, Period: time.Hour}}}}},
	}}
}

// The cost a route reads replaces the request's own cost in its block: a
// request of cost 5 with limit=100 charges items 100 and calls 5, and each
// outcome reports the cost its windows were charged.
func TestDecide_chargesTheCostARouteReads(t *testing.T) {
	d := decide(t, engineFor(t, itemsAndCalls(30)),
		engine.Request{Path: "/api/items?limit=100", Method: "GET", Cost: 5})

	items := outcomeOf(t, d, "items", "per-hour")
	if items.Cost != 100 || items.Remaining != 900 {
		t.Errorf("items after limit=100 at request cost 5: cost %d, remaining %d; want 100, 900",
			items.Cost, items.Remaining)
	}
	calls := outcomeOf(t, d, "calls", "per-hour")
	if calls.Cost != 5 || calls.Remaining != 25 {
		t.Errorf("calls after limit=100 at request cost 5: cost %d, remaining %d; want 5, 25",
			calls.Cost, calls.Remaining)
	}
}

// On an admission the headers come from the window with the fewest further
// requests at the cost it was charged, compared exactly. After limit=100,
// items has 900 left, nine more such requests, and binds before the 29 of
// calls; after limit=10, items has 990 left, 99 more, and calls binds. With
// calls at 31 an hour and a request cost of 3, calls has 28 left, 9.33 more,
// and items binds with its 9: both round down to nine, where the tie would
// go to calls, the smaller key.
func TestHeaders_comeFromTheWindowWithTheFewestRequestsLeftAtItsCost(t *testing.T) {
	cases := []struct {
		name  string
		calls int64
		cost  int64
		query string
		want  window
	}{
		{"limit=100", 30, 1, "limit=100", window{Block: "items", Rule: "per-hour", Limit: 1000, PeriodSeconds: 3600}},
		{"limit=10", 30, 1, "limit=10", window{Block: "calls", Rule: "per-hour", Limit: 30, PeriodSeconds: 3600}},
		{"ratios that round down alike", 31, 3, "limit=100",
			window{Block: "items", Rule: "per-hour", Limit: 1000, PeriodSeconds: 3600}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(t, engineFor(t, itemsAndCalls(tc.calls)),
				engine.Request{Path: "/api/items?" + tc.query, Method: "GET", Cost: tc.cost})

			if got := windowOf(headersOf(t, d)); got != tc.want {
				t.Errorf("Decide(/api/items?%s at cost %d, calls %d an hour) headers report %+v, want %+v",
					tc.query, tc.cost, tc.calls, got, tc.want)
			}
		})
	}
}

func TestExplicitKeysOverrideTheToken(t *testing.T) {
	req := orderRequest(t, "alice")
	req.Keys = map[string][]string{model.KeySub: {"t1"}}

	d := decide(t, newEngine(t), req)
	if got, want := appliedRules(d), []string{"cascade/everyone", "cascade/trial", "total/all"}; !slices.Equal(got, want) {
		t.Errorf("Decide(token of alice, keys sub=t1) applied %q, want %q", got, want)
	}
}

// Explicit keys override the token per key, so a key they leave absent keeps
// the token's value: the explicit tenant globex replaces the token's acme, and
// the token's sub alice still applies the rule that names her.
func TestExplicitKeysLeaveTheTokensOtherKeysInPlace(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain:   domain,
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org_id"}},
		Blocks: []model.Block{{Name: "b", Rules: []model.Rule{
			{Name: "alice", Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"}},
				Rates: []model.Rate{{Requests: 100, Period: time.Minute}}},
			{Name: "globex", Matches: []model.Predicate{{Key: "tenant", Operator: model.OperatorEquals, Value: "globex"}},
				Rates: []model.Rate{{Requests: 100, Period: time.Minute}}},
		}}},
	})
	req := engine.Request{Path: "/x", Method: "GET",
		Token: claimsToken(t, map[string]any{"sub": "alice", "org_id": "acme"}),
		Keys:  map[string][]string{"tenant": {"globex"}}}

	d := decide(t, e, req)
	if got, want := appliedRules(d), []string{"b/alice", "b/globex"}; !slices.Equal(got, want) {
		t.Errorf("Decide(token of alice and acme, keys tenant=globex) applied %q, want %q", got, want)
	}
}

func TestExtractionSkipsPropagate(t *testing.T) {
	d := decide(t, newEngine(t), engine.Request{Path: "/api/invoices/1", Method: "GET", Token: "garbage"})

	want := []identity.Skip{{Key: model.KeySub, Reason: identity.SkipDecodeFailed}}
	if !slices.Equal(d.Skips, want) {
		t.Errorf(`Decide(token "garbage").Skips = %v, want %v`, d.Skips, want)
	}
}

// A broken token degrades to anonymity: the per-client rules skip, and the
// unconditional total still enforces.
func TestDecide_anUndecodableTokenAppliesOnlyTheRulesWithoutIdentity(t *testing.T) {
	d := decide(t, newEngine(t), engine.Request{Path: "/api/invoices/1", Method: "GET", Token: "garbage"})

	if !d.Allowed {
		t.Errorf(`Decide(token "garbage").Allowed = false, want true`)
	}
	if got, want := appliedRules(d), []string{"total/all"}; !slices.Equal(got, want) {
		t.Errorf(`Decide(token "garbage") applied %q, want %q`, got, want)
	}
}

func TestOutsideAllRulesIsAllowedWithoutHeaders(t *testing.T) {
	d := decide(t, newEngine(t), engine.Request{Path: "/health", Method: "GET"})
	if !d.Allowed || d.Headers != nil || len(d.Rules) != 0 {
		t.Errorf("Decide(/health): allowed %t, headers %+v, rules %q; want allowed with no headers and no rules",
			d.Allowed, d.Headers, appliedRules(d))
	}
}

func TestHeadersAreDeterministicAcrossRuns(t *testing.T) {
	run := func() engine.Headers {
		return *headersOf(t, decide(t, newEngine(t), orderRequest(t, "alice")))
	}
	first := run()
	for range 3 {
		if got := run(); got != first {
			t.Fatalf("headers jittered across identical runs: %+v, then %+v", first, got)
		}
	}
}

// budgetSnapshot compiles a domain of 32 rules of four windows each, exactly
// the bucket budget of one decision.
func budgetSnapshot(t *testing.T) *compile.Snapshot {
	t.Helper()
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	rules := make([]model.Rule, 0, 32)
	for ri := range 32 {
		rates := make([]model.Rate, 0, len(periods))
		for _, pd := range periods {
			rates = append(rates, model.Rate{Requests: 100, Period: pd})
		}
		rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", ri), Rates: rates})
	}
	snap := compiled(t, model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: rules}}})
	if snap.DecisionBuckets != engine.MaxDecisionBuckets {
		t.Fatalf("32 rules of 4 windows compile to %d decision buckets, want the budget of %d",
			snap.DecisionBuckets, engine.MaxDecisionBuckets)
	}
	return snap
}

// oversizedSnapshot builds a domain one bucket past the budget. The compiler
// refuses such a generation, so the extra block goes in behind its back: what
// is under test is the engine's own backstop. In the component that compiles
// its own rules the backstop is unreachable; an embedder that builds a
// snapshot by hand is outside the contract, and the backstop keeps that
// mistake from monopolizing the domain's shard. The extra bucket copies the
// key of the first window of block b, which the store refuses as a duplicate,
// so a test of the backstop matches ErrTooManyBuckets, not any error.
func oversizedSnapshot(t *testing.T) *compile.Snapshot {
	t.Helper()
	snap := budgetSnapshot(t)
	smuggled := snap.Blocks[0].Rules[0]
	smuggled.Rates = smuggled.Rates[:1]
	extra := snap.Blocks[0]
	extra.Name = "smuggled"
	extra.Rules = []compile.Rule{smuggled}
	snap.Blocks = append(snap.Blocks, extra)
	return snap
}

func TestDecide_admitsADecisionAtTheBucketBudget(t *testing.T) {
	e := engine.New(budgetSnapshot(t), memory.New())
	d, err := e.Decide(t.Context(), engine.Request{Path: "/any", Method: "GET"})
	if err != nil {
		t.Fatalf("Decide over %d buckets: %v, want no error", engine.MaxDecisionBuckets, err)
	}
	if !d.Allowed {
		t.Errorf("Decide over %d buckets: allowed false, want true", engine.MaxDecisionBuckets)
	}
}

func TestDecide_refusesADecisionPastTheBucketBudget(t *testing.T) {
	e := engine.New(oversizedSnapshot(t), memory.New())
	_, err := e.Decide(t.Context(), engine.Request{Path: "/any", Method: "GET"})
	if !errors.Is(err, engine.ErrTooManyBuckets) {
		t.Errorf("Decide over %d buckets: %v, want ErrTooManyBuckets", engine.MaxDecisionBuckets+1, err)
	}
}

// The bucket budget is a property of the request rather than of the write, so
// Peek refuses an oversized decision exactly as Decide does. A management read
// that slipped past it would report numbers the enforcing path never produces.
func TestPeek_refusesADecisionPastTheBucketBudget(t *testing.T) {
	e := engine.New(oversizedSnapshot(t), memory.New())
	_, err := e.Peek(t.Context(), engine.Request{Path: "/any", Method: "GET"})
	if !errors.Is(err, engine.ErrTooManyBuckets) {
		t.Errorf("Peek over %d buckets: %v, want ErrTooManyBuckets", engine.MaxDecisionBuckets+1, err)
	}
}

// cacheProbe compiles one per-client rule that matches only alice: whether
// extraction saw the live token or a poisoned cache entry is visible in the
// applied rules.
func cacheProbe(t *testing.T, opts ...engine.Option) *engine.Engine {
	t.Helper()
	return engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "alice-only", Counters: []string{model.KeySub},
			Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"}},
			Rates:   []model.Rate{{Requests: 100, Period: time.Minute}}}},
	}}}, opts...)
}

// TestTokenCacheIsolatesOverlays alternates overlaid and clean requests over
// one token: the overlay must win within its own request and must never leak
// into the cached extraction, on the store path and on the hit path alike.
func TestTokenCacheIsolatesOverlays(t *testing.T) {
	e := cacheProbe(t)
	tok := token(t, "alice")
	overlaid := engine.Request{Path: "/x", Method: "GET", Token: tok,
		Keys: map[string][]string{model.KeySub: {"mallory"}}}
	clean := engine.Request{Path: "/x", Method: "GET", Token: tok}

	for _, step := range []struct {
		name string
		req  engine.Request
		want []string
	}{
		{"an overlaid request that stores the token's extraction", overlaid, nil},
		{"a clean request that hits the cache", clean, []string{"b/alice-only"}},
		{"an overlaid request on the hit path", overlaid, nil},
		{"a clean request after an overlay on the hit path", clean, []string{"b/alice-only"}},
	} {
		if got := appliedRules(decide(t, e, step.req)); !slices.Equal(got, step.want) {
			t.Errorf("%s: applied %q, want %q", step.name, got, step.want)
		}
	}
}

func TestTokenCacheDisabledStillExtracts(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(0))
	d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: token(t, "alice")})
	if got, want := appliedRules(d), []string{"b/alice-only"}; !slices.Equal(got, want) {
		t.Errorf("Decide(alice) without the cache applied %q, want %q", got, want)
	}
}

// A capacity of zero or below disables the token cache, so the same token
// twice is never served from it, while a capacity of one already caches it.
// Either way the decision reads the token's identity.
func TestWithTokenCache_disablesTheCacheAtACapacityOfZeroOrBelow(t *testing.T) {
	for _, c := range []struct {
		name     string
		capacity int
		hits     uint64
	}{
		{"a capacity of one", 1, 1},
		{"a capacity of zero", 0, 0},
		{"a negative capacity", -1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			stats := &engine.CacheStats{}
			e := cacheProbe(t, engine.WithTokenCache(c.capacity), engine.WithCacheStats(stats))
			req := engine.Request{Path: "/x", Method: "GET", Token: token(t, "alice")}

			decide(t, e, req)
			d := decide(t, e, req)
			if got := stats.Hits(); got != c.hits {
				t.Errorf("WithTokenCache(%d), the same token twice: %d cache hits, want %d", c.capacity, got, c.hits)
			}
			if got, want := appliedRules(d), []string{"b/alice-only"}; !slices.Equal(got, want) {
				t.Errorf("WithTokenCache(%d), the second request of alice applied %q, want %q", c.capacity, got, want)
			}
		})
	}
}

// probeClient is a client of cacheProbe with the rules its token applies.
type probeClient struct {
	sub, token string
	want       []string
}

func probeClients(t *testing.T) []probeClient {
	t.Helper()
	return []probeClient{
		{"alice", token(t, "alice"), []string{"b/alice-only"}},
		{"bob", token(t, "bob"), nil},
		{"carol", token(t, "carol"), nil},
	}
}

// TestTokenCacheRotationKeepsResultsExact churns a capacity-2 cache with
// three distinct tokens: generations rotate on nearly every insert, and every
// decision must still see its own token's identity.
func TestTokenCacheRotationKeepsResultsExact(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(2))
	clients := probeClients(t)
	for round := range 4 {
		for _, c := range clients {
			d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: c.token})
			if got := appliedRules(d); !slices.Equal(got, c.want) {
				t.Errorf("round %d, %s: applied %q, want %q", round+1, c.sub, got, c.want)
			}
		}
	}
}

// TestNoTargetSkipsIdentityWork pins the lazy-extraction contract: a request
// outside every target reports neither skips nor extracted keys, because
// identity was never resolved for it.
func TestNoTargetSkipsIdentityWork(t *testing.T) {
	d := decide(t, newEngine(t), engine.Request{Path: "/metrics", Method: "GET", Token: "not-a-token"})
	if !d.Allowed {
		t.Errorf("Decide(/metrics).Allowed = false, want true")
	}
	if d.Skips != nil || d.ExtractedKeys != nil {
		t.Errorf("Decide(/metrics): skips %v, extracted keys %q; want neither", d.Skips, d.ExtractedKeys)
	}
}

// A request that a block targets is Targeted even when no rule of the block
// applies to it, so its skips reach the caller: a request without a sub skips
// the only rule, counts nothing, and still reports the key it did not carry.
func TestDecide_aTargetedRequestThatNoRuleAppliesToIsTargeted(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{
			Name: "per-client",
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
			Rules: []model.Rule{{Name: "everyone", Counters: []string{model.KeySub},
				Rates: []model.Rate{{Requests: 100, Period: time.Minute}}}},
		}},
	})

	d := decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET", Token: "garbage"})

	if !d.Allowed || len(d.Rules) != 0 {
		t.Errorf(`Decide(token "garbage"): allowed %t, rules %q; want allowed with no rules`, d.Allowed, appliedRules(d))
	}
	if !d.Targeted {
		t.Errorf(`Decide(token "garbage").Targeted = false, want true`)
	}
	want := []identity.Skip{{Key: model.KeySub, Reason: identity.SkipDecodeFailed}}
	if !slices.Equal(d.Skips, want) {
		t.Errorf(`Decide(token "garbage").Skips = %v, want %v`, d.Skips, want)
	}
}

// TestTokenCacheConcurrentChurn hammers a capacity-2 cache from several
// goroutines over three tokens: rotation and promotion race constantly, and
// every decision must still see its own token's identity. The race detector
// covers the locking; the asserts cover the results.
func TestTokenCacheConcurrentChurn(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(2))
	clients := probeClients(t)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() { churnTokenCache(t, e, clients, g) })
	}
	wg.Wait()
}

// churnTokenCache drives one goroutine's share of the churn: 200 decisions
// rotating through the clients, each asserting it saw its own token's identity
// rather than a neighbor's.
func churnTokenCache(t *testing.T, e *engine.Engine, clients []probeClient, g int) {
	t.Helper()
	for i := range 200 {
		c := clients[(g+i)%len(clients)]
		d, err := e.Decide(t.Context(), engine.Request{Path: "/x", Method: "GET", Token: c.token})
		if err != nil {
			t.Errorf("Decide(%s): %v", c.sub, err)
			return
		}
		if got := appliedRules(d); !slices.Equal(got, c.want) {
			t.Errorf("goroutine %d, %s: applied %q, want %q", g, c.sub, got, c.want)
			return
		}
	}
}

// hugeToken is a token past identity.MaxTokenBytes.
func hugeToken() string {
	return "h." + strings.Repeat("A", identity.MaxTokenBytes) + ".s"
}

// TestOversizedTokenBypassesTheCache pins the order of defenses: the token
// size bound applies before any hashing or caching, so an oversized token is
// neither a hit nor a miss, however often it repeats.
func TestOversizedTokenBypassesTheCache(t *testing.T) {
	stats := &engine.CacheStats{}
	e := cacheProbe(t, engine.WithCacheStats(stats))
	huge := engine.Request{Path: "/x", Method: "GET", Token: hugeToken()}
	decide(t, e, huge)
	decide(t, e, huge)

	if got := stats.Misses(); got != 0 {
		t.Errorf("two requests with an oversized token: %d cache misses, want 0", got)
	}
	if got := stats.Hits(); got != 0 {
		t.Errorf("two requests with an oversized token: %d cache hits, want 0", got)
	}
}

// An oversized token reports its decode_failed skip exactly like the uncached
// path, and carries no identity.
func TestDecide_anOversizedTokenIsUndecodable(t *testing.T) {
	d := decide(t, cacheProbe(t), engine.Request{Path: "/x", Method: "GET", Token: hugeToken()})
	if !d.Allowed || len(d.Rules) != 0 {
		t.Errorf("Decide(oversized token): allowed %t, applied %q; want allowed with no rules",
			d.Allowed, appliedRules(d))
	}
	want := []identity.Skip{{Key: model.KeySub, Reason: identity.SkipDecodeFailed}}
	if !slices.Equal(d.Skips, want) {
		t.Errorf("Decide(oversized token).Skips = %v, want %v", d.Skips, want)
	}
}

// TestCacheStatsCountEligibleLookups pins what the shared counters mean: a
// hit avoided an extraction, a miss paid for one, and a tokenless request is
// neither — the ratio must read as cache effectiveness, not traffic shape.
func TestCacheStatsCountEligibleLookups(t *testing.T) {
	stats := &engine.CacheStats{}
	e := newEngine(t, engine.WithCacheStats(stats))

	decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET", Token: token(t, "alice")})
	decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET", Token: token(t, "alice")})
	decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET"})
	decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET", Token: token(t, "bob")})

	if got := stats.Hits(); got != 1 {
		t.Errorf("alice twice, no token, bob: %d hits, want 1", got)
	}
	if got := stats.Misses(); got != 2 {
		t.Errorf("alice twice, no token, bob: %d misses, want 2", got)
	}
}

// One CacheStats value outlives the engines it counts for: an engine built
// over a new snapshot adds to the counts of the one it replaced. Each engine
// pays one miss for alice's token and serves her second request from its own
// cache.
func TestCacheStats_keepCountingAcrossTheEnginesThatShareThem(t *testing.T) {
	stats := &engine.CacheStats{}
	req := engine.Request{Path: "/x", Method: "GET", Token: token(t, "alice")}
	first := cacheProbe(t, engine.WithCacheStats(stats))
	decide(t, first, req)
	decide(t, first, req)

	second := cacheProbe(t, engine.WithCacheStats(stats))
	decide(t, second, req)
	decide(t, second, req)

	if got := stats.Hits(); got != 2 {
		t.Errorf("alice twice on each of two engines: %d hits, want 2", got)
	}
	if got := stats.Misses(); got != 2 {
		t.Errorf("alice twice on each of two engines: %d misses, want 2", got)
	}
}

// Peek reports the remaining of alice's strictest window as it stands: the
// minute window of 100 holds 100 before anything is charged.
func TestPeek_chargesNothing(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")

	if got := headersOf(t, peek(t, e, req)).Remaining; got != 100 {
		t.Errorf("remaining on the first Peek = %d, want 100", got)
	}
	if got := headersOf(t, peek(t, e, req)).Remaining; got != 100 {
		t.Errorf("remaining on the second Peek = %d, want 100", got)
	}
}

// Peek answers what Decide would answer. It is what the management API reads
// through, so a listing reporting another verdict or other rules than the
// enforcing path would be worse than no listing at all.
func TestPeek_answersLikeDecide(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")

	peeked := peek(t, e, req)
	decided := decide(t, e, req)
	if decided.Allowed != peeked.Allowed {
		t.Errorf("Decide allowed %t, Peek predicted %t", decided.Allowed, peeked.Allowed)
	}
	if got, want := appliedRules(peeked), appliedRules(decided); !slices.Equal(got, want) {
		t.Errorf("Peek applied %q, Decide %q", got, want)
	}
}

func TestPeek_seesTheChargeDecideCommitted(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")
	decide(t, e, req)

	if got := headersOf(t, peek(t, e, req)).Remaining; got != 99 {
		t.Errorf("remaining on a Peek after one Decide against 100 = %d, want 99", got)
	}
}

// Among refusals, a cost that never fits binds harder than one waiting cures.
// Reporting the waiting window would send a caller back on a schedule that
// cannot help: the never window refuses the same cost forever.
func TestHeaders_capacityExceededOutranksALongerWait(t *testing.T) {
	e := engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{
			// Five deep, one request back every 720 s.
			{Name: "hour", Rates: []model.Rate{{Requests: 5, Period: time.Hour, Burst: 5}}},
			// A cost of 5 can never fit a bucket two deep.
			{Name: "never", Rates: []model.Rate{{Requests: 2, Period: time.Minute, Burst: 2}}},
		},
	}}})
	// A cost of 2 fits both buckets and leaves the hour bucket three requests,
	// so a cost of 5 waits there about 1440 s.
	if d := decide(t, e, engine.Request{Path: "/any", Method: "GET", Cost: 2}); !d.Allowed {
		t.Fatalf("Decide(cost 2) was refused, want an admission by both windows")
	}

	d := decide(t, e, engine.Request{Path: "/any", Method: "GET", Cost: 5})
	if hour := outcomeOf(t, d, "b", "hour"); hour.Allowed || hour.RetryAfter <= 0 {
		t.Fatalf("Decide(cost 5): the hour rule allowed %t, retry after %s; want a refusal waiting cures",
			hour.Allowed, hour.RetryAfter)
	}
	if d.Allowed || !d.CostExceedsCapacity {
		t.Fatalf("Decide(cost 5): allowed %t, cost exceeds capacity %t; want a refusal no waiting cures",
			d.Allowed, d.CostExceedsCapacity)
	}
	h := headersOf(t, d)
	if got, want := windowOf(h), (window{Block: "b", Rule: "never", Limit: 2, PeriodSeconds: 60}); got != want {
		t.Errorf("headers report %+v, want %+v, the window the cost can never fit", got, want)
	}
	if h.RetryAfter >= 0 {
		t.Errorf("headers retry after %s, want negative: no waiting cures the request", h.RetryAfter)
	}
}

// Two windows the cost can never fit carry no retry hint to rank by, so the
// order falls to the bucket key. Declaration order would pick the other one,
// which is the point: the headers of a repeated refusal have to name the same
// window every time, whatever order the rules happen to be written in.
func TestHeaders_twoCapacityExceededWindowsTieBreakByKey(t *testing.T) {
	e := engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{
			// First in the snapshot, and the larger key.
			{Name: "zzz", Rates: []model.Rate{{Requests: 3, Period: time.Minute, Burst: 3}}},
			{Name: "aaa", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Burst: 2}}},
		},
	}}})
	want := window{Block: "b", Rule: "aaa", Limit: 2, PeriodSeconds: 3600}

	for attempt := range 3 {
		d := decide(t, e, engine.Request{Path: "/any", Method: "GET", Cost: 5})
		if !d.CostExceedsCapacity {
			t.Fatalf("attempt %d: Decide(cost 5) cost exceeds capacity false, want true: 5 fits neither window",
				attempt+1)
		}
		h := headersOf(t, d)
		if got := windowOf(h); got != want {
			t.Errorf("attempt %d: headers report %+v, want %+v, the smaller key", attempt+1, got, want)
		}
		if h.RetryAfter >= 0 {
			t.Errorf("attempt %d: headers retry after %s, want negative", attempt+1, h.RetryAfter)
		}
	}
}

// An admission that leaves two windows with equal remaining ranks them by
// bucket key, as a refusal does: the headers name the window with the smaller
// key, which declaration order would not pick.
func TestHeaders_twoWindowsWithEqualRemainingTieBreakByKey(t *testing.T) {
	e := engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{
			// First in the snapshot, and the larger key.
			{Name: "zzz", Rates: []model.Rate{{Requests: 10, Period: time.Minute}}},
			{Name: "aaa", Rates: []model.Rate{{Requests: 10, Period: time.Hour}}},
		},
	}}})

	d := decide(t, e, engine.Request{Path: "/any", Method: "GET"})
	zzz, aaa := outcomeOf(t, d, "b", "zzz"), outcomeOf(t, d, "b", "aaa")
	if !d.Allowed || zzz.Remaining != 9 || aaa.Remaining != 9 {
		t.Fatalf("precondition: allowed %t, remaining of zzz %d and of aaa %d; want an admission leaving 9 in each",
			d.Allowed, zzz.Remaining, aaa.Remaining)
	}
	want := window{Block: "b", Rule: "aaa", Limit: 10, PeriodSeconds: 3600}
	if got := windowOf(headersOf(t, d)); got != want {
		t.Errorf("headers report %+v, want %+v, the smaller key", got, want)
	}
}

// Blocks reports what the target phase hit, in snapshot order, which is what
// the management API lists a path's rules from.
func TestCandidates_blocksReportsTheTargetedOnesInOrder(t *testing.T) {
	snap := compiled(t, model.Policy{Domain: domain, Blocks: []model.Block{
		{
			Name:   "invoices",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/invoices"}}}},
			Rules:  []model.Rule{{Name: "r", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}},
		},
		{
			Name:   "orders",
			Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"}}}},
			Rules:  []model.Rule{{Name: "r", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}},
		},
		{
			Name:  "everything",
			Rules: []model.Rule{{Name: "r", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}},
		},
	}})

	for _, c := range []struct {
		name, path string
		want       []string
	}{
		{"a path under one block's target", "/api/invoices/1", []string{"invoices", "everything"}},
		{"a path outside every target", "/nothing", []string{"everything"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			blocks := match.Match(snap, c.path, "GET").Blocks()
			got := make([]string, 0, len(blocks))
			for _, block := range blocks {
				got = append(got, block.Name)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("Match(%q).Blocks() = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

// A rule outcome carries the capacity its remaining counts down from, next to
// the limit the headers carry: the burst of a GCRA window, and the requests
// of a fixed window, which has no burst. The near-limit margin is a share of
// that capacity.
func TestRuleOutcomeCarriesTheCapacityOfItsWindow(t *testing.T) {
	d := decide(t, engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{{
			Name: "api",
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
			Rules: []model.Rule{
				{Name: "burst", Rates: []model.Rate{{Requests: 1000, Period: time.Minute, Burst: 100}}},
				{Name: "fixed", Rates: []model.Rate{{Requests: 100, Period: time.Minute, Algorithm: "FixedWindow"}}},
			},
		}},
	}), engine.Request{Path: "/api/orders", Method: "GET"})
	if got, want := appliedRules(d), []string{"api/burst", "api/fixed"}; !slices.Equal(got, want) {
		t.Errorf("Decide(/api/orders) applied %q, want %q", got, want)
	}

	for _, c := range []struct {
		name            string
		rule            string
		limit, capacity int64
	}{
		{"a GCRA window with a burst below its requests", "burst", 1000, 100},
		{"a fixed window", "fixed", 100, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := outcomeOf(t, d, "api", c.rule)
			if r.Limit != c.limit || r.Capacity != c.capacity {
				t.Errorf("rule %s: limit = %d, capacity = %d, want %d and %d",
					c.rule, r.Limit, r.Capacity, c.limit, c.capacity)
			}
		})
	}
}

// rolesProbe compiles one rule that applies to a token whose roles claim holds
// admin, its token cache counted by stats.
func rolesProbe(t *testing.T, stats *engine.CacheStats) *engine.Engine {
	t.Helper()
	return engineFor(t, model.Policy{Domain: domain,
		Mappings: []model.KeyMapping{{Key: "roles", Claim: "roles", Type: model.ValueStringArray}},
		Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{Name: "admins",
			Matches: []model.Predicate{{Key: "roles", Operator: model.OperatorContains, Value: "admin"}},
			Rates:   []model.Rate{{Requests: 100, Period: time.Minute}}}}}}},
		engine.WithCacheStats(stats))
}

// An extraction larger than the cache's entry bound is not cached: a stream
// of distinct tokens with a large array claim would otherwise hold the cache
// at its capacity times the claim, past a replica's memory limit. A small
// extraction is cached as before.
func TestTokenCacheSkipsALargeExtraction(t *testing.T) {
	t.Run("an extraction past the entry bound", func(t *testing.T) {
		stats := &engine.CacheStats{}
		e := rolesProbe(t, stats)
		// Sixty-three roles of 62 bytes and admin: about 5.6 KiB as the cache
		// estimates an entry, past its bound of 4 KiB.
		roles := make([]any, 0, identity.MaxArrayItems)
		for i := 1; i < identity.MaxArrayItems; i++ {
			roles = append(roles, fmt.Sprintf("role-%02d-%s", i, strings.Repeat("r", 54)))
		}
		roles = append(roles, "admin")
		large := engine.Request{Path: "/x", Method: "GET",
			Token: claimsToken(t, map[string]any{"sub": "alice", "roles": roles})}

		decide(t, e, large)
		d := decide(t, e, large)
		if got := stats.Hits(); got != 0 {
			t.Errorf("the same large extraction twice: %d cache hits, want 0", got)
		}
		if got, want := appliedRules(d), []string{"b/admins"}; !slices.Equal(got, want) {
			t.Errorf("the uncached extraction applied %q, want %q", got, want)
		}
	})
	t.Run("a small extraction", func(t *testing.T) {
		stats := &engine.CacheStats{}
		e := rolesProbe(t, stats)
		small := engine.Request{Path: "/x", Method: "GET", Token: token(t, "bob")}

		decide(t, e, small)
		decide(t, e, small)
		if got := stats.Hits(); got != 1 {
			t.Errorf("the same small extraction twice: %d cache hits, want 1", got)
		}
	})
}

// The direct form's values are normalized as a token's are, so a direct
// caller's sub Alice and a token whose sub is Alice charge one counter:
// the overlay of unnormalized values was what made a counter the management
// API could not address.
func TestDecide_theDirectFormIsNormalizedLikeTheToken(t *testing.T) {
	e := engineFor(t, model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{Name: "each",
		Counters: []string{model.KeySub}, Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}}}}})

	if d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: token(t, "Alice")}); !d.Allowed {
		t.Fatal("the first request, with a token of Alice, was refused under a limit of 1")
	}
	direct := engine.Request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeySub: {"Alice"}}}
	if d := decide(t, e, direct); d.Allowed {
		t.Error("the direct form's Alice was counted apart from the token's")
	}
}
