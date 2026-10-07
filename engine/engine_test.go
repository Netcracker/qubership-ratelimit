package engine_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// newEngine compiles the specification's cascade example — a FirstMatch
// cascade with Bypass and Shadow steps plus an additive total block — over a
// fresh in-memory store.
func newEngine(t *testing.T, opts ...engine.Option) *engine.Engine {
	t.Helper()
	p := model.Policy{
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
	}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	return engine.New(snap, memory.New(), opts...)
}

func token(t *testing.T, sub string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"sub": sub})
	if err != nil {
		t.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
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

// A group is compared with the key of the predicate that names it after that
// key's normalization, and the group values are compared as written: a token
// whose org_id is ACME lands in a group that lists acme, because extraction
// lowercases the key, and a group that lists Acme matches no token, because
// nothing lowercases the group.
func TestInGroupComparesTheGroupAsWrittenWithTheNormalizedKey(t *testing.T) {
	engineWithGroupOf := func(t *testing.T, member string) *engine.Engine {
		t.Helper()
		p := model.Policy{
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
		}
		snap, problems := compile.Compile("core-1-core", domain, &p)
		if len(problems) != 0 {
			t.Fatalf("compile problems: %v", problems)
		}
		return engine.New(snap, memory.New())
	}
	requestOf := func(t *testing.T, orgID string) engine.Request {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"sub": "alice", "org_id": orgID})
		if err != nil {
			t.Fatal(err)
		}
		return engine.Request{Path: "/api/orders", Method: "GET",
			Token: "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"}
	}

	lowered := decide(t, engineWithGroupOf(t, "acme"), requestOf(t, "ACME"))
	if len(lowered.Rules) != 1 || lowered.Rules[0].Rule != "partners" {
		t.Errorf("org_id ACME against the group [acme]: rules = %+v, want [partners]", lowered.Rules)
	}

	asWritten := decide(t, engineWithGroupOf(t, "Acme"), requestOf(t, "acme"))
	if len(asWritten.Rules) != 0 {
		t.Errorf("org_id acme against the group [Acme]: rules = %+v, want none", asWritten.Rules)
	}
}

func TestBypassLiftsItsBlockOnly(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, orderRequest(t, "prometheus"))
	if !d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
	for _, r := range d.Rules {
		if r.Block == "cascade" {
			t.Errorf("rules = %+v: bypass must leave its own block uncounted", d.Rules)
		}
	}
	// Bypass lifts only its block: the additive total still counts.
	if len(d.Rules) != 1 || d.Rules[0].Block != "total" {
		t.Errorf("rules = %+v: want the total block alone", d.Rules)
	}
	if d.Headers == nil || d.Headers.Limit != 5000 {
		t.Errorf("headers = %+v: want the total window", d.Headers)
	}
}

func TestHeadersComeFromTheStrictestRule(t *testing.T) {
	e := newEngine(t)

	first := decide(t, e, orderRequest(t, "alice"))
	if !first.Allowed || first.Headers == nil {
		t.Fatalf("decision = %+v", first)
	}
	if first.Headers.Limit != 100 || first.Headers.Remaining != 99 {
		t.Errorf("headers = %+v: want the per-client minute window, the tightest of three", first.Headers)
	}
	if len(first.ExtractedKeys) != 1 || first.ExtractedKeys[0] != model.KeySub {
		t.Errorf("extracted keys = %v: the success counters need the key names", first.ExtractedKeys)
	}
	everyone := first.Rules[0]
	if everyone.Rule != "everyone" || everyone.Limit != 100 || everyone.Remaining != 99 {
		t.Errorf("rule outcome = %+v: per-rule numbers must come from its own strictest bucket", everyone)
	}

	second := decide(t, e, orderRequest(t, "alice"))
	if second.Headers.Remaining != 98 {
		t.Errorf("remaining = %d, want 98 on the second request", second.Headers.Remaining)
	}
}

// The headers name the rule whose window they report, as block and rule.
// The binding window here belongs to the second matched rule, behind a rule
// of two windows, so the bucket the headers come from has to be traced back
// across the first rule's buckets, on an admission, on a refusal that
// waiting cures, and on one it does not.
func TestHeaders_nameTheRuleOfTheStrictestWindow(t *testing.T) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{
		{Name: "api", Rules: []model.Rule{{Name: "loose", Rates: []model.Rate{
			{Requests: 1000, Period: time.Minute}, {Requests: 10000, Period: time.Hour}}}}},
		{Name: "exports", Rules: []model.Rule{{Name: "tight", Rates: []model.Rate{
			{Requests: 2, Period: time.Minute}}}}},
	}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())
	req := engine.Request{Path: "/x", Method: "GET"}
	named := func(step string, d engine.Decision) {
		t.Helper()
		if d.Headers == nil || d.Headers.Block != "exports" || d.Headers.Rule != "tight" ||
			d.Headers.Limit != 2 || d.Headers.PeriodSeconds != 60 {
			t.Errorf("%s: headers = %+v, want the exports/tight minute window", step, d.Headers)
		}
	}

	named("admission", decide(t, e, req))
	decide(t, e, req)
	refused := decide(t, e, req)
	if refused.Allowed || refused.Headers.RetryAfter <= 0 {
		t.Fatalf("decision = %+v: want a refusal waiting cures", refused)
	}
	named("refusal", refused)

	req.Cost = 3
	never := decide(t, engine.New(snap, memory.New()), req)
	if !never.CostExceedsCapacity {
		t.Fatalf("decision = %+v: want a refusal no waiting cures", never)
	}
	named("refusal no waiting cures", never)
}

// EffectiveWindow is the time until the window admits one request more, the
// t of the ratelimit field. For a GCRA counter within its capacity it is one
// emission interval or less, not the time until the bucket drains: at two per
// hour, a client that spent both requests gets the next one 1800 s later,
// while the bucket is empty only after 3600 s. A fixed window returns its
// quota at the boundary, and a window at its full capacity has nothing to
// return.
func TestHeaders_effectiveWindowIsTheTimeToTheNextRequest(t *testing.T) {
	compiled := func(algorithm string) *compile.Snapshot {
		p := model.Policy{Domain: domain, Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "exports", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Algorithm: algorithm}}}}}}}
		snap, problems := compile.Compile("core-1-core", domain, &p)
		if len(problems) != 0 {
			t.Fatalf("compile problems: %v", problems)
		}
		return snap
	}
	req := engine.Request{Path: "/x", Method: "GET"}
	// The store reads the clock on every decision, so each one sees the
	// bucket a few microseconds drained.
	near := func(got, want time.Duration) bool { return got <= want && got > want-time.Second }
	check := func(step string, h *engine.Headers, window, reset time.Duration) {
		t.Helper()
		if !near(h.EffectiveWindow, window) || !near(h.ResetAfter, reset) {
			t.Errorf("%s: effective window %s and reset %s, want %s and %s",
				step, h.EffectiveWindow, h.ResetAfter, window, reset)
		}
	}

	gcra := engine.New(compiled(""), memory.New())
	check("GCRA, first admission", decide(t, gcra, req).Headers, 30*time.Minute, 30*time.Minute)
	check("GCRA, second admission", decide(t, gcra, req).Headers, 30*time.Minute, time.Hour)
	refused := decide(t, gcra, req)
	check("GCRA, refusal", refused.Headers, 30*time.Minute, time.Hour)
	if refused.Headers.RetryAfter < refused.Headers.EffectiveWindow {
		t.Errorf("retry after %s is shorter than the effective window %s",
			refused.Headers.RetryAfter, refused.Headers.EffectiveWindow)
	}

	fixed := engine.New(compiled("FixedWindow"), memory.New())
	h := decide(t, fixed, req).Headers
	if h.EffectiveWindow <= 0 || h.EffectiveWindow != h.ResetAfter {
		t.Errorf("fixed window: effective window %s, want the reset %s", h.EffectiveWindow, h.ResetAfter)
	}

	req.Cost = 3
	if h := decide(t, engine.New(compiled(""), memory.New()), req).Headers; h.EffectiveWindow >= 0 {
		t.Errorf("a full window reports an effective window of %s", h.EffectiveWindow)
	}
}

// A policy change that lowers burst keeps the counter's depth, so the
// effective window counts until that depth drains to one request below the
// new capacity and can exceed one emission interval: at two per hour, four
// requests under burst 4 leave a depth of 7200 s, and under burst 1 the next
// request returns 7200 s later, four intervals. retry-after and
// x-ratelimit-reset carry the same wait.
func TestHeaders_effectiveWindowCarriesTheDebtOfALoweredBurst(t *testing.T) {
	compiled := func(burst int64) *compile.Snapshot {
		p := model.Policy{Domain: domain, Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "exports", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Burst: burst}}}}}}}
		snap, problems := compile.Compile("core-1-core", domain, &p)
		if len(problems) != 0 {
			t.Fatalf("compile problems: %v", problems)
		}
		return snap
	}
	req := engine.Request{Path: "/x", Method: "GET"}
	counters := memory.New()
	wide := engine.New(compiled(4), counters)
	for i := 0; i < 4; i++ {
		if d := decide(t, wide, req); !d.Allowed {
			t.Fatalf("request %d under burst 4 = %+v, want an admission", i+1, d.Headers)
		}
	}

	h := decide(t, engine.New(compiled(1), counters), req).Headers
	near := func(got, want time.Duration) bool { return got <= want && got > want-time.Second }
	if !near(h.EffectiveWindow, 2*time.Hour) || !near(h.RetryAfter, 2*time.Hour) || !near(h.ResetAfter, 2*time.Hour) {
		t.Errorf("under burst 1: effective window %s, retry after %s, reset %s, want 2h0m0s each",
			h.EffectiveWindow, h.RetryAfter, h.ResetAfter)
	}
}

func TestShadowReportsWithoutVetoing(t *testing.T) {
	e := newEngine(t)

	var last engine.Decision
	for i := range 11 {
		last = decide(t, e, orderRequest(t, "t1"))
		if !last.Allowed {
			t.Fatalf("request %d denied: a shadow rule influenced the verdict", i+1)
		}
	}

	if len(last.Rules) != 3 {
		t.Fatalf("rules = %+v, want trial, everyone, and total", last.Rules)
	}
	trial := last.Rules[0]
	if !trial.Shadow || trial.Allowed {
		t.Errorf("trial outcome = %+v: the exhausted shadow rule must report its would-be denial", trial)
	}
	if trial.Limit != 10 || trial.Remaining != 0 || trial.RetryAfter <= 0 {
		t.Errorf("trial outcome = %+v: the shadow's would-be numbers feed near-limit metrics and audit", trial)
	}
	if !last.Rules[1].Allowed {
		t.Errorf("everyone outcome = %+v: the enforcing rule is far from its limit", last.Rules[1])
	}
}

func TestDenialHeaders(t *testing.T) {
	e := newEngine(t)
	for i := range 100 {
		if d := decide(t, e, orderRequest(t, "alice")); !d.Allowed {
			t.Fatalf("request %d denied under a limit of 100", i+1)
		}
	}

	d := decide(t, e, orderRequest(t, "alice"))
	if d.Allowed {
		t.Fatal("request 101 admitted past a 100-per-minute window")
	}
	if d.Headers == nil || d.Headers.Limit != 100 || d.Headers.RetryAfter <= 0 {
		t.Errorf("headers = %+v: want the denying window with a positive retry hint", d.Headers)
	}
}

func TestCostSemantics(t *testing.T) {
	e := newEngine(t)

	req := orderRequest(t, "alice")
	req.Cost = 5
	if d := decide(t, e, req); d.Headers.Remaining != 95 {
		t.Errorf("remaining = %d after cost 5, want 95", d.Headers.Remaining)
	}

	req.Cost = 0 // the protocol default of one
	if d := decide(t, e, req); d.Headers.Remaining != 94 {
		t.Errorf("remaining = %d after the default cost, want 94", d.Headers.Remaining)
	}
}

func TestCostThatNeverFits(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")
	req.Cost = 200 // beyond the 100-burst minute window, within the others

	d := decide(t, e, req)
	if d.Allowed || !d.CostExceedsCapacity {
		t.Fatalf("decision = %+v: want a refusal no waiting cures", d)
	}
	if d.Headers.RetryAfter >= 0 {
		t.Errorf("retry after = %s: no retry hint may reach the response", d.Headers.RetryAfter)
	}
}

func TestExplicitKeysOverrideTheToken(t *testing.T) {
	e := newEngine(t)
	req := orderRequest(t, "alice")
	req.Keys = map[string][]string{model.KeySub: {"t1"}}

	d := decide(t, e, req)
	if len(d.Rules) != 3 || d.Rules[0].Rule != "trial" {
		t.Errorf("rules = %+v: explicit keys must win over the token's sub", d.Rules)
	}
}

func TestExtractionSkipsPropagate(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, engine.Request{Path: "/api/invoices/1", Method: "GET", Token: "garbage"})

	if len(d.Skips) != 1 || d.Skips[0].Reason != identity.SkipDecodeFailed {
		t.Fatalf("skips = %v, want one decode_failed for the planned sub key", d.Skips)
	}
	// The broken token degrades to anonymity: per-client rules skip, the
	// unconditional total still enforces.
	if !d.Allowed || d.Headers == nil || d.Headers.Limit != 5000 {
		t.Errorf("decision = %+v: want the total block only", d)
	}
}

func TestOutsideAllRulesIsAllowedWithoutHeaders(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, engine.Request{Path: "/health", Method: "GET"})
	if !d.Allowed || d.Headers != nil || len(d.Rules) != 0 {
		t.Errorf("decision = %+v: a request outside all rules passes with no headers", d)
	}
}

func TestHeadersAreDeterministicAcrossRuns(t *testing.T) {
	run := func() engine.Headers {
		e := newEngine(t)
		return *decide(t, e, orderRequest(t, "alice")).Headers
	}
	first := run()
	for range 3 {
		if got := run(); got != first {
			t.Fatalf("headers jittered across identical runs: %+v vs %+v", got, first)
		}
	}
}

// TestBucketBudgetBackstop reaches the runtime backstop the only way that is
// left: by editing a compiled snapshot.
//
// The compiler refuses a generation over the budget, so in the component this
// error is unreachable — which is the point of checking it here. An embedder
// that builds a snapshot by hand is outside the contract, and the backstop is
// what keeps that mistake from monopolizing the domain's shard.
func TestBucketBudgetBackstop(t *testing.T) {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	rules := make([]model.Rule, 0, 32)
	for ri := range 32 {
		rates := make([]model.Rate, 0, len(periods))
		for _, pd := range periods {
			rates = append(rates, model.Rate{Requests: 100, Period: pd})
		}
		rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", ri), Rates: rates})
	}
	p := model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: rules}}}

	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("32 rules x 4 rates is exactly the budget; problems: %v", problems)
	}
	if snap.DecisionBuckets != engine.MaxDecisionBuckets {
		t.Fatalf("DecisionBuckets = %d, want the budget of %d",
			snap.DecisionBuckets, engine.MaxDecisionBuckets)
	}

	// One bucket past the budget, added behind the compiler's back.
	extra := snap.Blocks[0]
	extra.Name = "smuggled"
	extra.Rules = extra.Rules[:1]
	snap.Blocks = append(snap.Blocks, extra)

	e := engine.New(snap, memory.New())
	_, err := e.Decide(t.Context(), engine.Request{Path: "/any", Method: "GET"})
	if !errors.Is(err, engine.ErrTooManyBuckets) {
		t.Fatalf("Decide error = %v, want ErrTooManyBuckets", err)
	}
}

// cacheProbe compiles one per-client rule that matches only alice: whether
// extraction saw the live token or a poisoned cache entry is visible in the
// number of applied rules.
func cacheProbe(t *testing.T, opts ...engine.Option) *engine.Engine {
	t.Helper()
	p := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "alice-only", Counters: []string{model.KeySub},
			Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"}},
			Rates:   []model.Rate{{Requests: 100, Period: time.Minute}}}},
	}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	return engine.New(snap, memory.New(), opts...)
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

	for step, tc := range []struct {
		req  engine.Request
		want int
	}{{overlaid, 0}, {clean, 1}, {overlaid, 0}, {clean, 1}} {
		if d := decide(t, e, tc.req); len(d.Rules) != tc.want {
			t.Fatalf("step %d: %d applied rules, want %d", step, len(d.Rules), tc.want)
		}
	}
}

func TestTokenCacheDisabledStillExtracts(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(0))
	if d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: token(t, "alice")}); len(d.Rules) != 1 {
		t.Fatalf("extraction without the cache must still see alice: %d applied rules", len(d.Rules))
	}
}

// TestTokenCacheRotationKeepsResultsExact churns a capacity-2 cache with
// three distinct tokens: generations rotate on nearly every insert, and every
// decision must still see its own token's identity.
func TestTokenCacheRotationKeepsResultsExact(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(2))
	subs := []string{"alice", "bob", "carol"}
	for i := range 12 {
		sub := subs[i%len(subs)]
		want := 0
		if sub == "alice" {
			want = 1
		}
		if d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: token(t, sub)}); len(d.Rules) != want {
			t.Fatalf("step %d (%s): %d applied rules, want %d", i, sub, len(d.Rules), want)
		}
	}
}

// TestNoTargetSkipsIdentityWork pins the lazy-extraction contract: a request
// outside every target reports neither skips nor extracted keys, because
// identity was never resolved for it.
func TestNoTargetSkipsIdentityWork(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, engine.Request{Path: "/metrics", Method: "GET", Token: "not-a-token"})
	if !d.Allowed {
		t.Fatal("a request outside every target is allowed")
	}
	if d.Skips != nil || d.ExtractedKeys != nil {
		t.Fatalf("identity must not be resolved outside every target: skips %v, keys %v", d.Skips, d.ExtractedKeys)
	}
}

// TestTokenCacheConcurrentChurn hammers a capacity-2 cache from several
// goroutines over three tokens: rotation and promotion race constantly, and
// every decision must still see its own token's identity. The race detector
// covers the locking; the asserts cover the results.
func TestTokenCacheConcurrentChurn(t *testing.T) {
	e := cacheProbe(t, engine.WithTokenCache(2))
	subs := []string{"alice", "bob", "carol"}
	tokens := make([]string, len(subs))
	for i, sub := range subs {
		tokens[i] = token(t, sub)
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() { churnTokenCache(t, e, subs, tokens, g) })
	}
	wg.Wait()
}

// churnTokenCache drives one goroutine's share of the churn: 200 decisions
// rotating through the tokens, each asserting it saw its own token's identity
// rather than a neighbor's.
func churnTokenCache(t *testing.T, e *engine.Engine, subs, tokens []string, g int) {
	t.Helper()
	for i := range 200 {
		n := (g + i) % len(subs)
		d, err := e.Decide(t.Context(), engine.Request{Path: "/x", Method: "GET", Token: tokens[n]})
		if err != nil {
			t.Errorf("Decide: %v", err)
			return
		}
		want := 0
		if subs[n] == "alice" {
			want = 1
		}
		if len(d.Rules) != want {
			t.Errorf("%s: %d applied rules, want %d", subs[n], len(d.Rules), want)
			return
		}
	}
}

// TestOversizedTokenBypassesTheCache pins the order of defenses: the token
// size bound applies before any hashing or caching, and an oversized token
// still reports its decode_failed skips exactly like the uncached path.
func TestOversizedTokenBypassesTheCache(t *testing.T) {
	e := cacheProbe(t)
	huge := "h." + strings.Repeat("A", identity.MaxTokenBytes) + ".s"
	d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: huge})
	if !d.Allowed || len(d.Rules) != 0 {
		t.Fatalf("an undecodable token carries no identity: allowed %v, rules %v", d.Allowed, d.Rules)
	}
	if len(d.Skips) != 1 || d.Skips[0].Reason != identity.SkipDecodeFailed {
		t.Fatalf("skips = %v, want one decode_failed", d.Skips)
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

	if hits, misses := stats.Hits(), stats.Misses(); hits != 1 || misses != 2 {
		t.Errorf("hits = %d, misses = %d, want 1 and 2", hits, misses)
	}
}

// Peek answers what Decide would answer, and charges nothing. It is what the
// management API reads through, so a listing reporting different numbers from
// the enforcing path would be worse than no listing at all.
func TestPeek_answersLikeDecideWithoutCharging(t *testing.T) {
	e := newEngine(t)
	req := engine.Request{Path: "/api/invoices/1", Method: "GET", Token: token(t, "alice")}

	first, err := e.Peek(t.Context(), req)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	second, err := e.Peek(t.Context(), req)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if first.Headers == nil || second.Headers == nil {
		t.Fatal("a matched request must carry headers")
	}
	if first.Headers.Remaining != second.Headers.Remaining {
		t.Errorf("remaining moved between peeks: %d then %d",
			first.Headers.Remaining, second.Headers.Remaining)
	}

	decided, err := e.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decided.Allowed != first.Allowed {
		t.Errorf("Decide allowed = %v, Peek predicted %v", decided.Allowed, first.Allowed)
	}
	if len(decided.Rules) != len(first.Rules) {
		t.Errorf("Decide applied %d rules, Peek %d; the two match the same way",
			len(decided.Rules), len(first.Rules))
	}

	// Decide charged, which is the whole difference between the two.
	after, err := e.Peek(t.Context(), req)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if after.Headers.Remaining != first.Headers.Remaining-1 {
		t.Errorf("remaining after Decide = %d, want one below the %d Peek reported",
			after.Headers.Remaining, first.Headers.Remaining)
	}
}

// The bucket budget is a property of the request rather than of the write, so
// Peek refuses an oversized decision exactly as Decide does. A management read
// that slipped past it would report numbers the enforcing path never produces.
func TestPeek_refusesTheSameOversizedDecisionAsDecide(t *testing.T) {
	snap := oversizedSnapshot(t)
	e := engine.New(snap, memory.New())
	req := engine.Request{Path: "/any", Method: "GET"}

	if _, err := e.Decide(t.Context(), req); !errors.Is(err, engine.ErrTooManyBuckets) {
		t.Fatalf("Decide error = %v, want ErrTooManyBuckets", err)
	}
	if _, err := e.Peek(t.Context(), req); !errors.Is(err, engine.ErrTooManyBuckets) {
		t.Errorf("Peek error = %v, want ErrTooManyBuckets", err)
	}
}

// oversizedSnapshot builds a domain one bucket past the budget. The compiler
// refuses such a generation, so the extra block goes in behind its back: what
// is under test is the engine's own backstop.
func oversizedSnapshot(t *testing.T) *compile.Snapshot {
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
	p := model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: rules}}}

	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("32 rules x 4 rates is exactly the budget; problems: %v", problems)
	}
	extra := snap.Blocks[0]
	extra.Name = "smuggled"
	extra.Rules = extra.Rules[:1]
	snap.Blocks = append(snap.Blocks, extra)
	return snap
}

// Among refusals, a cost that never fits binds harder than one waiting cures.
// Reporting the waiting window would send a caller back on a schedule that
// cannot help: the hour window will refuse the same cost forever.
func TestHeaders_capacityExceededOutranksALongerWait(t *testing.T) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{
			// Exhausted after one request of cost 5, and it recovers.
			{Name: "minute", Rates: []model.Rate{{Requests: 5, Period: time.Hour, Burst: 5}}},
			// A cost of 5 can never fit a bucket two deep.
			{Name: "never", Rates: []model.Rate{{Requests: 2, Period: time.Minute, Burst: 2}}},
		},
	}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())

	decision, err := e.Decide(t.Context(), engine.Request{Path: "/any", Method: "GET", Cost: 5})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a cost of 5 against a bucket of 2 must be refused")
	}
	if !decision.CostExceedsCapacity {
		t.Fatal("the refusal is a capacity one, and the decision has to say so")
	}
	if decision.Headers == nil {
		t.Fatal("a refusal carries headers")
	}
	if decision.Headers.Limit != 2 {
		t.Errorf("headers name the window with limit %d, want the one the cost can never fit (2)",
			decision.Headers.Limit)
	}
	if decision.Headers.RetryAfter >= 0 {
		t.Errorf("RetryAfter = %v, want no hint for a request no waiting cures",
			decision.Headers.RetryAfter)
	}
}

// Two windows the cost can never fit carry no retry hint to rank by, so the
// order falls to the bucket key. Declaration order would pick the other one,
// which is the point: the headers of a repeated refusal have to name the same
// window every time, whatever order the rules happen to be written in.
func TestHeaders_twoCapacityExceededWindowsTieBreakByKey(t *testing.T) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{
			// First in the snapshot, and the larger key.
			{Name: "zzz", Rates: []model.Rate{{Requests: 3, Period: time.Minute, Burst: 3}}},
			{Name: "aaa", Rates: []model.Rate{{Requests: 2, Period: time.Hour, Burst: 2}}},
		},
	}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())

	for attempt := range 3 {
		decision, err := e.Decide(t.Context(), engine.Request{Path: "/any", Method: "GET", Cost: 5})
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if !decision.CostExceedsCapacity {
			t.Fatal("a cost of 5 fits neither window, and the decision has to say so")
		}
		if decision.Headers == nil {
			t.Fatal("a refusal carries headers")
		}
		if decision.Headers.Limit != 2 {
			t.Errorf("attempt %d: headers name the window with limit %d, want the smaller key (2)",
				attempt, decision.Headers.Limit)
		}
		if decision.Headers.RetryAfter >= 0 {
			t.Errorf("attempt %d: RetryAfter = %v, want no hint for a request no waiting cures",
				attempt, decision.Headers.RetryAfter)
		}
	}
}

// Blocks reports what the target phase hit, in snapshot order, which is what
// the management API lists a path's rules from.
func TestCandidates_blocksReportsTheTargetedOnesInOrder(t *testing.T) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{
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
	}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}

	targeted := match.Match(snap, "/api/invoices/1", "GET").Blocks()
	got := make([]string, 0, len(targeted))
	for _, block := range targeted {
		got = append(got, block.Name)
	}
	want := []string{"invoices", "everything"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Blocks() = %v, want %v in snapshot order", got, want)
	}

	if blocks := match.Match(snap, "/nothing", "GET").Blocks(); len(blocks) != 1 || blocks[0].Name != "everything" {
		t.Errorf("a path outside every target still meets the block without one, got %v", blocks)
	}
}

// A rule outcome carries the capacity its remaining counts down from, next to
// the limit the headers carry: the burst of a GCRA window, and the requests
// of a fixed window, which has no burst. The near-limit margin is a share of
// that capacity.
func TestRuleOutcomeCarriesTheCapacityOfItsWindow(t *testing.T) {
	p := model.Policy{
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
	}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())

	d := decide(t, e, engine.Request{Path: "/api/orders", Method: "GET"})
	if len(d.Rules) != 2 {
		t.Fatalf("rules = %+v, want the two rules of the block", d.Rules)
	}
	want := map[string][2]int64{"burst": {1000, 100}, "fixed": {100, 100}}
	for _, r := range d.Rules {
		limit, capacity := want[r.Rule][0], want[r.Rule][1]
		if r.Limit != limit || r.Capacity != capacity {
			t.Errorf("rule %s: limit = %d, capacity = %d, want %d and %d", r.Rule, r.Limit, r.Capacity, limit, capacity)
		}
	}
}

// An extraction larger than the cache's entry bound is not cached: a stream
// of distinct tokens with a large array claim would otherwise hold the cache
// at its capacity times the claim, past a replica's memory limit. A small
// extraction is cached as before.
func TestTokenCacheSkipsALargeExtraction(t *testing.T) {
	p := model.Policy{Domain: domain,
		Mappings: []model.KeyMapping{{Key: "roles", Claim: "roles", Type: model.ValueStringArray}},
		Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{Name: "admins",
			Matches: []model.Predicate{{Key: "roles", Operator: model.OperatorContains, Value: "admin"}},
			Rates:   []model.Rate{{Requests: 100, Period: time.Minute}}}}}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	stats := &engine.CacheStats{}
	e := engine.New(snap, memory.New(), engine.WithCacheStats(stats))

	roles := make([]string, identity.MaxArrayItems)
	for i := range roles {
		roles[i] = fmt.Sprintf("role-%02d-%s", i, strings.Repeat("r", 54))
	}
	raw, err := json.Marshal(map[string]any{"sub": "alice", "roles": append(roles, "admin")[1:]})
	if err != nil {
		t.Fatal(err)
	}
	large := engine.Request{Path: "/x", Method: "GET", Token: "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"}
	decide(t, e, large)
	d := decide(t, e, large)
	if hits := stats.Hits(); hits != 0 {
		t.Errorf("a large extraction was cached: %d hits", hits)
	}
	if len(d.Rules) != 1 {
		t.Errorf("an uncached extraction decided differently: rules %v", d.Rules)
	}

	small := engine.Request{Path: "/x", Method: "GET", Token: token(t, "bob")}
	decide(t, e, small)
	decide(t, e, small)
	if hits := stats.Hits(); hits != 1 {
		t.Errorf("a small extraction was not cached: %d hits", hits)
	}
}

// The direct form's values are normalized as a token's are, so a direct
// caller's sub Alice and a token whose sub is Alice charge one counter:
// the overlay of unnormalized values was what made a counter the management
// API could not address.
func TestDecide_theDirectFormIsNormalizedLikeTheToken(t *testing.T) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{Name: "each",
		Counters: []string{model.KeySub}, Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}}}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())

	if d := decide(t, e, engine.Request{Path: "/x", Method: "GET", Token: token(t, "Alice")}); !d.Allowed {
		t.Fatal("the first request was refused")
	}
	direct := engine.Request{Path: "/x", Method: "GET", Keys: map[string][]string{model.KeySub: {"Alice"}}}
	if d := decide(t, e, direct); d.Allowed {
		t.Error("the direct form's Alice was counted apart from the token's")
	}
}
