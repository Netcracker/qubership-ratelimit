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
		Name:   "quote-api",
		Domain: domain,
		Groups: []model.Group{{Name: "trial", Clients: []string{"t1"}}},
		Blocks: []model.Block{
			{
				Name: "cascade",
				Mode: model.ModeFirstMatch,
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/quotes/"}}}},
				Rules: []model.Rule{
					{Name: "internal", Behavior: model.BehaviorBypass,
						When: []model.Condition{
							{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "prometheus"}}},
					{Name: "trial", Behavior: model.BehaviorShadow, Counters: []string{model.KeyClient},
						When: []model.Condition{
							{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "trial"}},
						Rates: []model.Rate{{Requests: 10, Period: time.Minute}}},
					{Name: "everyone", Counters: []string{model.KeyClient},
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
	snap, problems := compile.Compile(domain, []model.Policy{p}, nil)
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

func quotes(t *testing.T, sub string) engine.Request {
	return engine.Request{Path: "/api/quotes/1", Method: "GET", Token: token(t, sub)}
}

func decide(t *testing.T, e *engine.Engine, req engine.Request) engine.Decision {
	t.Helper()
	d, err := e.Decide(t.Context(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return d
}

func TestBypassLiftsItsBlockOnly(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, quotes(t, "prometheus"))
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

	first := decide(t, e, quotes(t, "alice"))
	if !first.Allowed || first.Headers == nil {
		t.Fatalf("decision = %+v", first)
	}
	if first.Headers.Limit != 100 || first.Headers.Remaining != 99 {
		t.Errorf("headers = %+v: want the per-client minute window, the tightest of three", first.Headers)
	}
	if len(first.ExtractedKeys) != 1 || first.ExtractedKeys[0] != model.KeyClient {
		t.Errorf("extracted keys = %v: the success counters need the key names", first.ExtractedKeys)
	}
	everyone := first.Rules[0]
	if everyone.Rule != "everyone" || everyone.Limit != 100 || everyone.Remaining != 99 {
		t.Errorf("rule outcome = %+v: per-rule numbers must come from its own strictest bucket", everyone)
	}

	second := decide(t, e, quotes(t, "alice"))
	if second.Headers.Remaining != 98 {
		t.Errorf("remaining = %d, want 98 on the second request", second.Headers.Remaining)
	}
}

func TestShadowReportsWithoutVetoing(t *testing.T) {
	e := newEngine(t)

	var last engine.Decision
	for i := range 11 {
		last = decide(t, e, quotes(t, "t1"))
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
		if d := decide(t, e, quotes(t, "alice")); !d.Allowed {
			t.Fatalf("request %d denied under a limit of 100", i+1)
		}
	}

	d := decide(t, e, quotes(t, "alice"))
	if d.Allowed {
		t.Fatal("request 101 admitted past a 100-per-minute window")
	}
	if d.Headers == nil || d.Headers.Limit != 100 || d.Headers.RetryAfter <= 0 {
		t.Errorf("headers = %+v: want the denying window with a positive retry hint", d.Headers)
	}
}

func TestCostSemantics(t *testing.T) {
	e := newEngine(t)

	req := quotes(t, "alice")
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
	req := quotes(t, "alice")
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
	req := quotes(t, "alice")
	req.Keys = map[string][]string{model.KeyClient: {"t1"}}

	d := decide(t, e, req)
	if len(d.Rules) != 3 || d.Rules[0].Rule != "trial" {
		t.Errorf("rules = %+v: explicit keys must win over the token's sub", d.Rules)
	}
}

func TestExtractionSkipsPropagate(t *testing.T) {
	e := newEngine(t)
	d := decide(t, e, engine.Request{Path: "/api/quotes/1", Method: "GET", Token: "garbage"})

	if len(d.Skips) != 1 || d.Skips[0].Reason != identity.SkipDecodeFailed {
		t.Fatalf("skips = %v, want one decode_failed for the planned client key", d.Skips)
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
		return *decide(t, e, quotes(t, "alice")).Headers
	}
	first := run()
	for range 3 {
		if got := run(); got != first {
			t.Fatalf("headers jittered across identical runs: %+v vs %+v", got, first)
		}
	}
}

// TestBucketBudgetBackstop stacks three policies, each compiling exactly at
// the per-policy budget and targeting the whole domain: together they exceed
// what one decision may carry, and the engine refuses before the store.
func TestBucketBudgetBackstop(t *testing.T) {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	policies := make([]model.Policy, 0, 3)
	for pi := range 3 {
		rules := make([]model.Rule, 0, 16)
		for ri := range 16 {
			rates := make([]model.Rate, 0, len(periods))
			for _, pd := range periods {
				rates = append(rates, model.Rate{Requests: 100, Period: pd})
			}
			rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", ri), Rates: rates})
		}
		policies = append(policies, model.Policy{
			Name: fmt.Sprintf("p%d", pi), Domain: domain,
			Blocks: []model.Block{{Name: "b", Rules: rules}}})
	}
	snap, problems := compile.Compile(domain, policies, nil)
	for _, p := range problems {
		if p.Blocking {
			t.Fatalf("compile problems: %v", problems)
		}
	}
	// The oversized set compiles whole, but not silently: the domain-level
	// informational record is the compile-time face of the same budget.
	domainWarned := false
	for _, p := range problems {
		if p.Reason == compile.ReasonDomainBudgetExceeded && p.Policy == "" {
			domainWarned = true
		}
	}
	if !domainWarned {
		t.Fatalf("problems = %v, want an informational DomainBudgetExceeded record", problems)
	}

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
	p := model.Policy{Name: "probe", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "alice-only", Counters: []string{model.KeyClient},
			When:  []model.Condition{{Key: model.KeyClient, Operator: model.OperatorEquals, Value: "alice"}},
			Rates: []model.Rate{{Requests: 100, Period: time.Minute}}}},
	}}}
	snap, problems := compile.Compile(domain, []model.Policy{p}, nil)
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
		Keys: map[string][]string{model.KeyClient: {"mallory"}}}
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
		wg.Go(func() {
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
		})
	}
	wg.Wait()
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

	decide(t, e, engine.Request{Path: "/api/quotes/1", Method: "GET", Token: token(t, "alice")})
	decide(t, e, engine.Request{Path: "/api/quotes/1", Method: "GET", Token: token(t, "alice")})
	decide(t, e, engine.Request{Path: "/api/quotes/1", Method: "GET"})
	decide(t, e, engine.Request{Path: "/api/quotes/1", Method: "GET", Token: token(t, "bob")})

	if hits, misses := stats.Hits(), stats.Misses(); hits != 1 || misses != 2 {
		t.Errorf("hits = %d, misses = %d, want 1 and 2", hits, misses)
	}
}
