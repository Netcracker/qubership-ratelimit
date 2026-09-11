package engine_test

// The acceptance suite: every rule pattern the schema promises to express,
// exercised end to end through the public API — a full policy, real tokens,
// sequences of requests. Every name, path, and client here is synthetic.

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

// engineFor compiles one synthetic policy — which is one domain — over a fresh
// store.
func engineFor(t *testing.T, p model.Policy) *engine.Engine {
	t.Helper()
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	return engine.New(snap, memory.New())
}

// claimsToken builds an unsigned test token from synthetic claims.
func claimsToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
}

func widgets(t *testing.T, sub string) engine.Request {
	req := engine.Request{Path: "/api/widgets/1", Method: "GET"}
	if sub != "" {
		req.Token = claimsToken(t, map[string]any{"sub": sub})
	}
	return req
}

func prefixBlock(name string, rules ...model.Rule) model.Block {
	return model.Block{
		Name: name,
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/widgets/"}}}},
		Rules: rules,
	}
}

// Pattern 1: a shared counter over an enumerated client group — every member
// draws from one bucket, outsiders are untouched.
func TestAcceptanceSharedGroupBucket(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "partners", Clients: []string{"partner-a", "partner-b"}}},
		Blocks: []model.Block{prefixBlock("api", model.Rule{
			Name:    "partners-shared",
			Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "partners"}},
			Rates:   []model.Rate{{Requests: 3, Period: time.Minute}},
		})},
	})

	// Three requests split between two members drain the one shared bucket.
	decide(t, e, widgets(t, "partner-a"))
	decide(t, e, widgets(t, "partner-a"))
	decide(t, e, widgets(t, "partner-b"))
	if d := decide(t, e, widgets(t, "partner-b")); d.Allowed {
		t.Error("request 4 admitted: the group did not share one bucket")
	}
	if d := decide(t, e, widgets(t, "outsider")); !d.Allowed || d.Headers != nil {
		t.Errorf("outsider decision = %+v: the group's exhaustion must not touch non-members", d)
	}
}

// Pattern 2: a targeted override on top of a base limit via replaces.
func TestAcceptanceOverrideOnTopOfBase(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Groups: []model.Group{{Name: "vip", Clients: []string{"partner-a"}}},
		Blocks: []model.Block{prefixBlock("api",
			model.Rule{Name: "base", Counters: []string{model.KeyClient},
				Rates: []model.Rate{{Requests: 2, Period: time.Minute}}},
			model.Rule{Name: "vip",
				Matches:       []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "vip"}},
				Counters:      []string{model.KeyClient},
				Rates:         []model.Rate{{Requests: 5, Period: time.Minute}},
				ReplacedRules: []string{"base"}},
		)},
	})

	for i := range 5 {
		if d := decide(t, e, widgets(t, "partner-a")); !d.Allowed {
			t.Fatalf("vip request %d denied: the override did not replace the base", i+1)
		}
	}
	if d := decide(t, e, widgets(t, "partner-a")); d.Allowed {
		t.Error("vip request 6 admitted past the override limit")
	}

	decide(t, e, widgets(t, "bob"))
	decide(t, e, widgets(t, "bob"))
	if d := decide(t, e, widgets(t, "bob")); d.Allowed {
		t.Error("plain request 3 admitted: the base limit did not hold")
	}
}

// Pattern 3: role tiers from an array claim — the mapping extracts the array,
// Contains picks the tier, the tiers cascade.
func TestAcceptanceRoleTiersFromArrayClaim(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Mappings: []model.KeyMapping{
			{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
		},
		Blocks: []model.Block{{
			Name: "tiers",
			Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{
				{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/widgets/"}}}},
			Rules: []model.Rule{
				{Name: "admin-tier",
					Matches:  []model.Predicate{{Key: "roles", Operator: model.OperatorContains, Value: "admin"}},
					Counters: []string{model.KeyClient},
					Rates:    []model.Rate{{Requests: 4, Period: time.Minute}}},
				{Name: "basic-tier", Counters: []string{model.KeyClient},
					Rates: []model.Rate{{Requests: 2, Period: time.Minute}}},
			},
		}},
	})
	request := func(sub string, roles ...any) engine.Request {
		return engine.Request{Path: "/api/widgets/1", Method: "GET", Token: claimsToken(t, map[string]any{
			"sub": sub, "realm_access": map[string]any{"roles": roles},
		})}
	}

	admin := request("alice", "basic", "admin")
	for i := range 4 {
		if d := decide(t, e, admin); !d.Allowed {
			t.Fatalf("admin request %d denied under the admin tier", i+1)
		}
	}
	if d := decide(t, e, admin); d.Allowed {
		t.Error("admin request 5 admitted past the admin tier")
	}

	basic := request("bob", "basic")
	decide(t, e, basic)
	decide(t, e, basic)
	if d := decide(t, e, basic); d.Allowed {
		t.Error("basic request 3 admitted: Contains matched the wrong tier")
	}
}

// Pattern 4: an unconditional per-API total shared by everyone.
func TestAcceptanceUnconditionalTotal(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{prefixBlock("api", model.Rule{
			Name: "total", Rates: []model.Rate{{Requests: 3, Period: time.Minute}},
		})},
	})

	decide(t, e, widgets(t, "alice"))
	decide(t, e, widgets(t, "bob"))
	decide(t, e, widgets(t, "")) // anonymous draws from the same bucket
	if d := decide(t, e, widgets(t, "carol")); d.Allowed {
		t.Error("request 4 admitted: the total must not care who asks")
	}
}

// Pattern 5: multiple windows on one rule — the fixed hour quota binds while
// the generous minute window still has room.
func TestAcceptanceMultiWindow(t *testing.T) {
	waitOutHourBoundary()
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{prefixBlock("api", model.Rule{
			Name: "per-user", Counters: []string{model.KeyClient},
			Rates: []model.Rate{
				{Requests: 100, Period: time.Minute},
				{Requests: 3, Period: time.Hour, Algorithm: "FixedWindow"},
			},
		})},
	})

	for i := range 3 {
		if d := decide(t, e, widgets(t, "alice")); !d.Allowed {
			t.Fatalf("request %d denied under the hour quota of 3", i+1)
		}
	}
	d := decide(t, e, widgets(t, "alice"))
	if d.Allowed {
		t.Fatal("request 4 admitted past the hour quota")
	}
	if d.Headers.Limit != 3 {
		t.Errorf("headers = %+v: the binding window is the hour quota, not the minute rate", d.Headers)
	}
}

// Pattern 6: a FirstMatch tier cascade with Bypass and Shadow steps — covered
// end to end by the facade tests over the same shape; this entry pins the
// pattern's place in the acceptance list.
func TestAcceptanceTierCascade(t *testing.T) {
	e := newEngine(t)
	if d := decide(t, e, quotes(t, "prometheus")); !d.Allowed {
		t.Error("the bypass step of the cascade failed")
	}
	trial := decide(t, e, quotes(t, "t1"))
	if !trial.Allowed || len(trial.Rules) != 3 || !trial.Rules[0].Shadow {
		t.Errorf("decision = %+v: shadow then enforce through the cascade", trial)
	}
}

// Pattern 7: anonymous-only limits via NotExists — anonymity is limited
// tightly, identified clients pass that rule by.
func TestAcceptanceAnonymousOnly(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{prefixBlock("api",
			model.Rule{Name: "anonymous",
				Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorDoesNotExist}},
				Rates:   []model.Rate{{Requests: 2, Period: time.Minute}}},
			model.Rule{Name: "per-user", Counters: []string{model.KeyClient},
				Rates: []model.Rate{{Requests: 5, Period: time.Minute}}},
		)},
	})

	decide(t, e, widgets(t, ""))
	decide(t, e, widgets(t, ""))
	if d := decide(t, e, widgets(t, "")); d.Allowed {
		t.Error("anonymous request 3 admitted past the anonymous limit")
	}
	if d := decide(t, e, widgets(t, "alice")); !d.Allowed || d.Headers.Limit != 5 {
		t.Errorf("decision = %+v: an identified client lives on per-user, untouched by the anonymous rule", d)
	}
}

// Pattern 8: blocks are additive — a per-client allowance under a total
// ceiling, and a request must satisfy both.
func TestAcceptanceAdditiveBlocks(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{
			prefixBlock("api", model.Rule{
				Name: "per-user", Counters: []string{model.KeyClient},
				Rates: []model.Rate{{Requests: 5, Period: time.Minute}},
			}),
			prefixBlock("guard", model.Rule{
				Name: "total", Rates: []model.Rate{{Requests: 3, Period: time.Minute}},
			}),
		},
	})

	for i := range 3 {
		if d := decide(t, e, widgets(t, "alice")); !d.Allowed {
			t.Fatalf("request %d denied too early", i+1)
		}
	}
	d := decide(t, e, widgets(t, "alice"))
	if d.Allowed {
		t.Fatal("request 4 admitted: the second block's total did not bind")
	}
	if d.Headers.Limit != 3 {
		t.Errorf("headers = %+v: the denial belongs to the guard block's total", d.Headers)
	}
	if len(d.Rules) != 2 {
		t.Errorf("rules = %+v: both blocks' rules apply to one request", d.Rules)
	}
}

// waitOutHourBoundary keeps the fixed-window scenario from straddling a
// calendar boundary, best effort on the local clock.
func waitOutHourBoundary() {
	now := time.Now()
	boundary := now.Truncate(time.Hour).Add(time.Hour)
	if wait := boundary.Sub(now); wait < 10*time.Second {
		time.Sleep(wait + time.Second)
	}
}
