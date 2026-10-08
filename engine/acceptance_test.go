package engine_test

// The acceptance suite: every rule pattern the schema promises to express,
// exercised end to end through the public API — a full policy, real tokens,
// sequences of requests. Every name, path, and client here is synthetic.

import (
	"slices"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// widgets is a request under /api/widgets/, anonymous when sub is empty.
func widgets(t *testing.T, sub string) engine.Request {
	t.Helper()
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

// Pattern 1: a shared counter over an enumerated group of clients — every member
// draws from one bucket, outsiders are untouched.
func TestAcceptanceSharedGroupBucket(t *testing.T) {
	partners := func(t *testing.T) *engine.Engine {
		t.Helper()
		return engineFor(t, model.Policy{
			Domain: domain,
			Groups: []model.Group{{Name: "partners", Values: []string{"partner-a", "partner-b"}}},
			Blocks: []model.Block{prefixBlock("api", model.Rule{
				Name:    "partners-shared",
				Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "partners"}},
				Rates:   []model.Rate{{Requests: 3, Period: time.Minute}},
			})},
		})
	}

	t.Run("members draw from one bucket", func(t *testing.T) {
		e := partners(t)
		decide(t, e, widgets(t, "partner-a"))
		decide(t, e, widgets(t, "partner-a"))
		decide(t, e, widgets(t, "partner-b"))
		if d := decide(t, e, widgets(t, "partner-b")); d.Allowed {
			t.Error("the fourth request of the group, from partner-b, was admitted past the shared limit of 3")
		}
	})
	t.Run("the exhausted group leaves a non-member unlimited", func(t *testing.T) {
		e := partners(t)
		decide(t, e, widgets(t, "partner-a"))
		decide(t, e, widgets(t, "partner-a"))
		decide(t, e, widgets(t, "partner-b"))
		if d := decide(t, e, widgets(t, "outsider")); !d.Allowed || d.Headers != nil {
			t.Errorf("Decide(outsider): allowed %t, headers %+v; want allowed with no headers", d.Allowed, d.Headers)
		}
	})
}

// Pattern 2: a targeted override on top of a base limit via replaces.
func TestAcceptanceOverrideOnTopOfBase(t *testing.T) {
	overridden := func(t *testing.T) *engine.Engine {
		t.Helper()
		return engineFor(t, model.Policy{
			Domain: domain,
			Groups: []model.Group{{Name: "vip", Values: []string{"partner-a"}}},
			Blocks: []model.Block{prefixBlock("api",
				model.Rule{Name: "base", Counters: []string{model.KeySub},
					Rates: []model.Rate{{Requests: 2, Period: time.Minute}}},
				model.Rule{Name: "vip",
					Matches:       []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "vip"}},
					Counters:      []string{model.KeySub},
					Rates:         []model.Rate{{Requests: 5, Period: time.Minute}},
					ReplacedRules: []string{"base"}},
			)},
		})
	}

	t.Run("a member lives on the override", func(t *testing.T) {
		e := overridden(t)
		for i := range 5 {
			if d := decide(t, e, widgets(t, "partner-a")); !d.Allowed {
				t.Fatalf("vip request %d was refused under the override of 5: the base of 2 still applied", i+1)
			}
		}
		if d := decide(t, e, widgets(t, "partner-a")); d.Allowed {
			t.Error("vip request 6 was admitted past the override limit of 5")
		}
	})
	t.Run("a non-member stays on the base", func(t *testing.T) {
		e := overridden(t)
		decide(t, e, widgets(t, "bob"))
		decide(t, e, widgets(t, "bob"))
		if d := decide(t, e, widgets(t, "bob")); d.Allowed {
			t.Error("request 3 of bob was admitted past the base limit of 2")
		}
	})
}

// Trying an override in Shadow before enforcing it: the live base limit keeps
// refusing while the shadow counts. A shadow rule's replacedRules used to
// remove the rule it named, and the trial switched the live limit off.
func TestAcceptanceShadowOverrideLeavesTheBaseEnforcing(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{prefixBlock("api",
			model.Rule{Name: "base", Counters: []string{model.KeySub},
				Rates: []model.Rate{{Requests: 2, Period: time.Minute}}},
			model.Rule{Name: "trial", Behavior: model.BehaviorShadow,
				Counters:      []string{model.KeySub},
				Rates:         []model.Rate{{Requests: 1, Period: time.Minute}},
				ReplacedRules: []string{"base"}},
		)},
	})

	decide(t, e, widgets(t, "bob"))
	decide(t, e, widgets(t, "bob"))
	if d := decide(t, e, widgets(t, "bob")); d.Allowed {
		t.Error("request 3 of bob was admitted past the base limit of 2: the shadow trial switched it off")
	}
}

// Pattern 3: role tiers from an array claim — the mapping extracts the array,
// Contains picks the tier, the tiers cascade.
func TestAcceptanceRoleTiersFromArrayClaim(t *testing.T) {
	tiers := func(t *testing.T) *engine.Engine {
		t.Helper()
		return engineFor(t, model.Policy{
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
						Counters: []string{model.KeySub},
						Rates:    []model.Rate{{Requests: 4, Period: time.Minute}}},
					{Name: "basic-tier", Counters: []string{model.KeySub},
						Rates: []model.Rate{{Requests: 2, Period: time.Minute}}},
				},
			}},
		})
	}
	request := func(t *testing.T, sub string, roles ...any) engine.Request {
		t.Helper()
		return engine.Request{Path: "/api/widgets/1", Method: "GET", Token: claimsToken(t, map[string]any{
			"sub": sub, "realm_access": map[string]any{"roles": roles},
		})}
	}

	t.Run("an admin lives on the admin tier", func(t *testing.T) {
		e := tiers(t)
		admin := request(t, "alice", "basic", "admin")
		for i := range 4 {
			if d := decide(t, e, admin); !d.Allowed {
				t.Fatalf("admin request %d was refused under the admin tier of 4", i+1)
			}
		}
		if d := decide(t, e, admin); d.Allowed {
			t.Error("admin request 5 was admitted past the admin tier of 4")
		}
	})
	t.Run("a member without admin falls to the basic tier", func(t *testing.T) {
		e := tiers(t)
		basic := request(t, "bob", "basic")
		decide(t, e, basic)
		decide(t, e, basic)
		if d := decide(t, e, basic); d.Allowed {
			t.Error("basic request 3 was admitted past the basic tier of 2: Contains matched the admin tier")
		}
	})
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
		t.Error("request 4, from carol, was admitted past the total of 3 that alice, bob, and an anonymous client spent")
	}
}

// Pattern 5: multiple windows on one rule — the fixed hour quota binds while
// the generous minute window still has room.
func TestAcceptanceMultiWindow(t *testing.T) {
	waitOutHourBoundary()
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{prefixBlock("api", model.Rule{
			Name: "per-user", Counters: []string{model.KeySub},
			Rates: []model.Rate{
				{Requests: 100, Period: time.Minute},
				{Requests: 3, Period: time.Hour, Algorithm: "FixedWindow"},
			},
		})},
	})

	for i := range 3 {
		if d := decide(t, e, widgets(t, "alice")); !d.Allowed {
			t.Fatalf("request %d was refused under the hour quota of 3", i+1)
		}
	}
	d := decide(t, e, widgets(t, "alice"))
	if d.Allowed {
		t.Fatal("request 4 was admitted past the hour quota of 3")
	}
	want := window{Block: "api", Rule: "per-user", Limit: 3, PeriodSeconds: 3600}
	if got := windowOf(headersOf(t, d)); got != want {
		t.Errorf("headers report %+v, want %+v: the hour quota binds, not the minute rate", got, want)
	}
}

// Pattern 6: a FirstMatch tier cascade with Bypass and Shadow steps, on the
// cascade the facade tests share. The bypass case repeats
// TestBypassLiftsItsBlockOnly so that the acceptance list holds every pattern.
func TestAcceptanceTierCascade(t *testing.T) {
	t.Run("the bypass step lifts the cascade", func(t *testing.T) {
		d := decide(t, newEngine(t), orderRequest(t, "prometheus"))
		if !d.Allowed {
			t.Errorf("Decide(prometheus).Allowed = false, want true")
		}
		if got, want := appliedRules(d), []string{"total/all"}; !slices.Equal(got, want) {
			t.Errorf("Decide(prometheus) applied %q, want %q", got, want)
		}
	})
	t.Run("a trial member meets the shadow step, then the enforcing one", func(t *testing.T) {
		d := decide(t, newEngine(t), orderRequest(t, "t1"))
		if !d.Allowed {
			t.Errorf("Decide(t1).Allowed = false, want true")
		}
		want := []string{"cascade/everyone", "cascade/trial", "total/all"}
		if got := appliedRules(d); !slices.Equal(got, want) {
			t.Errorf("Decide(t1) applied %q, want %q", got, want)
		}
		if trial := outcomeOf(t, d, "cascade", "trial"); !trial.Shadow {
			t.Errorf("Decide(t1): the trial outcome is %+v, want a shadow", trial)
		}
	})
}

// Pattern 7: anonymous-only limits via NotExists — anonymity is limited
// tightly, identified clients pass that rule by.
func TestAcceptanceAnonymousOnly(t *testing.T) {
	anonymousOnly := func(t *testing.T) *engine.Engine {
		t.Helper()
		return engineFor(t, model.Policy{
			Domain: domain,
			Blocks: []model.Block{prefixBlock("api",
				model.Rule{Name: "anonymous",
					Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorDoesNotExist}},
					Rates:   []model.Rate{{Requests: 2, Period: time.Minute}}},
				model.Rule{Name: "per-user", Counters: []string{model.KeySub},
					Rates: []model.Rate{{Requests: 5, Period: time.Minute}}},
			)},
		})
	}

	t.Run("anonymous clients share the anonymous limit", func(t *testing.T) {
		e := anonymousOnly(t)
		decide(t, e, widgets(t, ""))
		decide(t, e, widgets(t, ""))
		if d := decide(t, e, widgets(t, "")); d.Allowed {
			t.Error("anonymous request 3 was admitted past the anonymous limit of 2")
		}
	})
	t.Run("an identified client passes the exhausted anonymous rule by", func(t *testing.T) {
		e := anonymousOnly(t)
		decide(t, e, widgets(t, ""))
		decide(t, e, widgets(t, ""))
		d := decide(t, e, widgets(t, "alice"))
		if !d.Allowed {
			t.Errorf("Decide(alice).Allowed = false, want true")
		}
		if got, want := appliedRules(d), []string{"api/per-user"}; !slices.Equal(got, want) {
			t.Errorf("Decide(alice) applied %q, want %q", got, want)
		}
	})
}

// Pattern 8: blocks are additive — a per-client allowance under a total
// ceiling, and a request must satisfy both.
func TestAcceptanceAdditiveBlocks(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain: domain,
		Blocks: []model.Block{
			prefixBlock("api", model.Rule{
				Name: "per-user", Counters: []string{model.KeySub},
				Rates: []model.Rate{{Requests: 5, Period: time.Minute}},
			}),
			prefixBlock("guard", model.Rule{
				Name: "total", Rates: []model.Rate{{Requests: 3, Period: time.Minute}},
			}),
		},
	})

	for i := range 3 {
		if d := decide(t, e, widgets(t, "alice")); !d.Allowed {
			t.Fatalf("request %d was refused within both limits", i+1)
		}
	}
	d := decide(t, e, widgets(t, "alice"))
	if d.Allowed {
		t.Fatal("request 4 was admitted: the total of the guard block did not bind")
	}
	want := window{Block: "guard", Rule: "total", Limit: 3, PeriodSeconds: 60}
	if got := windowOf(headersOf(t, d)); got != want {
		t.Errorf("headers report %+v, want %+v: the refusal belongs to the guard block's total", got, want)
	}
	if got, want := appliedRules(d), []string{"api/per-user", "guard/total"}; !slices.Equal(got, want) {
		t.Errorf("request 4 applied %q, want %q: both blocks apply to one request", got, want)
	}
}

// waitOutHourBoundary keeps the fixed-window scenario from straddling a
// calendar boundary, best effort on the local clock. The memory store reads
// the process clock and offers no other, and a fixed window resets on the
// hour, so the scenario sleeps past a boundary less than ten seconds away
// rather than polling for a condition.
func waitOutHourBoundary() {
	now := time.Now()
	boundary := now.Truncate(time.Hour).Add(time.Hour)
	if wait := boundary.Sub(now); wait < 10*time.Second {
		time.Sleep(wait + time.Second)
	}
}
