package engine_test

import (
	"context"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The response headers come from the one enforcing bucket that binds the
// client: on a refusal the one with the longest wait, since every bucket has
// to admit the next request; on a refusal no wait cures, none at all; and a
// shadow rule never, whatever its numbers. Every client of the gateway reads
// these headers.

// wholeDomain is a policy of one block over the whole domain with rules.
func wholeDomain(rules ...model.Rule) model.Policy {
	return model.Policy{Domain: domain, Blocks: []model.Block{{Name: "b", Rules: rules}}}
}

// decideCost runs one decision of cost and fails the test on an error.
func decideCost(t *testing.T, e *engine.Engine, cost int64) engine.Decision {
	t.Helper()
	d, err := e.Decide(context.Background(), engine.Request{Path: "/x", Method: "GET", Cost: cost})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return d
}

func TestHeaders_aRefusalWaitsForTheBucketThatRecoversLast(t *testing.T) {
	e := engineFor(t, wholeDomain(
		model.Rule{Name: "per-minute", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}},
		model.Rule{Name: "per-hour", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}},
	))
	decideCost(t, e, 1)

	d := decideCost(t, e, 1)

	if d.Allowed || d.Headers == nil {
		t.Fatalf("second request: Allowed = %v, Headers = %+v; want a refusal with headers", d.Allowed, d.Headers)
	}
	if d.Headers.Rule != "per-hour" {
		t.Errorf("headers from rule %q, want per-hour, the bucket that recovers last", d.Headers.Rule)
	}
	if d.Headers.RetryAfter < 59*time.Minute {
		t.Errorf("RetryAfter = %v, want about an hour: a retry before it is refused again", d.Headers.RetryAfter)
	}
}

func TestHeaders_aCostNoWindowHoldsCarriesNoRetryHint(t *testing.T) {
	e := engineFor(t, wholeDomain(
		model.Rule{Name: "small", Rates: []model.Rate{{Requests: 100, Period: time.Hour, Burst: 3}}},
		model.Rule{Name: "spent", Rates: []model.Rate{{Requests: 5, Period: time.Minute}}},
	))
	// Leaves spent 2 of 5: a cost of 5 waits for it, and never fits small.
	decideCost(t, e, 3)

	d := decideCost(t, e, 5)

	if d.Allowed {
		t.Fatal("cost 5 admitted into a burst of 3")
	}
	if !d.CostExceedsCapacity {
		t.Error("CostExceedsCapacity is false beside a bucket the cost can never fit, while another bucket only waits")
	}
	if d.Headers == nil || d.Headers.RetryAfter >= 0 || d.Headers.Rule != "small" {
		t.Errorf("Headers = %+v; want the window the cost never fits, with no retry hint", d.Headers)
	}
}

func TestHeaders_aShadowRuleNeverSourcesTheHeaders(t *testing.T) {
	e := engineFor(t, wholeDomain(
		model.Rule{Name: "enforced", Rates: []model.Rate{{Requests: 100, Period: time.Minute}}},
		model.Rule{Name: "trial", Behavior: model.BehaviorShadow, Rates: []model.Rate{{Requests: 1, Period: time.Minute}}},
	))
	decideCost(t, e, 1)

	d := decideCost(t, e, 1)

	if !d.Allowed {
		t.Fatal("a shadow rule over its limit refused the request")
	}
	if d.Headers == nil || d.Headers.Rule != "enforced" || d.Headers.Limit != 100 {
		t.Errorf("Headers = %+v; want the enforced rule's window, limit 100", d.Headers)
	}
}
