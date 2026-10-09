package engine_test

import (
	"context"
	"slices"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// A key is a set: a value a direct consumer sends twice, or in two spellings
// a Lowercase mapping folds into one, is one value, so Equals holds and the
// key can be a counter axis. Such keys used to match neither, and the rules
// over them were silently not applied. Two different values stay ambiguous.
func TestDecide_readsARepeatedValueOfAKeyOnce(t *testing.T) {
	e := engineFor(t, model.Policy{
		Domain:   domain,
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "tenant", Normalization: model.NormalizeLowercase}},
		Blocks: []model.Block{{Name: "b", Rules: []model.Rule{
			{Name: "alice", Matches: []model.Predicate{{Key: model.KeySub, Operator: model.OperatorEquals, Value: "alice"}},
				Rates: []model.Rate{{Requests: 100, Period: time.Hour}}},
			{Name: "per-sub", Counters: []string{model.KeySub}, Rates: []model.Rate{{Requests: 100, Period: time.Hour}}},
			{Name: "per-tenant", Counters: []string{"tenant"}, Rates: []model.Rate{{Requests: 100, Period: time.Hour}}},
		}}},
	})

	for _, tc := range []struct {
		name string
		keys map[string][]string
		want []string
	}{
		{"one value", map[string][]string{model.KeySub: {"alice"}}, []string{"alice", "per-sub"}},
		{"a value sent twice", map[string][]string{model.KeySub: {"alice", "alice"}}, []string{"alice", "per-sub"}},
		{"two spellings lowercased into one", map[string][]string{"tenant": {"Acme", "acme"}}, []string{"per-tenant"}},
		{"two different values", map[string][]string{model.KeySub: {"alice", "bob"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := e.Peek(context.Background(), engine.Request{Path: "/x", Method: "GET", Keys: tc.keys})
			if err != nil {
				t.Fatalf("Peek: %v", err)
			}
			applied := make([]string, 0, len(d.Rules))
			for _, r := range d.Rules {
				applied = append(applied, r.Rule)
			}
			if !slices.Equal(applied, tc.want) {
				t.Errorf("rules applied to %v: %v, want %v", tc.keys, applied, tc.want)
			}
		})
	}
}
