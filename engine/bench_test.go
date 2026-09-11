package engine_test

// Layered benchmarks of the request path: the full pipeline first, then each
// stage in isolation, so a regression names its layer itself.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/identity"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/match"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

// benchSnapshot compiles a realistic domain: an array-claim mapping, a
// cascade block, and a domain total — two applied rules and three buckets
// per authenticated request (the vip and admin rules do not match the bench
// identity). Limits sit far above any benchtime iteration count, so the
// loops measure the admitted path — the one that writes state;
// BenchmarkDecideDenied pins the refusal path.
func benchSnapshot(b *testing.B) *compile.Snapshot {
	b.Helper()
	p := model.Policy{
		Domain: domain,
		Mappings: []model.KeyMapping{
			{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
		},
		Groups: []model.Group{{Name: "vip", Clients: []string{"partner-a", "partner-b"}}},
		Blocks: []model.Block{
			{
				Name: "api", Mode: model.ModeFirstMatch,
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/widgets/"}}}},
				Rules: []model.Rule{
					{Name: "vip", Counters: []string{model.KeyClient},
						Matches: []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "vip"}},
						Rates:   []model.Rate{{Requests: 1000, Period: time.Minute}}},
					{Name: "admin", Counters: []string{model.KeyClient},
						Matches: []model.Predicate{{Key: "roles", Operator: model.OperatorContains, Value: "admin"}},
						Rates:   []model.Rate{{Requests: 500, Period: time.Minute}}},
					{Name: "everyone", Counters: []string{model.KeyClient},
						Rates: []model.Rate{
							{Requests: 6_000_000, Period: time.Minute},
							{Requests: 1_000_000_000, Period: time.Hour, Algorithm: "FixedWindow"}}},
				},
			},
			{
				Name: "total",
				Target: model.Target{Routes: []model.Route{
					{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
				Rules: []model.Rule{{Name: "all",
					Rates: []model.Rate{{Requests: 60_000_000, Period: time.Minute}}}},
			},
		},
	}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		b.Fatalf("compile problems: %v", problems)
	}
	return snap
}

func benchToken(b *testing.B) string {
	b.Helper()
	raw, err := json.Marshal(map[string]any{
		"sub": "alice", "iss": "https://idp.example", "exp": 1900000000,
		"realm_access": map[string]any{"roles": []any{"basic", "reporting"}},
	})
	if err != nil {
		b.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
}

func BenchmarkDecideAuthed(b *testing.B) {
	e := engine.New(benchSnapshot(b), memory.New())
	req := engine.Request{Path: "/api/widgets/1", Method: "GET", Token: benchToken(b)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.Decide(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecidePreExtracted(b *testing.B) {
	e := engine.New(benchSnapshot(b), memory.New())
	req := engine.Request{Path: "/api/widgets/1", Method: "GET",
		Keys: map[string][]string{model.KeyClient: {"alice"}, "roles": {"basic", "reporting"}}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.Decide(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecideAuthedNoCache(b *testing.B) {
	e := engine.New(benchSnapshot(b), memory.New(), engine.WithTokenCache(0))
	req := engine.Request{Path: "/api/widgets/1", Method: "GET", Token: benchToken(b)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.Decide(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecideNoTarget(b *testing.B) {
	e := engine.New(benchSnapshot(b), memory.New())
	req := engine.Request{Path: "/metrics", Method: "GET", Token: benchToken(b)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.Decide(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecideDenied pins the refusal path: a one-request window is
// exhausted by the first iteration, and every later decision is refused
// without a state write.
func BenchmarkDecideDenied(b *testing.B) {
	p := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name:  "b",
		Rules: []model.Rule{{Name: "one", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		b.Fatalf("compile problems: %v", problems)
	}
	e := engine.New(snap, memory.New())
	req := engine.Request{Path: "/x", Method: "GET"}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := e.Decide(b.Context(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecideParallel(b *testing.B) {
	e := engine.New(benchSnapshot(b), memory.New())
	req := engine.Request{Path: "/api/widgets/1", Method: "GET", Token: benchToken(b)}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.Decide(b.Context(), req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkIdentityExtract(b *testing.B) {
	snap := benchSnapshot(b)
	tok := benchToken(b)
	b.ReportAllocs()
	for b.Loop() {
		identity.Extract(snap.Extraction, tok)
	}
}

func BenchmarkMatchTargets(b *testing.B) {
	snap := benchSnapshot(b)
	b.ReportAllocs()
	for b.Loop() {
		match.Match(snap, "/api/widgets/1", "GET")
	}
}

func BenchmarkMatchEvaluate(b *testing.B) {
	snap := benchSnapshot(b)
	keys := map[string][]string{model.KeyClient: {"alice"}, "roles": {"basic", "reporting"}}
	b.ReportAllocs()
	for b.Loop() {
		match.Match(snap, "/api/widgets/1", "GET").Evaluate(keys)
	}
}

// BenchmarkMatchManyBlocks scans a domain of 64 single-rule blocks whose
// routes all miss until the last one: the worst case of the linear target
// scan, and the number that decides whether a route index is worth its
// complexity.
func BenchmarkMatchManyBlocks(b *testing.B) {
	const blocks = 64
	p := model.Policy{Domain: domain}
	for i := range blocks {
		routes := make([]model.Route, 0, 4)
		for _, sub := range []string{"a", "b", "c", "d"} {
			routes = append(routes, model.Route{
				Path: model.PathMatch{Type: model.PathPrefix, Value: fmt.Sprintf("/svc%d/%s/", i, sub)}})
		}
		p.Blocks = append(p.Blocks, model.Block{
			Name:   fmt.Sprintf("b%d", i),
			Target: model.Target{Routes: routes},
			Rules: []model.Rule{{Name: "all",
				Rates: []model.Rate{{Requests: 100, Period: time.Minute}}}},
		})
	}
	snap, problems := compile.Compile("core-1-core", domain, &p)
	if len(problems) != 0 {
		b.Fatalf("compile problems: %v", problems)
	}
	path := fmt.Sprintf("/svc%d/d/x", blocks-1)
	b.ReportAllocs()
	for b.Loop() {
		match.Match(snap, path, "GET")
	}
}

func BenchmarkKeyBucket(b *testing.B) {
	snap := benchSnapshot(b)
	rate := snap.Blocks[0].Rules[2].Rates[0]
	axes := []string{"alice"}
	b.ReportAllocs()
	for b.Loop() {
		key.Bucket(rate.Prefix, axes)
	}
}

func BenchmarkMemoryStoreDecide(b *testing.B) {
	s := memory.New()
	snap := benchSnapshot(b)
	keys := map[string][]string{model.KeyClient: {"alice"}}
	buckets := match.Match(snap, "/api/widgets/1", "GET").Evaluate(keys).Buckets()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Decide(b.Context(), buckets, 1); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMemoryStoreBuckets sweeps the bucket count of one decision, up to
// the per-policy budget: store cost is linear in buckets, and this pins the
// slope.
func BenchmarkMemoryStoreBuckets(b *testing.B) {
	for _, n := range []int{1, 4, 8, 16, 64} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			s := memory.New()
			buckets := make([]store.Bucket, n)
			for i := range buckets {
				w := algo.Window{Requests: 60_000_000, Period: time.Minute, Burst: 60_000_000}
				id := algo.GCRAID
				if i%2 == 1 {
					w = algo.Window{Requests: 1_000_000_000, Period: time.Hour}
					id = algo.FixedWindowID
				}
				buckets[i] = store.Bucket{Key: fmt.Sprintf("bench:{sweep}:%d:", i), Algorithm: id, Window: w}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.Decide(b.Context(), buckets, 1); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
