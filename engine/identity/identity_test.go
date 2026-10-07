package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// plan compiles the extraction plan the way production gets it, so these
// tests exercise the real compile output, not a hand-built lookalike.
func plan(t testing.TB) []compile.KeyExtraction {
	t.Helper()
	snap, problems := compile.Compile("core-1-core", "gateway.public", &model.Policy{
		Domain: "gateway.public",
		Mappings: []model.KeyMapping{
			{Key: "roles", Claim: "realm_access.roles", Type: model.ValueStringArray},
			{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}, Normalization: model.NormalizeLowercase},
		},
		Blocks: []model.Block{{
			Name:  "b",
			Rules: []model.Rule{{Name: "r", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}},
		}},
	})
	if len(problems) != 0 {
		t.Fatalf("compile problems: %v", problems)
	}
	return snap.Extraction
}

func token(t testing.TB, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func skipsOf(skips []Skip) map[string]SkipReason {
	out := map[string]SkipReason{}
	for _, s := range skips {
		out[s.Key] = s.Reason
	}
	return out
}

func TestExtract(t *testing.T) {
	p := plan(t)
	tok := token(t, map[string]any{
		"sub":          "Alice",
		"org_id":       "ACME",
		"realm_access": map[string]any{"roles": []any{"user", "admin"}},
	})

	keys, skips := Extract(p, tok)
	if len(skips) != 0 {
		t.Fatalf("unexpected skips: %v", skips)
	}
	want := map[string][]string{
		"sub":    {"alice"},         // built-in: sub, lowercased
		"tenant": {"acme"},          // normalized
		"roles":  {"user", "admin"}, // array claim through the dot path
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

func TestBearerPrefixAndPadding(t *testing.T) {
	p := plan(t)
	raw, _ := json.Marshal(map[string]any{"sub": "bob"})
	padded := "h." + base64.URLEncoding.EncodeToString(raw) + ".sig"

	keys, skips := Extract(p, "Bearer "+padded)
	if len(skips) != 0 || len(keys["sub"]) != 1 || keys["sub"][0] != "bob" {
		t.Errorf("keys = %v, skips = %v: bearer prefix and padded base64 must both be accepted", keys, skips)
	}
}

func TestMissingTokenIsNotAnError(t *testing.T) {
	keys, skips := Extract(plan(t), "  ")
	if keys != nil || skips != nil {
		t.Errorf("keys = %v, skips = %v: a missing token is anonymous traffic, not an anomaly", keys, skips)
	}
}

func TestUndecodableTokenSkipsEveryKey(t *testing.T) {
	p := plan(t)
	for _, tok := range []string{"garbage", "a.b.c", "h." + strings.Repeat("x", MaxTokenBytes+1) + ".s"} {
		keys, skips := Extract(p, tok)
		if len(keys) != 0 || len(skips) != len(p) {
			t.Fatalf("token %.16q: keys = %v, skips = %d, want a decode_failed skip per planned key",
				tok, keys, len(skips))
		}
		for _, s := range skips {
			if s.Reason != SkipDecodeFailed {
				t.Fatalf("skip = %v, want decode_failed", s)
			}
		}
	}
}

func TestFallbacks(t *testing.T) {
	const carol = "carol"
	p := plan(t)

	// org_id is absent: tenant falls back to sub.
	keys, skips := Extract(p, token(t, map[string]any{"sub": carol}))
	if len(skips) != 0 || keys["tenant"][0] != carol {
		t.Errorf("keys = %v, skips = %v: want the fallback to sub", keys, skips)
	}

	// org_id is empty: emptiness is absence, the fallback still fires.
	keys, _ = Extract(p, token(t, map[string]any{"sub": carol, "org_id": ""}))
	if keys["tenant"][0] != carol {
		t.Errorf("keys = %v: an empty claim must keep falling back", keys)
	}

	// A bad-typed primary reports the anomaly and the fallback still serves.
	keys, skips = Extract(p, token(t, map[string]any{"sub": carol, "org_id": 42}))
	if keys["tenant"][0] != carol || skipsOf(skips)["tenant"] != SkipBadType {
		t.Errorf("keys = %v, skips = %v: want the value from the fallback and the bad_type skip", keys, skips)
	}
}

func TestSanitaryLimits(t *testing.T) {
	p := plan(t)

	long := strings.Repeat("x", MaxValueBytes+1)
	keys, skips := Extract(p, token(t, map[string]any{"sub": long}))
	if _, present := keys["sub"]; present || skipsOf(skips)["sub"] != SkipTooLong {
		t.Errorf("keys = %v, skips = %v: want too_long and no sub key", keys, skips)
	}

	items := make([]any, MaxArrayItems+1)
	for i := range items {
		items[i] = "r"
	}
	keys, skips = Extract(p, token(t, map[string]any{
		"realm_access": map[string]any{"roles": items},
	}))
	if _, present := keys["roles"]; present || skipsOf(skips)["roles"] != SkipTooManyItems {
		t.Errorf("keys = %v, skips = %v: want too_many_items and no roles key", keys, skips)
	}

	keys, skips = Extract(p, token(t, map[string]any{
		"realm_access": map[string]any{"roles": "admin"},
	}))
	if _, present := keys["roles"]; present || skipsOf(skips)["roles"] != SkipBadType {
		t.Errorf("keys = %v, skips = %v: a scalar under an array-typed key is bad_type", keys, skips)
	}
}

func TestAbsenceIsSilent(t *testing.T) {
	keys, skips := Extract(plan(t), token(t, map[string]any{"iss": "idp"}))
	if len(keys) != 0 || len(skips) != 0 {
		t.Errorf("keys = %v, skips = %v: merely absent claims are not anomalies", keys, skips)
	}
}

// FuzzExtract pins the two properties that matter for a parser of untrusted
// bytes in the request path: it never panics, and its outputs respect the
// sanitary bounds regardless of input shape.
func FuzzExtract(f *testing.F) {
	p := []compile.KeyExtraction{
		{Key: "sub", Path: []string{"sub"}, Type: model.ValueString, Normalization: model.NormalizeLowercase},
		{Key: "roles", Path: []string{"a", "b"}, Type: model.ValueStringArray},
		{Key: "tenant", Path: []string{"org"}, Type: model.ValueString, Fallbacks: [][]string{{"sub"}}},
	}
	f.Add("h.eyJzdWIiOiJhbGljZSJ9.s")
	f.Add("Bearer h.eyJhIjp7ImIiOlsieCJdfX0.s")
	f.Add("")
	f.Add("....")
	f.Add("h." + strings.Repeat("A", 1000) + ".s")

	f.Fuzz(func(t *testing.T, tok string) {
		keys, _ := Extract(p, tok)
		for k, values := range keys {
			if len(values) > MaxArrayItems {
				t.Fatalf("key %s carries %d values past the bound", k, len(values))
			}
			for _, v := range values {
				if len(v) > MaxValueBytes {
					t.Fatalf("key %s carries a value of %d bytes past the bound", k, len(v))
				}
			}
		}
	})
}

// nested builds a payload claim that nests depth levels deep.
func nested(depth int) any {
	var v any = "x"
	for range depth {
		v = map[string]any{"n": v}
	}
	return v
}

// A payload past the shape bounds is undecodable whatever its size: the
// bound on its size alone left the decode free to cost many times a realistic
// token's. A string that only looks like structure counts for nothing.
func TestShapeLimits(t *testing.T) {
	p := plan(t)
	ok := func(claims map[string]any) bool {
		_, skips := Extract(p, token(t, claims))
		return skipsOf(skips)["sub"] != SkipDecodeFailed
	}

	// The payload object itself is the first level.
	if !ok(map[string]any{"sub": "alice", "deep": nested(MaxPayloadDepth - 1)}) {
		t.Error("a payload at the depth bound was refused")
	}
	if ok(map[string]any{"sub": "alice", "deep": nested(MaxPayloadDepth)}) {
		t.Error("a payload past the depth bound was decoded")
	}

	// The object's claims take 2n-1 separators and the pair's comma one more,
	// so n claims reach the bound exactly at 2n.
	wide := map[string]any{"sub": "alice", "pair": []int{1, 1}}
	for i := 0; len(wide)*2 < MaxPayloadSeparators; i++ {
		wide[fmt.Sprintf("c%04d", i)] = 1
	}
	if !ok(wide) {
		t.Errorf("a payload of %d claims, at the separator bound, was refused", len(wide))
	}
	wide["past"] = 1
	if ok(wide) {
		t.Errorf("a payload of %d claims, past the separator bound, was decoded", len(wide))
	}

	if !ok(map[string]any{"sub": "alice", "note": strings.Repeat(`{[,:]}"\`, 400)}) {
		t.Error("structure inside a string counted toward the bounds")
	}
}

// Explicit holds a direct caller's values to the rules a token's values
// meet: both sides of the value and the array bound, the declared key's
// normalization, and a skip for a declared key only.
func TestExplicit_appliesTheTokensRules(t *testing.T) {
	p := plan(t)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("r%d", i)
		}
		return out
	}
	long := strings.Repeat("x", MaxValueBytes)

	keys, skips := Explicit(p, map[string][]string{
		"sub": {long}, "roles": many(MaxArrayItems), "tenant": {"Acme", ""}, "own": {"Kept"}})
	want := map[string][]string{"sub": {long}, "roles": many(MaxArrayItems), "tenant": {"acme"}, "own": {"Kept"}}
	if !reflect.DeepEqual(keys, want) || len(skips) != 0 {
		t.Errorf("values within the bounds: keys %v, skips %v; want %v and no skips", keys, skips, want)
	}

	keys, skips = Explicit(p, map[string][]string{
		"sub": {long + "x"}, "roles": many(MaxArrayItems + 1), "own": {long + "x"}})
	if len(keys) != 0 {
		t.Errorf("a key past a bound was kept: %v", keys)
	}
	wantSkips := map[string]SkipReason{"sub": SkipTooLong, "roles": SkipTooManyItems}
	if got := skipsOf(skips); !reflect.DeepEqual(got, wantSkips) {
		t.Errorf("skips %v, want %v: an undeclared key reports none", got, wantSkips)
	}
}

// A token that carries none of the plan's claims allocates no map, whatever
// the size of the plan: a map sized by a plan of hundreds of mappings would
// be kilobytes of garbage on every such request.
func TestExtract_allocatesNoMapForATokenWithoutTheClaims(t *testing.T) {
	plan := make([]compile.KeyExtraction, 400)
	for i := range plan {
		plan[i] = compile.KeyExtraction{Key: fmt.Sprintf("k%d", i), Path: []string{fmt.Sprintf("c%d", i)},
			Type: model.ValueString}
	}
	tok := token(t, map[string]any{"nonce": 1})
	keys, skips := Extract(plan, tok)
	if keys != nil || len(skips) != 0 {
		t.Errorf("a token without the claims extracted %v with skips %v", keys, skips)
	}
}
