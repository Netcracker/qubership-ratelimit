package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// plan compiles the extraction plan the way production gets it, so these
// tests exercise the real compile output, not a hand-built lookalike. It
// plans three keys: the built-in sub, roles from realm_access.roles, and
// tenant from org_id, lowercased, falling back to sub.
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

// skipsOf indexes skips by key, for a test that asserts the reason of one key.
func skipsOf(skips []Skip) map[string]SkipReason {
	out := map[string]SkipReason{}
	for _, s := range skips {
		out[s.Key] = s.Reason
	}
	return out
}

// sorted returns skips ordered by key, for a comparison that leaves the order
// of the plan out and still fails on a duplicate.
func sorted(skips []Skip) []Skip {
	out := slices.Clone(skips)
	slices.SortFunc(out, func(a, b Skip) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func TestExtract_readsTheBuiltInAndTheMappedKeys(t *testing.T) {
	claims := map[string]any{
		"sub":          "Alice",
		"org_id":       "ACME",
		"realm_access": map[string]any{"roles": []any{"user", "admin"}},
	}

	keys, skips := Extract(plan(t), token(t, claims))
	if len(skips) != 0 {
		t.Errorf("Extract(plan, token of %v) skips = %v, want none", claims, skips)
	}
	want := map[string][]string{
		"sub":    {"alice"},         // built-in: sub, lowercased
		"tenant": {"acme"},          // normalized
		"roles":  {"user", "admin"}, // array claim through the dot path
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("Extract(plan, token of %v) = %v, want %v", claims, keys, want)
	}
}

// The payload is {"sub":"bob"} in base64url with its padding.
func TestExtract_readsAPaddedTokenBehindABearerPrefix(t *testing.T) {
	const tok = "Bearer h.eyJzdWIiOiJib2IifQ==.sig"
	keys, skips := Extract(plan(t), tok)
	if len(skips) != 0 {
		t.Errorf("Extract(plan, %q) skips = %v, want none", tok, skips)
	}
	if got, want := keys["sub"], []string{"bob"}; !slices.Equal(got, want) {
		t.Errorf("Extract(plan, %q)[sub] = %q, want %q", tok, got, want)
	}
}

// A missing token is anonymous traffic, not an anomaly.
func TestExtract_returnsNothingForABlankToken(t *testing.T) {
	keys, skips := Extract(plan(t), "  ")
	if keys != nil || skips != nil {
		t.Errorf(`Extract(plan, "  ") = %v, %v; want nil, nil`, keys, skips)
	}
}

func TestExtract_skipsEveryPlannedKeyOfAnUndecodableToken(t *testing.T) {
	for _, c := range []struct{ name, token string }{
		{"a token without a payload segment", "garbage"},
		{"a payload segment that is not base64url", "a.b.c"},
		{"a well-formed token past MaxTokenBytes",
			token(t, map[string]any{"sub": "alice", "pad": strings.Repeat("x", MaxTokenBytes)})},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, skips := Extract(plan(t), c.token)
			if len(keys) != 0 {
				t.Errorf("Extract(plan, %.32q) = %v, want no keys", c.token, keys)
			}
			want := []Skip{
				{Key: "roles", Reason: SkipDecodeFailed},
				{Key: "sub", Reason: SkipDecodeFailed},
				{Key: "tenant", Reason: SkipDecodeFailed},
			}
			if got := sorted(skips); !slices.Equal(got, want) {
				t.Errorf("Extract(plan, %.32q) skips = %v, want %v", c.token, got, want)
			}
		})
	}
}

// tenant reads org_id and falls back to sub. An empty claim is absence, and a
// claim of the wrong type reports its skip and still falls back.
func TestExtract_fallsBackWhenThePrimaryClaimYieldsNothing(t *testing.T) {
	for _, c := range []struct {
		name      string
		claims    map[string]any
		wantSkips []Skip
	}{
		{"an absent primary claim", map[string]any{"sub": "carol"}, nil},
		{"an empty primary claim", map[string]any{"sub": "carol", "org_id": ""}, nil},
		{"a primary claim of the wrong type", map[string]any{"sub": "carol", "org_id": 42},
			[]Skip{{Key: "tenant", Reason: SkipBadType}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, skips := Extract(plan(t), token(t, c.claims))
			if got, want := keys["tenant"], []string{"carol"}; !slices.Equal(got, want) {
				t.Errorf("Extract(plan, token of %v)[tenant] = %q, want %q", c.claims, got, want)
			}
			if got := sorted(skips); !slices.Equal(got, c.wantSkips) {
				t.Errorf("Extract(plan, token of %v) skips = %v, want %v", c.claims, got, c.wantSkips)
			}
		})
	}
}

func TestExtract_dropsAnAnomalousClaimWithItsReason(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims map[string]any
		key    string
		reason SkipReason
	}{
		{"a value past MaxValueBytes",
			map[string]any{"sub": strings.Repeat("x", MaxValueBytes+1)}, "sub", SkipTooLong},
		{"an array past MaxArrayItems",
			map[string]any{"realm_access": map[string]any{"roles": slices.Repeat([]any{"r"}, MaxArrayItems+1)}},
			"roles", SkipTooManyItems},
		{"a scalar under an array-typed key",
			map[string]any{"realm_access": map[string]any{"roles": "admin"}}, "roles", SkipBadType},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, skips := Extract(plan(t), token(t, c.claims))
			if got, present := keys[c.key]; present {
				t.Errorf("Extract(plan, token)[%s] = %.64q, want the key absent", c.key, got)
			}
			if got := skipsOf(skips)[c.key]; got != c.reason {
				t.Errorf("Extract(plan, token) skip of %s = %q, want %q", c.key, got, c.reason)
			}
		})
	}
}

// A planned claim the token lacks reports no skip.
func TestExtract_reportsNoSkipForAnAbsentClaim(t *testing.T) {
	claims := map[string]any{"iss": "idp"}
	keys, skips := Extract(plan(t), token(t, claims))
	if len(keys) != 0 || len(skips) != 0 {
		t.Errorf("Extract(plan, token of %v) = %v, %v; want no keys and no skips", claims, keys, skips)
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
				t.Fatalf("Extract(%q) key %s carries %d values past the bound", tok, k, len(values))
			}
			for _, v := range values {
				if len(v) > MaxValueBytes {
					t.Fatalf("Extract(%q) key %s carries a value of %d bytes past the bound", tok, k, len(v))
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

// wide builds a payload of n claims that holds 2n separators: n colons and
// n-1 commas between the claims, and one comma inside the pair.
func wide(n int) map[string]any {
	claims := map[string]any{"sub": "alice", "pair": []int{1, 1}}
	for i := range n - 2 {
		claims[fmt.Sprintf("c%04d", i)] = 1
	}
	return claims
}

// A payload within the shape bounds decodes. The payload object itself is the
// first level of nesting, and structure inside a string counts for nothing.
func TestExtract_decodesAPayloadWithinTheShapeBounds(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims map[string]any
	}{
		{"nesting at MaxPayloadDepth", map[string]any{"sub": "alice", "deep": nested(MaxPayloadDepth - 1)}},
		{"separators at MaxPayloadSeparators", wide(MaxPayloadSeparators / 2)},
		{"key syntax inside a string", map[string]any{"sub": "alice", "note": strings.Repeat(`{[,:]}"\`, 400)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, skips := Extract(plan(t), token(t, c.claims))
			if len(skips) != 0 {
				t.Errorf("Extract(plan, token) skips = %v, want none", skips)
			}
			if got, want := keys["sub"], []string{"alice"}; !slices.Equal(got, want) {
				t.Errorf("Extract(plan, token)[sub] = %q, want %q", got, want)
			}
		})
	}
}

// A payload past a shape bound is undecodable whatever its size: the bound on
// its size alone left the decode free to cost many times a realistic token's.
func TestExtract_refusesAPayloadPastAShapeBound(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims map[string]any
	}{
		{"nesting one level past MaxPayloadDepth", map[string]any{"sub": "alice", "deep": nested(MaxPayloadDepth)}},
		{"separators past MaxPayloadSeparators", wide(MaxPayloadSeparators/2 + 1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, skips := Extract(plan(t), token(t, c.claims))
			if len(keys) != 0 {
				t.Errorf("Extract(plan, token) = %v, want no keys", keys)
			}
			want := []Skip{
				{Key: "roles", Reason: SkipDecodeFailed},
				{Key: "sub", Reason: SkipDecodeFailed},
				{Key: "tenant", Reason: SkipDecodeFailed},
			}
			if got := sorted(skips); !slices.Equal(got, want) {
				t.Errorf("Extract(plan, token) skips = %v, want %v", got, want)
			}
		})
	}
}

// many returns n distinct non-empty values.
func many(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("r%d", i)
	}
	return out
}

// Explicit holds a direct caller's values to the rules a token's values meet:
// a value and an array at their bounds are kept, an empty value is dropped,
// and a declared key's normalization applies.
func TestExplicit_keepsTheValuesWithinTheBounds(t *testing.T) {
	long := strings.Repeat("x", MaxValueBytes)

	keys, skips := Explicit(plan(t), map[string][]string{
		"sub": {long}, "roles": many(MaxArrayItems), "tenant": {"Acme", ""}, "own": {"Kept"}})
	if len(skips) != 0 {
		t.Errorf("Explicit(plan, values within the bounds) skips = %v, want none", skips)
	}
	want := map[string][]string{"sub": {long}, "roles": many(MaxArrayItems), "tenant": {"acme"}, "own": {"Kept"}}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("Explicit(plan, values within the bounds) = %v, want %v", keys, want)
	}
}

// A key past a bound is absent, and a skip is reported for a declared key
// only: an undeclared key is the caller's own name.
func TestExplicit_dropsAKeyPastABound(t *testing.T) {
	long := strings.Repeat("x", MaxValueBytes)

	keys, skips := Explicit(plan(t), map[string][]string{
		"sub": {long + "x"}, "roles": many(MaxArrayItems + 1), "own": {long + "x"}})
	if len(keys) != 0 {
		t.Errorf("Explicit(plan, values past the bounds) = %.80v, want no keys", keys)
	}
	want := []Skip{{Key: "roles", Reason: SkipTooManyItems}, {Key: "sub", Reason: SkipTooLong}}
	if got := sorted(skips); !slices.Equal(got, want) {
		t.Errorf("Explicit(plan, values past the bounds) skips = %v, want %v", got, want)
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
	keys, skips := Extract(plan, token(t, map[string]any{"nonce": 1}))
	if keys != nil || len(skips) != 0 {
		t.Errorf("Extract(400 keys, a token without their claims) = %#v, %v; want a nil map and no skips", keys, skips)
	}
}
