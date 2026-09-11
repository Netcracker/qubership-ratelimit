package identity

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// plan compiles the extraction plan the way production gets it, so these
// tests exercise the real compile output, not a hand-built lookalike.
func plan(t *testing.T) []compile.KeyExtraction {
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

func token(t *testing.T, claims map[string]any) string {
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
		"client": {"alice"},         // built-in: sub, lowercased
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
	if len(skips) != 0 || len(keys["client"]) != 1 || keys["client"][0] != "bob" {
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
	if _, present := keys["client"]; present || skipsOf(skips)["client"] != SkipTooLong {
		t.Errorf("keys = %v, skips = %v: want too_long and no client key", keys, skips)
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
		{Key: "client", Path: []string{"sub"}, Type: model.ValueString, Normalization: model.NormalizeLowercase},
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
