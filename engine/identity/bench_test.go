package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// benchPayload encodes claims as a token without the test helper's *testing.T.
func benchPayload(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "h." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// The cost of extraction for a realistic token and for the worst shapes the
// size bound admits: deeply nested, and densely packed. Before the shape
// bound the worst cost tens of times the realistic one; a payload past the
// bound now stops at the linear scan.
func BenchmarkExtractShapes(b *testing.B) {
	p := plan(&testing.T{})
	roles := make([]any, 20)
	for i := range roles {
		roles[i] = "role-" + strings.Repeat("r", 10)
	}
	realistic := benchPayload(map[string]any{
		"sub": "00000000-0000-4000-8000-000000000001", "iss": "https://idp.example/realms/core",
		"aud": "gateway", "exp": 4102444800, "iat": 1700000000, "azp": "web", "scope": "openid profile",
		"preferred_username": "alice", "email": "alice@example.com", "realm_access": map[string]any{"roles": roles},
	})
	var deep any = "x"
	for range 1500 {
		deep = []any{deep}
	}
	deepToken := benchPayload(map[string]any{"sub": "alice", "d": deep})
	dense := map[string]any{"sub": "alice"}
	for i := 0; len(benchPayload(dense)) < MaxTokenBytes-64; i++ {
		dense[fmt.Sprintf("k%d", i)] = 0
	}
	denseToken := benchPayload(dense)
	// The worst admitted: as many claims as the separators allow, one of them
	// nested to the depth bound.
	admitted := map[string]any{"sub": "alice", "d": nestedArray(MaxPayloadDepth - 2)}
	for i := 0; len(admitted)*2 < MaxPayloadSeparators-8; i++ {
		admitted[fmt.Sprintf("k%d", i)] = 0
	}
	admittedToken := benchPayload(admitted)

	for name, tok := range map[string]string{"realistic": realistic, "deep": deepToken, "dense": denseToken,
		"admitted": admittedToken} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Extract(p, tok)
			}
		})
	}
}

// nestedArray is a value nested depth arrays deep.
func nestedArray(depth int) any {
	var v any = "x"
	for range depth {
		v = []any{v}
	}
	return v
}
