package identity

import (
	"fmt"
	"strings"
	"testing"
)

// The cost of extraction for a realistic token, for the worst shapes the size
// bound admits, deeply nested and densely packed, which the shape bound
// refuses after its linear scan, and for the worst shape the shape bound
// still admits, which is the residual: about eight times the realistic token,
// where the size alone left the worst at about a hundred times.
func BenchmarkExtractShapes(b *testing.B) {
	p := plan(b)
	roles := make([]any, 20)
	for i := range roles {
		roles[i] = "role-" + strings.Repeat("r", 10)
	}
	realistic := token(b, map[string]any{
		"sub": "00000000-0000-4000-8000-000000000001", "iss": "https://idp.example/realms/core",
		"aud": "gateway", "exp": 4102444800, "iat": 1700000000, "azp": "web", "scope": "openid profile",
		"preferred_username": "alice", "email": "alice@example.com", "realm_access": map[string]any{"roles": roles},
	})
	var deep any = "x"
	for range 1500 {
		deep = []any{deep}
	}
	deepToken := token(b, map[string]any{"sub": "alice", "d": deep})
	dense := map[string]any{"sub": "alice"}
	for i := 0; len(token(b, dense)) < MaxTokenBytes-64; i++ {
		dense[fmt.Sprintf("k%d", i)] = 0
	}
	denseToken := token(b, dense)
	// The worst admitted: as many claims as the separators allow, one of them
	// nested to the depth bound.
	admitted := map[string]any{"sub": "alice", "d": nestedArray(MaxPayloadDepth - 2)}
	for i := 0; len(admitted)*2 < MaxPayloadSeparators-8; i++ {
		admitted[fmt.Sprintf("k%d", i)] = 0
	}
	admittedToken := token(b, admitted)

	for _, shape := range []struct{ name, token string }{{"realistic", realistic}, {"deep", deepToken},
		{"dense", denseToken}, {"admitted", admittedToken}} {
		b.Run(shape.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Extract(p, shape.token)
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
