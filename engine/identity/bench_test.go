package identity

import (
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// The cost of extraction for a realistic token, for the worst shapes the size
// bound admits, deeply nested and densely packed, which the shape bound
// refuses after its linear scan, and for the worst shapes the shape bound
// still admits, which are the residual: under fifteen times the realistic
// token, where the size alone left the worst at about a hundred times. The
// worst admitted are an array of as many elements as the separators allow; an
// array of empty objects and arrays nested to the depth bound, whose brackets
// count toward the separators; and an array of number literals on a float64
// rounding halfway point, which the decode keeps as text.
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
	deepToken := token(b, map[string]any{"sub": "alice", "d": nestedArray(1500)})
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
	// The payload object, the array, two colons, and a comma leave 507 of the
	// bound to the commas between 508 elements.
	elements := make([]any, MaxPayloadSeparators-4)
	for i := range elements {
		elements[i] = strings.Repeat("x", 20)
	}
	arrayToken := token(b, map[string]any{"sub": "alice", "a": elements})
	nests := []any{}
	for {
		next := append(slices.Clone(nests), nestedEmpty(MaxPayloadDepth-2))
		if _, ok := payload(token(b, map[string]any{"sub": "alice", "e": next})); !ok {
			break
		}
		nests = next
	}
	nestsToken := token(b, map[string]any{"sub": "alice", "e": nests})
	numbers := []any{}
	for len(token(b, map[string]any{"sub": "alice", "n": numbers})) < MaxTokenBytes-len(halfwayAboveMax)*4/3-8 {
		numbers = append(numbers, json.Number(halfwayAboveMax))
	}
	numbersToken := token(b, map[string]any{"sub": "alice", "n": numbers})

	for _, admittedShape := range []string{admittedToken, arrayToken, nestsToken, numbersToken} {
		if _, ok := payload(admittedShape); !ok {
			b.Fatalf("a shape meant to be admitted is refused: %.64s", admittedShape)
		}
	}

	for _, shape := range []struct{ name, token string }{{"realistic", realistic}, {"deep", deepToken},
		{"dense", denseToken}, {"admitted", admittedToken}, {"array", arrayToken}, {"nests", nestsToken},
		{"numbers", numbersToken}} {
		b.Run(shape.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Extract(p, shape.token)
			}
		})
	}
}

// halfwayAboveMax is the exact decimal halfway between the largest float64
// and the next power of two: strconv.ParseFloat cannot round it on its fast
// path and works through all of its 309 digits.
var halfwayAboveMax = func() string {
	largest := new(big.Float).SetPrec(2048).SetFloat64(1.7976931348623157e308)
	halfULP := new(big.Float).SetPrec(2048).SetMantExp(big.NewFloat(1), 1023-53)
	return new(big.Float).SetPrec(2048).Add(largest, halfULP).Text('f', 0)
}()

// nestedEmpty is an empty object nested in depth-1 arrays: depth brackets and
// no value.
func nestedEmpty(depth int) any {
	var v any = map[string]any{}
	for range depth - 1 {
		v = []any{v}
	}
	return v
}

// nestedArray is a value nested depth arrays deep.
func nestedArray(depth int) any {
	var v any = "x"
	for range depth {
		v = []any{v}
	}
	return v
}
