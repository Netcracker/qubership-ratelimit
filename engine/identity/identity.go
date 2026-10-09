package identity

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// Sanitary limits are engine constants, not configuration: the token is
// untrusted input on the request path, and its bounds are not a policy knob.
const (
	// MaxTokenBytes bounds the whole token; anything larger is undecodable.
	MaxTokenBytes = 16 << 10

	// MaxValueBytes bounds one extracted value.
	MaxValueBytes = 256

	// MaxArrayItems bounds an array claim.
	MaxArrayItems = 64

	// MaxPayloadDepth bounds how deeply the payload's objects and arrays nest.
	// A realistic token nests two or three levels (realm_access.roles,
	// resource_access.<client>.roles); a payload past the bound is undecodable.
	MaxPayloadDepth = 8

	// MaxPayloadSeparators bounds the commas and colons of the payload, about
	// two for each claim and one for each array item. A realistic token has a
	// few dozen; a heavy one, 150 realm roles, ten clients of eight roles, and
	// thirty flat claims, has 312. A payload past the bound is undecodable.
	MaxPayloadSeparators = 512
)

// SkipReason labels why a declared key extracted nothing, in the exact
// vocabulary the extraction metrics use. A merely absent or empty claim is
// not a skip — absence is the normal state of anonymous traffic.
type SkipReason string

const (
	SkipDecodeFailed SkipReason = "decode_failed"
	SkipBadType      SkipReason = "bad_type"
	SkipTooLong      SkipReason = "too_long"
	SkipTooManyItems SkipReason = "too_many_items"
)

// Skip is one anomaly for the metrics layer. It never carries claim values:
// nothing this package returns can leak token content into labels or logs.
type Skip struct {
	Key    string
	Reason SkipReason
}

// Extract turns a token into descriptor key values, following the compiled
// plan. The payload is decoded, never verified — the gateway checked the
// signature. A missing token is not an error and not a skip: identity keys
// are simply absent, and the rules that need them will not match. An
// undecodable token reports one decode_failed skip per planned key, which is
// what feeds the "key declared, tokens arriving, zero extractions" detector.
func Extract(plan []compile.KeyExtraction, token string) (map[string][]string, []Skip) {
	token = strings.TrimSpace(token)
	if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = token[7:]
	}
	if token == "" {
		return nil, nil
	}

	claims, ok := payload(token)
	if !ok {
		skips := make([]Skip, len(plan))
		for i, e := range plan {
			skips[i] = Skip{Key: e.Key, Reason: SkipDecodeFailed}
		}
		return nil, skips
	}

	// The map is made for the first value found, not sized by the plan: a
	// policy of a few hundred mappings would otherwise allocate kilobytes for
	// every token that carries none of their claims.
	var keys map[string][]string
	var skips []Skip
	for _, e := range plan {
		values, reason := extractKey(claims, e)
		if reason != "" {
			skips = append(skips, Skip{Key: e.Key, Reason: reason})
		}
		if len(values) > 0 {
			if keys == nil {
				keys = make(map[string][]string)
			}
			keys[e.Key] = values
		}
	}
	return keys, skips
}

// Explicit applies the rules of extraction to pre-extracted values, the
// direct form of the protocol, so that a value counts the same whichever form
// carried it. A key with more than MaxArrayItems values, or with a value
// longer than MaxValueBytes, is absent, empty values are dropped, and the
// values of a key the plan lowercases are lowercased. A key is a set, so a
// value repeated, before or after lowercasing, counts once, at its first
// position. A skip is reported for a
// key the plan declares; the others are the caller's own names, and a skip
// carrying them would hand the caller the cardinality of a metric.
func Explicit(plan []compile.KeyExtraction, keys map[string][]string) (map[string][]string, []Skip) {
	if len(keys) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(keys))
	var skips []Skip
	for key, values := range keys {
		extraction, declared := planned(plan, key)
		kept, reason := explicitValues(values)
		if reason != "" {
			if declared {
				skips = append(skips, Skip{Key: key, Reason: reason})
			}
			continue
		}
		if len(kept) == 0 {
			continue
		}
		if declared && extraction.Normalization == model.NormalizeLowercase {
			for i := range kept {
				kept[i] = strings.ToLower(kept[i])
			}
		}
		out[key] = distinct(kept)
	}
	return out, skips
}

// distinct returns values without repeats, in the order of first occurrence.
func distinct(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// planned finds the plan's extraction of key.
func planned(plan []compile.KeyExtraction, key string) (compile.KeyExtraction, bool) {
	for _, e := range plan {
		if e.Key == key {
			return e, true
		}
	}
	return compile.KeyExtraction{}, false
}

// explicitValues is coerceArray for values that arrive as strings: the
// non-empty ones, or a reason when the key is out of bounds.
func explicitValues(values []string) ([]string, SkipReason) {
	if len(values) > MaxArrayItems {
		return nil, SkipTooManyItems
	}
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) > MaxValueBytes {
			return nil, SkipTooLong
		}
		if v != "" {
			kept = append(kept, v)
		}
	}
	return kept, ""
}

// payload decodes the JWT payload segment. Both unpadded (the standard) and
// padded base64url are accepted; everything else is undecodable.
func payload(token string) (map[string]any, bool) {
	if len(token) > MaxTokenBytes {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil, false
		}
	}
	if !withinShape(raw) {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	return claims, true
}

// withinShape reports whether the payload nests no deeper than
// MaxPayloadDepth and holds no more than MaxPayloadSeparators separators. The
// token is unsigned input, and MaxTokenBytes bounds its size but not the work
// json.Unmarshal does on it: a deeply nested or densely packed payload of the
// same size costs many times a realistic one, and no cache helps when every
// token is new. The scan is one linear pass over the bytes, far cheaper than
// the decode it guards; it skips strings, so their content counts for nothing.
func withinShape(raw []byte) bool {
	depth, separators := 0, 0
	inString, escaped := false, false
	for _, b := range raw {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > MaxPayloadDepth {
				return false
			}
		case '}', ']':
			depth--
		case ',', ':':
			separators++
			if separators > MaxPayloadSeparators {
				return false
			}
		}
	}
	return true
}

// extractKey tries the primary path, then the fallbacks, and returns the
// first non-empty valid result. An anomalous candidate reports its reason and
// falls through, so a later fallback can still serve the key — the first
// anomaly stays visible either way.
func extractKey(claims map[string]any, e compile.KeyExtraction) ([]string, SkipReason) {
	var firstSkip SkipReason
	note := func(r SkipReason) {
		if firstSkip == "" {
			firstSkip = r
		}
	}

	paths := make([][]string, 0, 1+len(e.Fallbacks))
	paths = append(paths, e.Path)
	paths = append(paths, e.Fallbacks...)

	for _, p := range paths {
		v, found := walk(claims, p)
		if !found {
			continue
		}
		values, reason := coerce(v, e.Type)
		if reason != "" {
			note(reason)
			continue
		}
		if len(values) == 0 {
			continue
		}
		if e.Normalization == model.NormalizeLowercase {
			for i := range values {
				values[i] = strings.ToLower(values[i])
			}
		}
		return values, firstSkip
	}
	return nil, firstSkip
}

// walk follows path segments through nested objects.
func walk(claims map[string]any, path []string) (any, bool) {
	var current any = claims
	for _, segment := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = obj[segment]; !ok {
			return nil, false
		}
	}
	return current, true
}

// coerce shapes a claim value per the declared type. Empty results carry no
// reason: an empty claim is absence, and absence keeps falling back.
func coerce(v any, t model.ValueType) ([]string, SkipReason) {
	if t == model.ValueStringArray {
		return coerceArray(v)
	}

	s, ok := v.(string)
	if !ok {
		return nil, SkipBadType
	}
	if len(s) > MaxValueBytes {
		return nil, SkipTooLong
	}
	if s == "" {
		return nil, ""
	}
	return []string{s}, ""
}

// coerceArray keeps the non-empty strings of an array claim, refusing the
// whole claim on a foreign element type or an out-of-bounds size.
func coerceArray(v any) ([]string, SkipReason) {
	arr, ok := v.([]any)
	if !ok {
		return nil, SkipBadType
	}
	if len(arr) > MaxArrayItems {
		return nil, SkipTooManyItems
	}
	values := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, SkipBadType
		}
		if len(s) > MaxValueBytes {
			return nil, SkipTooLong
		}
		if s != "" {
			values = append(values, s)
		}
	}
	return values, ""
}
