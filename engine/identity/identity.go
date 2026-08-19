package identity

import (
	"encoding/base64"
	"encoding/json"
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

	keys := make(map[string][]string, len(plan))
	var skips []Skip
	for _, e := range plan {
		values, reason := extractKey(claims, e)
		if reason != "" {
			skips = append(skips, Skip{Key: e.Key, Reason: reason})
		}
		if len(values) > 0 {
			keys[e.Key] = values
		}
	}
	return keys, skips
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
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	return claims, true
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
		if e.Normalize == model.NormalizeLowercase {
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
