package management

import (
	"fmt"
	"strings"
)

// The counter key layout belongs to the engine's key package, which builds
// every key and deliberately exposes no reader: the decision path only ever
// writes keys, so nothing inside the engine needs to take one apart.
//
// Management does. An operator looking at a limited counter has to be told
// which client it belongs to, and the axis values live nowhere else — they are
// in the key and in the token they came from, and the token never leaves the
// identity layer. So this file decodes what key.Bucket encodes.
//
// Two encoders of one format drift, and a drift here is silent: a reset would
// build a key that misses the live counter, and the caller would be told the
// limit was lifted when it was not. The round-trip test in keys_test.go pins
// this decoder against key.Bucket itself, so a change to the layout upstream
// fails a test here rather than a reset in production.

// decodeAxes reads the axis values out of a counter key, pairing them with the
// axis names of the rule in the order the key carries them.
//
// The key is the rate's prefix followed by one terminated segment per axis, so
// the values are what remains after the prefix, split on the terminator.
func decodeAxes(key, ratePrefix string, names []string) (map[string]string, error) {
	remainder, found := strings.CutPrefix(key, ratePrefix)
	if !found {
		return nil, fmt.Errorf("key %q does not belong to the rate prefix %q", key, ratePrefix)
	}
	if remainder == "" {
		// A rule without axes counts one bucket for the whole rate, and its
		// key is the bare prefix.
		return nil, nil
	}
	// Every segment is terminated, the last one included, so the split leaves
	// a trailing empty element that is a property of the format, not a value.
	segments := strings.Split(remainder, ":")
	if last := len(segments) - 1; last >= 0 && segments[last] == "" {
		segments = segments[:last]
	}
	if len(segments) != len(names) {
		return nil, fmt.Errorf("key %q carries %d axis values but the rule declares %d",
			key, len(segments), len(names))
	}

	axes := make(map[string]string, len(segments))
	for i, segment := range segments {
		value, err := unescapeSegment(segment)
		if err != nil {
			return nil, fmt.Errorf("axis %q of key %q: %w", names[i], key, err)
		}
		axes[names[i]] = value
	}
	return axes, nil
}

// unescapeSegment reverses the percent-encoding the key schema applies to the
// characters it reserves.
func unescapeSegment(segment string) (string, error) {
	if !strings.Contains(segment, "%") {
		return segment, nil
	}
	var b strings.Builder
	b.Grow(len(segment))
	for i := 0; i < len(segment); i++ {
		if segment[i] != '%' {
			b.WriteByte(segment[i])
			continue
		}
		if i+2 >= len(segment) {
			return "", fmt.Errorf("truncated percent escape in %q", segment)
		}
		high, err := hexDigit(segment[i+1])
		if err != nil {
			return "", err
		}
		low, err := hexDigit(segment[i+2])
		if err != nil {
			return "", err
		}
		b.WriteByte(high<<4 | low)
		i += 2
	}
	return b.String(), nil
}

func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	default:
		return 0, fmt.Errorf("invalid percent escape digit %q", string(c))
	}
}
