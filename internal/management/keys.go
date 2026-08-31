package management

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/key"
)

// The counter key layout belongs to the engine's key package, which builds
// every key and deliberately exposes no reader: the decision path only ever
// writes keys, so nothing inside the engine needs to take one apart.
//
// Management does. An operator looking at a limited counter has to be told
// which client it belongs to, and the axis values live nowhere else: in the key
// and in the token they came from, and the token never leaves the identity
// layer. So this file decodes what the key package encodes.
//
// Two encoders of one format drift, and a drift here is silent: a reset would
// build a key that misses the live counter, and the caller would be told the
// limit was lifted when it was not. The round-trip test in keys_test.go pins
// this decoder against the key package itself, so a change to the layout
// upstream fails a test here rather than a reset in production.

// counterKey is one parsed counter key: the identity of the rule that owns it,
// its window, and its axis values, all unescaped.
//
// It is parsed rather than matched against the snapshot on purpose. A listing
// scans keys, and among them are counters of rules a rollout has removed while
// their state lives out its TTL; those still parse, which is what lets the
// listing count them as scanned and skip them knowingly instead of mistaking
// them for corruption.
type counterKey struct {
	RuleID string
	Policy string
	Block  string
	Rule   string

	Algorithm     string
	PeriodSeconds int64

	// RatePrefix is the constant part of the key up to the axis values: the same
	// string compilation built for the rate this counter belongs to.
	RatePrefix string

	// Axes are the values in key order. Their names come from the rule, which
	// only the snapshot carries.
	Axes []string
}

// parseCounterKey takes one counter key of a domain apart.
func parseCounterKey(domain, k string) (counterKey, error) {
	prefix := key.DomainPrefix(domain)
	rest, found := strings.CutPrefix(k, prefix)
	if !found {
		return counterKey{}, fmt.Errorf("key %q does not belong to domain %q", k, domain)
	}

	// Every segment is terminated, the last one included, so the split leaves a
	// trailing empty element that is a property of the format, not a value.
	fields := strings.Split(rest, ":")
	if last := len(fields) - 1; last >= 0 && fields[last] == "" {
		fields = fields[:last]
	}
	if len(fields) < 3 {
		return counterKey{}, fmt.Errorf("key %q carries %d segments, fewer than the rule, algorithm, and period the layout requires", k, len(fields))
	}

	policy, block, rule, err := splitTriple(fields[0])
	if err != nil {
		return counterKey{}, fmt.Errorf("key %q: %w", k, err)
	}
	period, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return counterKey{}, fmt.Errorf("key %q carries a period that is not a whole number of seconds: %q", k, fields[2])
	}

	parsed := counterKey{
		RuleID:        ruleID(policy, block, rule),
		Policy:        policy,
		Block:         block,
		Rule:          rule,
		Algorithm:     fields[1],
		PeriodSeconds: period,
		RatePrefix:    prefix + strings.Join(fields[:3], ":") + ":",
	}
	for _, field := range fields[3:] {
		value, err := unescapeSegment(field)
		if err != nil {
			return counterKey{}, fmt.Errorf("key %q: %w", k, err)
		}
		parsed.Axes = append(parsed.Axes, value)
	}
	return parsed, nil
}

// namedAxes pairs the key's axis values with the axis names the rule declares.
// A mismatch means the key and the rule disagree about how many axes there
// are, which is a rule that was redefined under a live counter.
func (c counterKey) namedAxes(names []string) (map[string]string, error) {
	if len(c.Axes) != len(names) {
		return nil, fmt.Errorf("a counter of %s carries %d axis values but the rule declares %d",
			c.RuleID, len(c.Axes), len(names))
	}
	if len(names) == 0 {
		return nil, nil
	}
	axes := make(map[string]string, len(names))
	for i, name := range names {
		axes[name] = c.Axes[i]
	}
	return axes, nil
}

// splitTriple takes the escaped policy/block/rule segment apart.
func splitTriple(segment string) (policy, block, rule string, err error) {
	parts := strings.Split(segment, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("the rule segment %q is not policy/block/rule", segment)
	}
	out := make([]string, 3)
	for i, part := range parts {
		value, err := unescapeSegment(part)
		if err != nil {
			return "", "", "", err
		}
		if value == "" {
			return "", "", "", fmt.Errorf("the rule segment %q carries an empty part", segment)
		}
		out[i] = value
	}
	return out[0], out[1], out[2], nil
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
