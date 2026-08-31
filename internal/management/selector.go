package management

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The selection grammar: rules x window x identity x state.
//
// One grammar serves the listing and the addressed reset, and one canonical
// form serves everything that has to recognize a selection again: the cursor
// that must not be replayed against a different listing, and the idempotency
// key that must not answer a different command. Canonical means: rule ids
// sorted and deduplicated, axis names sorted, values within an axis sorted and
// deduplicated, the period in seconds, the algorithm lowercased, and absent
// fields absent. So 1m and 60s are one selection, and so are two orderings of
// the same client list.

// axisPrefix marks the dynamic identity parameters. OpenAPI cannot declare
// wildcard parameter names, so the family travels as raw query pairs.
const axisPrefix = "axis."

// selector is a parsed, canonical selection.
type selector struct {
	// RuleIDs are full triples or their 1- and 2-segment prefixes (a policy, a
	// policy/block). Empty selects every rule.
	RuleIDs []string `json:"ruleIds,omitempty"`

	Algorithm string `json:"algorithm,omitempty"`

	// PeriodSeconds is the canonical window length; zero means unfiltered.
	PeriodSeconds int64 `json:"periodSeconds,omitempty"`

	// Axes are OR within one name and AND between names. A counter whose rule
	// does not declare a named axis never matches.
	Axes map[string][]string `json:"axes,omitempty"`

	// LimitedOnly narrows to counters refusing right now, judged at cost 1.
	LimitedOnly bool `json:"limited,omitempty"`
}

// canonical renders the selector for hashing. The struct carries no map with
// unordered iteration left in it, since encoding/json sorts object keys and
// every slice was sorted on the way in, so equal selections hash equal on every
// replica.
func (s selector) canonical() []byte {
	buf, err := json.Marshal(s)
	if err != nil {
		panic("management: the selector failed to marshal: " + err.Error())
	}
	return buf
}

// fingerprint identifies the selection a cursor was minted for.
func (s selector) fingerprint() string {
	sum := sha256.Sum256(s.canonical())
	return hex.EncodeToString(sum[:])[:16]
}

// parseSelector reads the grammar out of a query string.
//
// Unknown axis names are not validated here: a listing filters keys, and a key
// carries axis values the enforced set may no longer describe. What each caller
// validates against the snapshot is its own decision: the addressed reset must,
// the listing must not.
func parseSelector(query url.Values) (selector, *apiError) {
	out := selector{}

	for _, id := range query["ruleId"] {
		if err := checkRuleIDForm(id); err != nil {
			return selector{}, err
		}
		out.RuleIDs = append(out.RuleIDs, id)
	}
	out.RuleIDs = sortedUnique(out.RuleIDs)

	if raw := query.Get("algorithm"); raw != "" {
		out.Algorithm = strings.ToLower(raw)
	}
	if raw := query.Get("period"); raw != "" {
		seconds, err := parsePeriod(raw)
		if err != nil {
			return selector{}, err
		}
		out.PeriodSeconds = seconds
	}
	if err := parseEnumTrue(query, "limited", &out.LimitedOnly); err != nil {
		return selector{}, err
	}

	axes, err := parseAxes(query)
	if err != nil {
		return selector{}, err
	}
	out.Axes = axes
	return out, nil
}

// parseAxes collects the axis.<name> family, ORing repeated values of one name.
func parseAxes(query url.Values) (map[string][]string, *apiError) {
	var axes map[string][]string
	for parameter, values := range query {
		name, found := strings.CutPrefix(parameter, axisPrefix)
		if !found {
			continue
		}
		if name == "" {
			return nil, invalid("an axis parameter needs a name after "+axisPrefix, parameter)
		}
		if slices.Contains(values, "") {
			return nil, invalid("axis "+logSafe(name)+" has an empty value, which addresses no counter", parameter)
		}
		if axes == nil {
			axes = map[string][]string{}
		}
		axes[name] = sortedUnique(values)
	}
	return axes, nil
}

// checkRuleIDForm accepts a full triple or one of its segment prefixes.
func checkRuleIDForm(id string) *apiError {
	parts := strings.Split(id, "/")
	if len(parts) > 3 {
		return invalid("the ruleId "+logSafe(id)+
			" has more than the three policy/block/rule segments", "ruleId")
	}
	if slices.Contains(parts, "") {
		return invalid("the ruleId "+logSafe(id)+
			" carries an empty segment; use policy, policy/block, or policy/block/rule", "ruleId")
	}
	return nil
}

// parsePeriod normalizes a window filter into seconds. An integer is already
// seconds; a duration string is accepted and normalized, so 1m and 60s select
// the same window.
func parsePeriod(raw string) (int64, *apiError) {
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds <= 0 {
			return 0, invalid("the period must be a positive number of seconds", "period")
		}
		return seconds, nil
	}
	period, err := time.ParseDuration(raw)
	if err != nil {
		return 0, invalid("the period "+logSafe(raw)+
			" is neither a number of seconds nor a duration such as 1m or 24h", "period")
	}
	if period <= 0 || period%time.Second != 0 {
		return 0, invalid("the period must be a positive whole number of seconds", "period")
	}
	return int64(period / time.Second), nil
}

// parseEnumTrue reads one of the parameters whose only value is true.
//
// Explicit false is refused rather than accepted as a no-op: a filter that
// pretends to narrow and does not is how somebody resets more than they meant
// to. Omitting the parameter is the way to not select.
func parseEnumTrue(query url.Values, name string, out *bool) *apiError {
	raw := query.Get(name)
	switch raw {
	case "":
		return nil
	case "true":
		*out = true
		return nil
	default:
		return invalid("the only value of "+name+" is true; omit the parameter instead of passing "+
			logSafe(raw), name)
	}
}

// matches reports whether a parsed counter key survives the key-level filters.
// The axis and state filters need the rule behind the key and are applied by
// the caller.
func (s selector) matches(parsed counterKey) bool {
	if s.Algorithm != "" && parsed.Algorithm != s.Algorithm {
		return false
	}
	if s.PeriodSeconds != 0 && parsed.PeriodSeconds != s.PeriodSeconds {
		return false
	}
	if len(s.RuleIDs) == 0 {
		return true
	}
	for _, id := range s.RuleIDs {
		if matchesRuleID(id, parsed) {
			return true
		}
	}
	return false
}

// matchesRuleID compares by whole segments: a policy name selects its blocks,
// never a policy whose name merely starts the same way.
func matchesRuleID(id string, parsed counterKey) bool {
	switch parts := strings.Split(id, "/"); len(parts) {
	case 1:
		return parsed.Policy == parts[0]
	case 2:
		return parsed.Policy == parts[0] && parsed.Block == parts[1]
	case 3:
		return parsed.RuleID == id
	default:
		return false
	}
}

// matchesAxes reports whether a counter's identity survives the axis filters:
// OR within one name, AND between names, and a counter whose rule does not
// declare a named axis never matches.
func (s selector) matchesAxes(axes map[string]string) bool {
	for name, wanted := range s.Axes {
		value, declared := axes[name]
		if !declared {
			return false
		}
		if !slices.Contains(wanted, value) {
			return false
		}
	}
	return true
}

// cursorTTL bounds how long a continuation stays valid. A listing is a live
// scan, not a snapshot, so a cursor presented long after its page describes a
// collection that has moved on.
const cursorTTL = 10 * time.Minute

// cursor is an opaque continuation. It carries the selection it was minted for
// so that presenting it with different filters is refused rather than silently
// answered with a different listing.
type cursor struct {
	After       string `json:"k"`
	Fingerprint string `json:"f"`
	ExpiresAt   int64  `json:"e"`
}

// encodeCursor mints the continuation after the given key.
func encodeCursor(after string, s selector, now time.Time) string {
	buf, err := json.Marshal(cursor{
		After:       after,
		Fingerprint: s.fingerprint(),
		ExpiresAt:   now.Add(cursorTTL).Unix(),
	})
	if err != nil {
		panic("management: the cursor failed to marshal: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodeCursor reads a continuation and checks it against the selection it is
// being presented with.
func decodeCursor(raw string, s selector, now time.Time) (string, *apiError) {
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", invalid("the cursor is not a continuation this API minted", "cursor")
	}
	var parsed cursor
	if err := json.Unmarshal(buf, &parsed); err != nil {
		return "", invalid("the cursor is not a continuation this API minted", "cursor")
	}
	if parsed.Fingerprint != s.fingerprint() {
		return "", invalid("the cursor was minted for a different selection; restart the listing", "cursor")
	}
	if now.Unix() > parsed.ExpiresAt {
		return "", invalid("the cursor has expired; restart the listing", "cursor")
	}
	return parsed.After, nil
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
