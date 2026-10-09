package management

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One canonical form serves the cursor that must not be replayed against a
// different listing and the idempotency key that must not answer a different
// command. Both rest on the same property: two spellings of one selection hash
// equal, and two different selections do not.

func TestSelector_canonicalizesTheSpellingsOfOneSelection(t *testing.T) {
	const firstQuery = "ruleId=b/b&ruleId=a/a&axis.sub=bob&axis.sub=alice&period=1m&algorithm=GCRA"
	const secondQuery = "ruleId=a/a&ruleId=b/b&ruleId=a/a&axis.sub=alice&axis.sub=bob&period=60&algorithm=gcra"
	first := mustSelector(t, firstQuery)
	second := mustSelector(t, secondQuery)

	assert.Equal(t, first, second, "parseSelector(%q) against parseSelector(%q)", firstQuery, secondQuery)
	assert.Equal(t, first.fingerprint(), second.fingerprint(),
		"fingerprints of parseSelector(%q) and parseSelector(%q)", firstQuery, secondQuery)
	assert.Equal(t, []string{"a/a", "b/b"}, first.RuleIDs, "parseSelector(%q)", firstQuery)
	assert.Equal(t, int64(60), first.PeriodSeconds, "parseSelector(%q)", firstQuery)
	assert.Equal(t, "gcra", first.Algorithm, "parseSelector(%q)", firstQuery)
	assert.Equal(t, map[string][]string{"sub": {"alice", "bob"}}, first.Axes, "parseSelector(%q)", firstQuery)
}

func TestSelectorFingerprint_differsBetweenDifferentSelections(t *testing.T) {
	cases := []struct {
		name        string
		left, right string
	}{
		{name: "another value of one axis", left: "axis.sub=alice", right: "axis.sub=bob"},
		{name: "a second axis name", left: "axis.sub=alice", right: "axis.sub=alice&axis.plan=premium"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, mustSelector(t, tc.left).fingerprint(), mustSelector(t, tc.right).fingerprint(),
				"fingerprints of %q and %q", tc.left, tc.right)
		})
	}
}

func TestParsePeriod_readsSecondsOrADurationAsWholeSeconds(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{raw: "1", want: 1},
		{raw: "60", want: 60},
		{raw: "1m", want: 60},
		{raw: "24h", want: 86400},
		{raw: "90s", want: 90},
		{raw: "1.5m", want: 90},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			seconds, apiErr := parsePeriod(tc.raw, "period")
			require.Nil(t, apiErr, "parsePeriod(%q)", tc.raw)
			assert.Equal(t, tc.want, seconds, "parsePeriod(%q)", tc.raw)
		})
	}
}

// A window shorter than a second is not a period the key layout can carry:
// the key holds whole seconds, and truncation would collide two windows.
func TestParsePeriod_refusesAPeriodThatIsNotAPositiveWholeNumberOfSeconds(t *testing.T) {
	cases := []struct{ name, raw string }{
		{name: "zero seconds", raw: "0"},
		{name: "negative seconds", raw: "-1"},
		{name: "neither seconds nor a duration", raw: "soon"},
		{name: "a duration under a second", raw: "500ms"},
		{name: "a duration with a fraction of a second", raw: "1500ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, apiErr := parsePeriod(tc.raw, "period")
			require.NotNil(t, apiErr, "parsePeriod(%q)", tc.raw)
			assert.Equal(t, CodeInvalidRequest, apiErr.GetErrorCode(), "parsePeriod(%q)", tc.raw)
			assert.Equal(t, []string{"period"}, apiErr.fields, "parsePeriod(%q)", tc.raw)
		})
	}
}

func TestDecodeCursor_returnsTheStoreCursorItWasMintedWith(t *testing.T) {
	sel := mustSelector(t, "axis.sub=alice")
	now := time.Now()

	step, apiErr := decodeCursor(encodeCursor("127.0.0.1:6379@42", sel, now), sel, now)

	require.Nil(t, apiErr, "decodeCursor of a cursor minted for the same selection")
	assert.Equal(t, "127.0.0.1:6379@42", step)
}

// A cursor is bound to the selection it was minted for and to its lifetime, and
// anything this API did not mint is refused too.
func TestDecodeCursor_refusesACursorItCannotResume(t *testing.T) {
	alice := mustSelector(t, "axis.sub=alice")
	now := time.Now()
	minted := encodeCursor("127.0.0.1:6379@42", alice, now)

	cases := []struct {
		name string
		raw  string
		sel  selector
		at   time.Time
	}{
		{name: "a cursor of another selection", raw: minted, sel: mustSelector(t, "axis.sub=bob"), at: now},
		{name: "an expired cursor", raw: minted, sel: alice, at: now.Add(cursorTTL + time.Second)},
		{name: "a value this API never minted", raw: "not-a-cursor!", sel: alice, at: now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, apiErr := decodeCursor(tc.raw, tc.sel, tc.at)
			require.NotNil(t, apiErr, "decodeCursor(%q)", tc.raw)
			assert.Equal(t, CodeInvalidRequest, apiErr.GetErrorCode(), "decodeCursor(%q)", tc.raw)
			assert.Equal(t, []string{"cursor"}, apiErr.fields, "decodeCursor(%q)", tc.raw)
		})
	}
}

// A cursor lives at least cursorTTL: presented exactly that long after it was
// minted, it still resumes the listing.
func TestDecodeCursor_resumesExactlyAtTheEndOfItsTTL(t *testing.T) {
	alice := mustSelector(t, "axis.sub=alice")
	now := time.Now()
	minted := encodeCursor("127.0.0.1:6379@42", alice, now)

	_, apiErr := decodeCursor(minted, alice, now.Add(cursorTTL))

	assert.Nil(t, apiErr, "decodeCursor exactly cursorTTL after minting")
}

// One segment names a block and selects its rules; two are the whole id. A
// prefix of a name is not a prefix of an id.
func TestMatchesRuleID_comparesWholeSegments(t *testing.T) {
	parsed := counterKey{RuleID: "orders/per-client", Block: "orders", Rule: "per-client"}

	cases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "the block", id: "orders", want: true},
		{name: "the whole id", id: "orders/per-client", want: true},
		{name: "a prefix of the block name", id: "order", want: false},
		{name: "a prefix of the rule name", id: "orders/per", want: false},
		// The policy segment is gone, so a three-part id addresses nothing.
		{name: "a three-part id", id: "api/orders/per-client", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesRuleID(tc.id, parsed), "matchesRuleID(%q, %s)", tc.id, parsed.RuleID)
		})
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	values, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return values
}

// mustSelector parses raw as a listing query and stops the test when the
// selection grammar refuses it.
func mustSelector(t *testing.T, raw string) selector {
	t.Helper()
	sel, apiErr := parseSelector(mustQuery(t, raw))
	require.Nil(t, apiErr, "parseSelector(%q)", raw)
	return sel
}
