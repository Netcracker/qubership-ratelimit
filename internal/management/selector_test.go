package management

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// One canonical form serves the cursor that must not be replayed against a
// different listing and the idempotency key that must not answer a different
// command. Both rest on the same property: two spellings of one selection hash
// equal, and two different selections do not.

func TestSelector_canonicalizesTheSpellingsOfOneSelection(t *testing.T) {
	first, err := parseSelector(mustQuery(t,
		"ruleId=b/b/b&ruleId=a/a/a&axis.client=bob&axis.client=alice&period=1m&algorithm=GCRA"))
	require.Nil(t, err)

	second, err := parseSelector(mustQuery(t,
		"ruleId=a/a/a&ruleId=b/b/b&ruleId=a/a/a&axis.client=alice&axis.client=bob&period=60&algorithm=gcra"))
	require.Nil(t, err)

	require.Equal(t, first, second)
	require.Equal(t, first.fingerprint(), second.fingerprint())
	require.Equal(t, []string{"a/a/a", "b/b/b"}, first.RuleIDs)
	require.Equal(t, int64(60), first.PeriodSeconds)
	require.Equal(t, "gcra", first.Algorithm)
}

func TestSelector_differentSelectionsDoNotCollide(t *testing.T) {
	alice, _ := parseSelector(mustQuery(t, "axis.client=alice"))
	bob, _ := parseSelector(mustQuery(t, "axis.client=bob"))
	require.NotEqual(t, alice.fingerprint(), bob.fingerprint())

	// A second name is an AND, not a wider OR.
	both, _ := parseSelector(mustQuery(t, "axis.client=alice&axis.plan=premium"))
	require.NotEqual(t, alice.fingerprint(), both.fingerprint())
}

func TestParsePeriod_normalizesAndRefuses(t *testing.T) {
	for raw, want := range map[string]int64{"60": 60, "1m": 60, "24h": 86400, "90s": 90, "1.5m": 90} {
		seconds, err := parsePeriod(raw)
		require.Nil(t, err, "period %q", raw)
		require.Equal(t, want, seconds)
	}
	// A window shorter than a second is not a period the key layout can carry:
	// the key holds whole seconds, and truncation would collide two windows.
	for _, raw := range []string{"0", "-1", "soon", "500ms", "1500ms"} {
		_, err := parsePeriod(raw)
		require.NotNil(t, err, "period %q", raw)
	}
}

func TestCursor_isBoundToItsSelectionAndItsLifetime(t *testing.T) {
	sel, _ := parseSelector(mustQuery(t, "axis.client=alice"))
	other, _ := parseSelector(mustQuery(t, "axis.client=bob"))
	now := time.Now()

	token := encodeCursor("rl:v1:{d}:a/b/c:gcra:60:alice:", sel, now)

	after, err := decodeCursor(token, sel, now)
	require.Nil(t, err)
	require.Equal(t, "rl:v1:{d}:a/b/c:gcra:60:alice:", after)

	_, err = decodeCursor(token, other, now)
	require.NotNil(t, err, "a cursor of another selection is refused")

	_, err = decodeCursor(token, sel, now.Add(cursorTTL+time.Second))
	require.NotNil(t, err, "an expired cursor is refused")

	_, err = decodeCursor("not-a-cursor!", sel, now)
	require.NotNil(t, err)
}

func TestMatchesRuleID_comparesWholeSegments(t *testing.T) {
	parsed := counterKey{
		RuleID: "api/orders/per-client", Policy: "api", Block: "orders", Rule: "per-client",
	}

	require.True(t, matchesRuleID("api", parsed))
	require.True(t, matchesRuleID("api/orders", parsed))
	require.True(t, matchesRuleID("api/orders/per-client", parsed))

	// A prefix of a name is not a prefix of an id.
	require.False(t, matchesRuleID("ap", parsed))
	require.False(t, matchesRuleID("api/order", parsed))
	require.False(t, matchesRuleID("api/orders/per", parsed))
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	values, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return values
}
