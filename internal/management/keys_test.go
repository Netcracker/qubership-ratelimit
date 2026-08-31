package management

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The decoder here and the builder in the key package are two implementations
// of one format, and a drift between them is silent: a reset would compute a
// key that misses the live counter, and the caller would be told a limit was
// lifted when it was not. These tests pin the decoder against the builder
// itself rather than against a string somebody typed.

func TestParseCounterKey_roundTripsWhatTheKeyPackageBuilds(t *testing.T) {
	gcra, ok := algo.ByID(algo.GCRAID)
	require.True(t, ok)
	window := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	cases := []struct {
		name  string
		ident key.Ident
		axes  []string
	}{
		{
			name:  "one axis",
			ident: key.Ident{Domain: testDomain, Policy: "quote-api", Block: "cascade", Rule: "everyone"},
			axes:  []string{"alice"},
		},
		{
			name:  "no axes at all",
			ident: key.Ident{Domain: testDomain, Policy: "global", Block: "everything", Rule: "total"},
		},
		{
			name:  "several axes",
			ident: key.Ident{Domain: testDomain, Policy: "api", Block: "by-order", Rule: "each"},
			axes:  []string{"alice", "4711"},
		},
		{
			// The characters the key schema reserves are exactly the ones a
			// claim value can carry, and an axis that forged a segment
			// boundary would address another client's counter.
			name:  "values carrying the reserved characters",
			ident: key.Ident{Domain: testDomain, Policy: "api", Block: "by-order", Rule: "each"},
			axes:  []string{"tenant:one/two", "%3A{}"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := key.RatePrefix(tc.ident, gcra, window)
			built := key.Bucket(prefix, tc.axes)

			parsed, err := parseCounterKey(testDomain, built)
			require.NoError(t, err)

			require.Equal(t, tc.ident.Policy, parsed.Policy)
			require.Equal(t, tc.ident.Block, parsed.Block)
			require.Equal(t, tc.ident.Rule, parsed.Rule)
			require.Equal(t, ruleID(tc.ident.Policy, tc.ident.Block, tc.ident.Rule), parsed.RuleID)
			require.Equal(t, "gcra", parsed.Algorithm)
			require.Equal(t, int64(60), parsed.PeriodSeconds)
			require.Equal(t, prefix, parsed.RatePrefix)
			require.Equal(t, tc.axes, parsed.Axes)
		})
	}
}

func TestParseCounterKey_refusesWhatItCannotRead(t *testing.T) {
	cases := map[string]string{
		"another domain":                "rl:v1:{other}:api/orders/per-client:gcra:60:alice:",
		"a truncated key":               "rl:v1:{" + testDomain + "}:api/orders/per-client:",
		"a two-part rule id":            "rl:v1:{" + testDomain + "}:api/orders:gcra:60:",
		"a period that is not a number": "rl:v1:{" + testDomain + "}:api/orders/per-client:gcra:soon:",
		"a truncated escape":            "rl:v1:{" + testDomain + "}:api/orders/per-client:gcra:60:%A:",
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseCounterKey(testDomain, k)
			require.Error(t, err)
		})
	}
}

func TestNamedAxes_refusesARuleThatDisagreesWithItsCounter(t *testing.T) {
	parsed := counterKey{RuleID: "api/orders/per-client", Axes: []string{"alice"}}

	axes, err := parsed.namedAxes([]string{model.KeyClient})
	require.NoError(t, err)
	require.Equal(t, map[string]string{model.KeyClient: "alice"}, axes)

	// A rule redefined under a live counter: two axes now, one value in the key.
	_, err = parsed.namedAxes([]string{model.KeyClient, "order_id"})
	require.Error(t, err)
}
