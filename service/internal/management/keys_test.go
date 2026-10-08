package management

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
	require.True(t, ok, "algo.ByID(%q)", algo.GCRAID)
	window := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	cases := []struct {
		name   string
		ident  key.Ident
		axes   []string
		ruleID string
	}{
		{
			name:   "one axis",
			ident:  key.Ident{Namespace: testNamespace, Domain: testDomain, Block: "cascade", Rule: "everyone"},
			axes:   []string{"alice"},
			ruleID: "cascade/everyone",
		},
		{
			name:   "no axes at all",
			ident:  key.Ident{Namespace: testNamespace, Domain: testDomain, Block: "everything", Rule: "total"},
			ruleID: "everything/total",
		},
		{
			name:   "several axes",
			ident:  key.Ident{Namespace: testNamespace, Domain: testDomain, Block: "by-order", Rule: "each"},
			axes:   []string{"alice", "4711"},
			ruleID: "by-order/each",
		},
		{
			// The characters the key schema reserves are exactly the ones a
			// claim value can carry, and an axis that forged a segment
			// boundary would address another client's counter.
			name:   "values carrying the reserved characters",
			ident:  key.Ident{Namespace: testNamespace, Domain: testDomain, Block: "by-order", Rule: "each"},
			axes:   []string{"tenant:one/two", "%3A{}"},
			ruleID: "by-order/each",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := key.RatePrefix(tc.ident, gcra, window)
			built := key.Bucket(prefix, tc.axes)

			parsed, err := parseCounterKey(testNamespace, testDomain, built)
			require.NoError(t, err, "parseCounterKey(%q)", built)

			assert.Equal(t, counterKey{
				RuleID:        tc.ruleID,
				Block:         tc.ident.Block,
				Rule:          tc.ident.Rule,
				Algorithm:     "gcra",
				PeriodSeconds: 60,
				RatePrefix:    prefix,
				Axes:          tc.axes,
			}, parsed, "parseCounterKey(%q)", built)
		})
	}
}

func TestParseCounterKey_refusesWhatItCannotRead(t *testing.T) {
	// The hash tag carries the namespace as well as the domain, so a key of
	// another installation is as foreign as a key of another domain.
	tag := "rl:v1:{" + testNamespace + "/" + testDomain + "}:"
	cases := map[string]string{
		"another domain":                "rl:v1:{" + testNamespace + "/other}:orders/per-client:gcra:60:alice:",
		"another installation":          "rl:v1:{other-ns/" + testDomain + "}:orders/per-client:gcra:60:alice:",
		"a truncated key":               tag + "orders/per-client:",
		"a one-part rule id":            tag + "orders:gcra:60:",
		"a three-part rule id":          tag + "api/orders/per-client:gcra:60:",
		"a period that is not a number": tag + "orders/per-client:gcra:soon:",
		"a truncated escape":            tag + "orders/per-client:gcra:60:%A:",
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseCounterKey(testNamespace, testDomain, k)
			assert.Error(t, err, "parseCounterKey(%q)", k)
		})
	}
}

// A rule redefined under a live counter declares a different number of axes
// than the key carries values, and pairing the two is refused.
func TestNamedAxes_refusesARuleThatDisagreesWithItsCounter(t *testing.T) {
	parsed := counterKey{RuleID: "orders/per-client", Axes: []string{"alice"}}

	axes, err := parsed.namedAxes([]string{model.KeySub})
	require.NoError(t, err, "namedAxes([sub]) of a counter carrying one value")
	require.Equal(t, map[string]string{model.KeySub: "alice"}, axes,
		"namedAxes([sub]) of a counter carrying one value")

	_, err = parsed.namedAxes([]string{model.KeySub, "order_id"})
	assert.Error(t, err, "namedAxes([sub order_id]) of a counter carrying one value")
}

// The management side keeps its records, sweep lease, and confirmation tokens
// beside the counters they act on: the batch script deletes counter keys and
// advances the record in one call. On a cluster that is legal only while both
// hash to one slot, and a second hand-written spelling of the tag is how they
// drift apart while a standalone Redis stays green.
func TestRecordKeys_shareTheSlotOfTheCountersTheyActOn(t *testing.T) {
	gcra, ok := algo.ByID(algo.GCRAID)
	require.True(t, ok, "algo.ByID(%q)", algo.GCRAID)

	counter := key.RatePrefix(
		key.Ident{Namespace: testNamespace, Domain: testDomain, Block: "orders", Rule: "per-client"},
		gcra, algo.Window{Requests: 100, Period: time.Minute, Burst: 100})
	tag := key.DomainTag(testNamespace, testDomain)
	require.Contains(t, counter, tag, "the counter key does not carry the domain's hash tag")

	for name, k := range map[string]string{
		"the idempotency record": recordKey(testNamespace, testDomain, endpointResets, "alice", "key-1"),
		"the sweep lease":        leaseKey(testNamespace, testDomain),
		"the confirmation token": tokenKey(testNamespace, testDomain, "ct-0123456789ab"),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, k, tag)
		})
	}
}
