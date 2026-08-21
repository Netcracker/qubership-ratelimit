package management

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/key"
)

// testPrefix builds a rate prefix the way compilation does, so the round-trip
// below runs against the real key layout rather than a string this test made
// up.
func testPrefix(t *testing.T) string {
	t.Helper()
	algorithm, ok := algo.ByName("FixedWindow")
	require.True(t, ok)
	return key.RatePrefix(
		key.Ident{Domain: testDomain, Policy: "api", Block: "orders", Rule: "per-client"},
		algorithm,
		algo.Window{Requests: 3, Period: time.Hour},
	)
}

func TestDecodeAxes_roundTripsWhatTheKeySchemaEncodes(t *testing.T) {
	// The engine builds keys and never reads them back, so this decoder is the
	// only other implementation of the layout. Pinning it against key.Bucket is
	// what turns a future change upstream into a failing test here instead of a
	// reset that silently misses live counters.
	prefix := testPrefix(t)
	values := []string{
		"alice",
		"tenant:with:colons",
		"path/with/slashes",
		"already%3Aescaped",
		"{braces}",
		"unicode-ключ",
		"%",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			encoded := key.Bucket(prefix, []string{value})

			axes, err := decodeAxes(encoded, prefix, []string{"client"})

			require.NoError(t, err)
			assert.Equal(t, map[string]string{"client": value}, axes)
		})
	}
}

func TestDecodeAxes_readsSeveralAxesInOrder(t *testing.T) {
	prefix := testPrefix(t)
	encoded := key.Bucket(prefix, []string{"acme", "alice"})

	axes, err := decodeAxes(encoded, prefix, []string{"tenant", "client"})

	require.NoError(t, err)
	assert.Equal(t, map[string]string{"tenant": "acme", "client": "alice"}, axes)
}

func TestDecodeAxes_aRuleWithoutAxesHasNone(t *testing.T) {
	// A rule counting the whole domain has one bucket, and its key is the bare
	// prefix. Reporting an axis there would invent a client that does not exist.
	prefix := testPrefix(t)

	axes, err := decodeAxes(prefix, prefix, nil)

	require.NoError(t, err)
	assert.Empty(t, axes)
}

func TestDecodeAxes_rejectsAKeyFromAnotherRate(t *testing.T) {
	prefix := testPrefix(t)

	_, err := decodeAxes("rl:v1:{other}:api/orders/per-client:fixedwindow:60:alice:", prefix, []string{"client"})

	require.Error(t, err)
}

func TestDecodeAxes_rejectsACountMismatch(t *testing.T) {
	// A key carrying more values than the rule declares means the decoder and
	// the rule set disagree, which is exactly the drift this must not paper
	// over by pairing values with the wrong names.
	prefix := testPrefix(t)
	encoded := key.Bucket(prefix, []string{"acme", "alice"})

	_, err := decodeAxes(encoded, prefix, []string{"client"})

	require.Error(t, err)
}

func TestUnescapeSegment_rejectsATruncatedEscape(t *testing.T) {
	_, err := unescapeSegment("alice%3")

	require.Error(t, err)
}

func TestUnescapeSegment_rejectsANonHexEscape(t *testing.T) {
	_, err := unescapeSegment("alice%ZZ")

	require.Error(t, err)
}
