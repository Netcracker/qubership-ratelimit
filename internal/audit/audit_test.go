package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwitchboard_nothingIsStreamedByDefault(t *testing.T) {
	// A record per decision per replica is a firehose, so the shipped state is
	// silence and turning it on is a deliberate act.
	board := NewSwitchboard()

	assert.False(t, board.Any())
	assert.False(t, board.Enabled("gateway.public", "api", "orders", "per-client"))
	assert.Empty(t, board.Selection().Rules)
}

func TestSwitchboard_streamsOnlyTheSelectedRule(t *testing.T) {
	board := NewSwitchboard()

	board.Set(Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "api/orders/per-client"}}})

	assert.True(t, board.Enabled("gateway.public", "api", "orders", "per-client"))
	assert.False(t, board.Enabled("gateway.public", "api", "orders", "other"))
	assert.False(t, board.Enabled("gateway.private", "api", "orders", "per-client"),
		"a rule of another domain is another rule")
}

func TestSelectionNormalize_dropsDuplicatesAndOrders(t *testing.T) {
	// Two ways of writing one selection have to store and report identically,
	// or a client comparing what it sent with what it gets back sees a change
	// that did not happen.
	selection := Selection{Rules: []RuleRef{
		{Domain: "gateway.public", RuleID: "b/b/b"},
		{Domain: "gateway.public", RuleID: "a/a/a"},
		{Domain: "gateway.public", RuleID: "b/b/b"},
	}}

	normalized := selection.Normalize()

	require.Len(t, normalized.Rules, 2)
	assert.Equal(t, "a/a/a", normalized.Rules[0].RuleID)
	assert.Equal(t, "b/b/b", normalized.Rules[1].RuleID)
}

func TestHub_deliversToEverySubscriber(t *testing.T) {
	hub := NewHub()
	first, closeFirst := hub.Subscribe()
	defer closeFirst()
	second, closeSecond := hub.Subscribe()
	defer closeSecond()

	hub.Publish(Record{RuleID: "api/orders/per-client"})

	assert.Equal(t, "api/orders/per-client", (<-first.Records()).RuleID)
	assert.Equal(t, "api/orders/per-client", (<-second.Records()).RuleID)
}

func TestHub_publishingWithoutSubscribersIsHarmless(t *testing.T) {
	hub := NewHub()

	hub.Publish(Record{RuleID: "api/orders/per-client"})

	assert.Zero(t, hub.Subscribers())
}

func TestHub_dropsRecordsForASubscriberThatIsBehind(t *testing.T) {
	// The decision path publishes while answering a rate limit check. A reader
	// that cannot keep up has to lose records rather than hold up a gateway,
	// and it has to be counted so the reader can be told its view has gaps.
	hub := NewHub()
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	for range subscriberBuffer + 10 {
		hub.Publish(Record{RuleID: "api/orders/per-client"})
	}

	assert.Equal(t, uint64(10), subscription.Dropped())
	assert.Len(t, subscription.Records(), subscriberBuffer)
}

func TestHub_unsubscribingStopsDelivery(t *testing.T) {
	hub := NewHub()
	subscription, unsubscribe := hub.Subscribe()

	unsubscribe()
	hub.Publish(Record{RuleID: "api/orders/per-client"})

	assert.Zero(t, hub.Subscribers())
	assert.Empty(t, subscription.Records())
}
