package rls

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// auditServer builds a server over the one-per-hour fixture with the decision
// audit stream attached.
func auditServer(t *testing.T) (*Server, *auditstream.Switchboard, *auditstream.Hub, func() string) {
	t.Helper()
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))

	switchboard := auditstream.NewSwitchboard()
	hub := auditstream.NewHub()
	log, logged := recordingLogger()

	server := NewServer(ruleStore, log, WithDecisionAudit(switchboard, hub, "ratelimit-0"))
	return server, switchboard, hub, logged
}

func TestDecisionAudit_staysSilentUntilARuleIsSelected(t *testing.T) {
	// Nothing selected is the shipped state, and it has to cost nothing: no
	// record, no log line, no subscriber woken up.
	server, _, hub, logged := auditServer(t)
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	_, err := server.ShouldRateLimit(context.Background(),
		request("gateway.public", map[string]string{"path": "/api"}))
	require.NoError(t, err)

	assert.Empty(t, subscription.Records())
	assert.NotContains(t, logged(), "decision audit")
}

func TestDecisionAudit_publishesTheSelectedRule(t *testing.T) {
	server, switchboard, hub, _ := auditServer(t)
	switchboard.Set(auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: "gateway.public", RuleID: "one/b/all"}},
	})
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	_, err := server.ShouldRateLimit(context.Background(),
		request("gateway.public", map[string]string{"path": "/api/orders", "method": "GET"}))
	require.NoError(t, err)

	record := <-subscription.Records()
	assert.Equal(t, "gateway.public", record.Domain)
	assert.Equal(t, "one/b/all", record.RuleID)
	assert.Equal(t, auditstream.VerdictAllowed, record.Verdict)
	assert.Equal(t, int64(1), record.Limit)
	assert.Equal(t, "/api/orders", record.Path)
	assert.Equal(t, "GET", record.Method)
	assert.Equal(t, "ratelimit-0", record.Replica)
	assert.False(t, record.Time.IsZero())
}

func TestDecisionAudit_reportsARefusalWithItsRetryHint(t *testing.T) {
	server, switchboard, hub, _ := auditServer(t)
	switchboard.Set(auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: "gateway.public", RuleID: "one/b/all"}},
	})
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	// One per hour: the first is admitted, the second is not.
	_, err := server.ShouldRateLimit(context.Background(), request("gateway.public", nil))
	require.NoError(t, err)
	_, err = server.ShouldRateLimit(context.Background(), request("gateway.public", nil))
	require.NoError(t, err)

	<-subscription.Records()
	refusal := <-subscription.Records()
	assert.Equal(t, auditstream.VerdictRefused, refusal.Verdict)
	assert.Zero(t, refusal.Remaining)
	assert.Positive(t, refusal.RetryAfterSeconds)
}

func TestDecisionAudit_neverCarriesTheToken(t *testing.T) {
	// The record names the rule and the verdict. Identity stays inside the
	// engine, and the raw credential never leaves the identity layer.
	server, switchboard, hub, logged := auditServer(t)
	switchboard.Set(auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: "gateway.public", RuleID: "one/b/all"}},
	})
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	_, err := server.ShouldRateLimit(context.Background(),
		request("gateway.public", map[string]string{"path": "/api", "token": rawToken}))
	require.NoError(t, err)

	record := <-subscription.Records()
	assert.NotContains(t, record.Path, "super-secret-payload")
	assert.NotContains(t, logged(), rawToken)
}

func TestDecisionAudit_ignoresARuleNobodySelected(t *testing.T) {
	server, switchboard, hub, _ := auditServer(t)
	switchboard.Set(auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: "gateway.public", RuleID: "other/block/rule"}},
	})
	subscription, unsubscribe := hub.Subscribe()
	defer unsubscribe()

	_, err := server.ShouldRateLimit(context.Background(), request("gateway.public", nil))
	require.NoError(t, err)

	assert.Empty(t, subscription.Records())
}

func TestDecisionAudit_worksWithoutTheStreamAttached(t *testing.T) {
	// A process running without the management API constructs the server with
	// no switchboard at all; the decision path must not care.
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, _ := recordingLogger()

	_, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(),
		request("gateway.public", nil))

	require.NoError(t, err)
}
