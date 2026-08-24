package management

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forged is what a caller sends when they want the audit trail to say something
// other than what happened: a newline, then a line that looks like the
// operator's own.
const forged = "acme\nrate limit management mutation action=ResetCounters outcome=succeeded subject=somebody-else"

func TestAudit_cannotBeForgedThroughTheValuesItRecords(t *testing.T) {
	// The rule, the domain and the axis values all arrive on the request, so an
	// audit trail that copied them verbatim could be written by the very party
	// it is auditing.
	var recorded strings.Builder
	auditor := &KubeAuditor{
		Log: funcr.New(func(prefix, args string) { recorded.WriteString(args + "\n") },
			funcr.Options{}),
	}

	auditor.Record(context.Background(), AuditEvent{
		Action:  ActionResetCounters,
		Outcome: OutcomeSucceeded,
		Subject: Subject{Name: "system:serviceaccount:core:oncall"},
		Domain:  forged,
		RuleID:  forged,
		Axes:    map[string]string{"tenant": forged},
		Reason:  forged,
	})

	// The sink escapes what it is handed, so a raw newline shows up as the two
	// characters \n. Its absence is what proves the newline never reached the
	// logger, rather than having been escaped on the way out — a formatter that
	// escapes is not a guarantee the next one will.
	logged := recorded.String()
	require.NotEmpty(t, logged)
	assert.NotContains(t, logged, `\n`,
		"a newline survived into a recorded value, so the caller can forge records")
	assert.Contains(t, logged, "acme", "the value itself must still be recorded")
}

func TestLogSafe_boundsAnUnboundedValue(t *testing.T) {
	// The length is chosen by the client, so an unbounded copy is an unbounded
	// log record.
	assert.LessOrEqual(t, len(logSafe(strings.Repeat("a", 10_000))), maxLoggedValueLength)
}

func TestLogSafe_keepsAnOrdinaryValueIntact(t *testing.T) {
	assert.Equal(t, "api-defaults/api/per-path", logSafe("api-defaults/api/per-path"))
}
