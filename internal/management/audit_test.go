package management

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// Every mutation is audited, and the journal is the primary carrier: who
// called, which key they used, what they addressed, and what came of it. These
// tests hold that line to its contract — including the part of it the logger
// contributes, since the request id reaches the line through the context rather
// than through a field the handler writes.

// recordingLogger keeps what the handlers logged, with the context each line
// was written under.
type recordingLogger struct {
	mu    sync.Mutex
	lines []loggedLine
}

type loggedLine struct {
	ctx     context.Context
	message string
}

func (l *recordingLogger) DebugC(context.Context, string, ...any) {}

func (l *recordingLogger) InfoC(ctx context.Context, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, loggedLine{ctx: ctx, message: fmt.Sprintf(format, args...)})
}

func (l *recordingLogger) ErrorC(ctx context.Context, format string, args ...any) {
	l.InfoC(ctx, format, args...)
}

// find returns the one line whose message starts with the prefix.
func (l *recordingLogger) find(t *testing.T, prefix string) loggedLine {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.HasPrefix(line.message, prefix) {
			return line
		}
	}
	t.Fatalf("no log line starting with %q; got %v", prefix, l.lines)
	return loggedLine{}
}

func TestAudit_recordsWhatTheMutationDid(t *testing.T) {
	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log

	h.spend(t, "/api/orders", map[string][]string{model.KeyClient: {"crawler"}}, 3)
	require.Equal(t, http.StatusOK,
		h.reset(t, "ruleId=api/orders/per-client&axis.client=crawler", "key-1", operatorRoles()).Code)

	line := log.find(t, "management mutation ")
	for _, part := range []string{
		"subject=alice@example.com",
		"idempotencyKey=key-1",
		"domain=" + testDomain,
		"endpoint=counters",
		"ruleId=api/orders/per-client",
		"crawler",
		"outcome=reset",
		"count=1",
	} {
		require.Contains(t, line.message, part)
	}
}

// The bulk journal entry is written at acceptance, because acceptance is the
// moment the deletions became inevitable.
func TestAudit_recordsABulkAcceptance(t *testing.T) {
	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log

	h.preview(t, map[string]any{
		"selector": map[string]any{"ruleIds": []string{"api/orders"}},
	}, "key-1")

	line := log.find(t, "management mutation accepted")
	for _, part := range []string{
		"subject=alice@example.com",
		"idempotencyKey=key-1",
		"endpoint=counter-resets",
		"command=preview-selector",
		"dryRun=true",
		"api/orders",
	} {
		require.Contains(t, line.message, part)
	}
}

// The request id is not a field the handlers write. It reaches the line through
// the context the platform's logger reads it from, which is the same value the
// response header carries — so quoting one finds the other.
func TestAudit_carriesTheRequestIDThroughItsContext(t *testing.T) {
	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log

	recorder := h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-1", operatorRoles())
	require.Equal(t, http.StatusOK, recorder.Code)

	line := log.find(t, "management mutation ")
	require.NotContains(t, line.message, "requestId=",
		"the id belongs to the logger's own field, not to the message")

	id, err := xrequestid.Of(line.ctx)
	require.NoError(t, err, "the line was written under a context carrying the id")
	require.Equal(t, recorder.Header().Get(RequestIDHeader), id.GetRequestId())
}

// A caller-supplied id runs through unchanged, which is what makes it worth
// quoting.
func TestAudit_carriesTheCallersRequestID(t *testing.T) {
	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log

	target := BasePath + "/domains/" + testDomain +
		"/counters?ruleId=api/orders/per-client&axis.client=alice"
	recorder := h.callWith(t, http.MethodDelete, target, operatorRoles(), nil,
		func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "key-1")
			request.Header.Set(RequestIDHeader, "trace-42")
		})
	require.Equal(t, http.StatusOK, recorder.Code)

	id, err := xrequestid.Of(log.find(t, "management mutation ").ctx)
	require.NoError(t, err)
	require.Equal(t, "trace-42", id.GetRequestId())
}
