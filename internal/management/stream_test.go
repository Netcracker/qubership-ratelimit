package management

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
)

// withSelectionStore gives the API somewhere to persist the audit selection,
// backed by a fake API server so the ConfigMap round trip is the real one.
func (h *testAPI) withSelectionStore(t *testing.T) *testAPI {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	h.api.Selection = &auditstream.Store{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		Namespace: "core",
	}
	return h
}

func TestGetAudit_reportsNothingSelectedByDefault(t *testing.T) {
	// The stream is a firehose at gateway speed, so the shipped state is off.
	h := newTestAPI(t)

	recorder := h.call(t, allowAll(), http.MethodGet, BasePath+"/audit", nil)

	require.Equal(t, http.StatusOK, recorder.Code)
	view := decodeBody[AuditView](t, recorder)
	assert.Empty(t, view.Rules)
	assert.Equal(t, auditstream.MaxSelectedRules, view.MaxRules)
	assert.Equal(t, BasePath+"/audit/stream", view.StreamPath)
	assert.Equal(t, "ratelimit-test-0", view.Replica)
}

func TestPutAudit_selectsARule(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/per-client"}},
	})

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Len(t, decodeBody[AuditView](t, recorder).Rules, 1)
	assert.True(t, h.api.Switchboard.Enabled(testDomain, "api", "orders", "per-client"))
}

func TestPutAudit_persistsTheSelectionForEveryReplica(t *testing.T) {
	// A selection held in one process would stream one replica's share of the
	// traffic and leave the operator wondering why the rule looks quiet.
	h := newTestAPI(t).withSelectionStore(t)

	h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/per-client"}},
	})

	stored, err := h.api.Selection.Load(context.Background())
	require.NoError(t, err)
	require.Len(t, stored.Rules, 1)
	assert.Equal(t, "api/orders/per-client", stored.Rules[0].RuleID)
}

func TestPutAudit_anEmptySelectionTurnsTheStreamOff(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)
	h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/per-client"}},
	})

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{})

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.False(t, h.api.Switchboard.Any())
}

func TestPutAudit_rejectsARuleThatIsNotEnforced(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/typo"}},
	})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.False(t, h.api.Switchboard.Any(), "a rejected selection must not switch anything on")
}

func TestPutAudit_rejectsAnUnboundDomain(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: "gateway.typo", RuleID: "api/orders/per-client"}},
	})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Contains(t, decodeBody[Problem](t, recorder).Detail, "gateway.typo")
}

func TestPutAudit_refusesMoreRulesThanTheCeiling(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)
	selection := auditstream.Selection{}
	for i := range auditstream.MaxSelectedRules + 1 {
		selection.Rules = append(selection.Rules, auditstream.RuleRef{
			Domain: testDomain,
			RuleID: "api/orders/per-client-" + strings.Repeat("x", i),
		})
	}

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", selection)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestPutAudit_leavesAnAuditRecord(t *testing.T) {
	h := newTestAPI(t).withSelectionStore(t)

	h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/per-client"}},
	})

	event := h.auditor.last()
	assert.Equal(t, ActionSetAudit, event.Action)
	assert.Equal(t, OutcomeSucceeded, event.Outcome)
	assert.Equal(t, "system:serviceaccount:core:operator", event.Subject.Name)
}

func TestStreamAudit_deliversARecordAsAnEvent(t *testing.T) {
	h := newTestAPI(t)
	server := httptest.NewServer(h.api.Handler(allowAll(), allowAll(), nil))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		server.URL+BasePath+"/audit/stream", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer test-token")

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "text/event-stream", response.Header.Get("Content-Type"))

	reader := bufio.NewReader(response.Body)
	// The opening comment proves the handler is subscribed: publishing before
	// it is would race the subscription and drop the record.
	opening, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, opening, "ratelimit-test-0")

	h.api.Hub.Publish(auditstream.Record{
		Domain:  testDomain,
		RuleID:  "api/orders/per-client",
		Verdict: auditstream.VerdictRefused,
		Limit:   3,
		Replica: "ratelimit-test-0",
	})

	event := readUntil(t, reader, "event: decision")
	data, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "event: decision", event)
	assert.Contains(t, data, `"ruleId":"api/orders/per-client"`)
	assert.Contains(t, data, `"verdict":"refused"`)
}

func TestStreamAudit_filtersByRule(t *testing.T) {
	h := newTestAPI(t)
	server := httptest.NewServer(h.api.Handler(allowAll(), allowAll(), nil))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		server.URL+BasePath+"/audit/stream?ruleId=api/orders/per-client", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer test-token")

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	reader := bufio.NewReader(response.Body)
	_, err = reader.ReadString('\n')
	require.NoError(t, err)

	// The unwanted record goes first. If the filter leaked, it would be the
	// one the reader picks up below.
	h.api.Hub.Publish(auditstream.Record{Domain: testDomain, RuleID: "global/everything/total"})
	h.api.Hub.Publish(auditstream.Record{Domain: testDomain, RuleID: "api/orders/per-client"})

	readUntil(t, reader, "event: decision")
	data, err := reader.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, data, "api/orders/per-client")
	assert.NotContains(t, data, "global/everything/total")
}

// readUntil reads lines until one equals want, failing the test if the stream
// ends first.
func readUntil(t *testing.T, reader *bufio.Reader, want string) string {
	t.Helper()
	for range 50 {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.TrimRight(line, "\n") == want {
			return want
		}
	}
	t.Fatalf("the stream never carried %q", want)
	return ""
}

// TestPutAudit_reportsAStoreFailure keeps the endpoint honest about the one
// failure that matters: the selection is shared state, and a client told the
// rule is streaming when the write failed would wait for records that never
// arrive.
func TestPutAudit_reportsAStoreFailure(t *testing.T) {
	h := newTestAPI(t)
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	h.api.Selection = &auditstream.Store{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(failingCreate()).Build(),
		Namespace: "core",
	}

	recorder := h.call(t, allowAll(), http.MethodPut, BasePath+"/audit", auditstream.Selection{
		Rules: []auditstream.RuleRef{{Domain: testDomain, RuleID: "api/orders/per-client"}},
	})

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.False(t, h.api.Switchboard.Any(), "a failed write must not leave this replica streaming alone")
}

// failingCreate makes the fake API server refuse to create the ConfigMap.
func failingCreate() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return errors.New("the API server is unavailable")
		},
	}
}
