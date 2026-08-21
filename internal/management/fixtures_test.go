package management

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// testDomain is the domain every fixture binds to.
const testDomain = "gateway.public"

// perClientPolicy counts three requests an hour per client, which is the
// smallest shape that exercises an axis: the counter key carries a value, so a
// reset can name one client.
func perClientPolicy() model.Policy {
	return model.Policy{
		Name:   "api",
		Domain: testDomain,
		Blocks: []model.Block{{
			Name: "orders",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/api"},
			}}},
			Rules: []model.Rule{{
				Name:     "per-client",
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{{Requests: 3, Period: time.Hour}},
			}},
		}},
	}
}

// wholeDomainPolicy counts every request together, with no axis at all: its
// counter key is the bare rate prefix, which is the other case a reset and a
// listing have to handle.
func wholeDomainPolicy() model.Policy {
	return model.Policy{
		Name:   "global",
		Domain: testDomain,
		Blocks: []model.Block{{
			Name: "everything",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/"},
			}}},
			Rules: []model.Rule{{
				Name:  "total",
				Rates: []model.Rate{{Requests: 2, Period: time.Hour}},
			}},
		}},
	}
}

// compileSnapshot builds the snapshot the endpoints read.
func compileSnapshot(t *testing.T, policies ...model.Policy) *compile.Snapshot {
	t.Helper()
	snapshot, problems := compile.Compile(testDomain, policies, nil)
	for _, problem := range problems {
		require.False(t, problem.Blocking, "blocking compile problem: %+v", problem)
	}
	return snapshot
}

// testAPI wires an API over in-memory counters, with the engine attached so a
// test can spend a budget through the same path the gateway uses.
type testAPI struct {
	api      *API
	snapshot *compile.Snapshot
	engine   *engine.Engine
	counters counters.Store
	auditor  *recordingAuditor
}

func newTestAPI(t *testing.T, policies ...model.Policy) *testAPI {
	t.Helper()
	if len(policies) == 0 {
		policies = []model.Policy{perClientPolicy()}
	}

	snapshot := compileSnapshot(t, policies...)
	counterStore := memory.New()
	decisionEngine := engine.New(snapshot, counterStore)

	rules := store.New()
	rules.Replace(store.NewRuleSet(map[string]store.Domain{
		testDomain: {Engine: decisionEngine, Snapshot: snapshot},
	}))

	auditor := &recordingAuditor{}
	return &testAPI{
		api: &API{
			Rules:       rules,
			Counters:    counterStore,
			Scope:       ScopeShared,
			Auditor:     auditor,
			Switchboard: auditstream.NewSwitchboard(),
			Hub:         auditstream.NewHub(),
			Replica:     "ratelimit-test-0",
			Log:         logr.Discard(),
		},
		snapshot: snapshot,
		engine:   decisionEngine,
		counters: counterStore,
		auditor:  auditor,
	}
}

// spendPath is the path every fixture policy targets.
const spendPath = "/api/orders"

// spend charges the engine as a real request would, so the counters a test
// then lists or resets were created by the decision path rather than written
// by hand.
func (h *testAPI) spend(t *testing.T, client string, times int) {
	t.Helper()
	request := engine.Request{Path: spendPath}
	if client != "" {
		request.Keys = map[string][]string{model.KeyClient: {client}}
	}
	for range times {
		_, err := h.engine.Decide(context.Background(), request)
		require.NoError(t, err)
	}
}

// recordingAuditor captures the audit trail so a test can assert that a
// mutation left one.
type recordingAuditor struct {
	events []AuditEvent
}

func (a *recordingAuditor) Record(_ context.Context, event AuditEvent) {
	a.events = append(a.events, event)
}

func (a *recordingAuditor) last() AuditEvent {
	if len(a.events) == 0 {
		return AuditEvent{}
	}
	return a.events[len(a.events)-1]
}

// stubAuth authenticates and authorizes without an API server.
type stubAuth struct {
	subject       Subject
	authenticated bool
	allowed       bool
	authnErr      error
	authzErr      error
}

func allowAll() *stubAuth {
	return &stubAuth{
		subject:       Subject{Name: "system:serviceaccount:core:operator", Groups: []string{"system:serviceaccounts"}},
		authenticated: true,
		allowed:       true,
	}
}

func (s *stubAuth) Authenticate(context.Context, string) (Subject, bool, error) {
	return s.subject, s.authenticated, s.authnErr
}

func (s *stubAuth) Authorize(context.Context, Subject, string, string) (bool, string, error) {
	return s.allowed, "stub", s.authzErr
}
