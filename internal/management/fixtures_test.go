package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/records"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// discardLogger drops what the handlers write. What the log says is not what
// these tests assert; the one line that is a contract — the audit record — has
// its own test.
type discardLogger struct{}

func (discardLogger) DebugC(context.Context, string, ...any) {}
func (discardLogger) InfoC(context.Context, string, ...any)  {}
func (discardLogger) ErrorC(context.Context, string, ...any) {}

// testDomain is the domain every fixture binds to, and testNamespace is the
// installation it belongs to: both are segments of every counter key.
const (
	testDomain    = "gateway.public"
	testNamespace = "core-1-core"
)

// quoteBlocks is a FirstMatch cascade: an exempt client, a premium tier, and
// everyone else. It is the shape the applicability analysis exists for — a rule
// is reachable only if no earlier one decided first.
func quoteBlocks() []model.Block {
	return []model.Block{{
		Name: "cascade",
		Mode: model.ModeFirstMatch,
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/quotes/"},
		}}},
		Rules: []model.Rule{
			{
				Name:     "internal",
				Behavior: model.BehaviorBypass,
				Matches: []model.Predicate{{
					Key: model.KeyClient, Operator: model.OperatorEquals, Value: "prometheus",
				}},
			},
			{
				Name: "premium",
				Matches: []model.Predicate{{
					Key: "plan", Operator: model.OperatorEquals, Value: "premium",
				}},
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{{Requests: 1000, Period: time.Minute}},
			},
			{
				Name:     "everyone",
				Counters: []string{model.KeyClient},
				Rates:    []model.Rate{{Requests: 100, Period: time.Minute}},
			},
		},
	}}
}

// orderBlocks is an All block where a narrow rule replaces a wide one, plus a
// template block whose capture is a second counter axis.
func orderBlocks() []model.Block {
	return []model.Block{
		{
			Name: "orders",
			Target: model.Target{Routes: []model.Route{{
				Path:    model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"},
				Methods: []string{http.MethodGet, http.MethodPost},
			}}},
			Rules: []model.Rule{
				{
					Name:     "per-client",
					Counters: []string{model.KeyClient},
					Rates:    []model.Rate{{Requests: 3, Period: time.Hour}},
				},
				{
					Name: "support",
					Matches: []model.Predicate{{
						Key: "roles", Operator: model.OperatorContains, Value: "support",
					}},
					Counters:      []string{model.KeyClient},
					ReplacedRules: []string{"per-client"},
					Rates:         []model.Rate{{Requests: 50, Period: time.Hour}},
				},
			},
		},
		{
			Name: "by-order",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}"},
			}}},
			Rules: []model.Rule{{
				Name:     "each",
				Counters: []string{model.KeyClient, "order_id"},
				Rates: []model.Rate{
					{Requests: 5, Period: time.Minute},
					{Requests: 20, Period: time.Hour},
				},
			}},
		},
	}
}

// widerOrders is orderBlocks with a second window on per-client: the rollout
// that changes both the rule set version and the keys the rule addresses, which
// is what a replay must not pick up.
func widerOrders() []model.Block {
	blocks := orderBlocks()
	blocks[0].Rules[0].Rates = append(blocks[0].Rules[0].Rates,
		model.Rate{Requests: 100, Period: 24 * time.Hour, Algorithm: "FixedWindow"})
	return blocks
}

// wholeDomainBlocks counts every request together, with no axis at all: its
// counter key is the bare rate prefix, the other case a listing and a reset
// have to handle.
func wholeDomainBlocks() []model.Block {
	return []model.Block{{
		Name: "everything",
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/"},
		}}},
		Rules: []model.Rule{{
			Name:  "total",
			Rates: []model.Rate{{Requests: 2, Period: time.Hour}},
		}},
	}}
}

// testPolicy is the singleton of the domain: the blocks under test plus the
// identity keys the fixtures read, a scalar plan and an array-valued roles.
// Extraction and rules live in one object now, so they compile as one unit.
func testPolicy(blocks []model.Block) model.Policy {
	return model.Policy{
		Domain: testDomain,
		Mappings: []model.KeyMapping{
			{Key: "plan", Claim: "plan"},
			{Key: "roles", Claim: "roles", Type: model.ValueStringArray},
		},
		Blocks: blocks,
	}
}

// compileSnapshot builds the snapshot the endpoints read.
func compileSnapshot(t *testing.T, blocks []model.Block) *compile.Snapshot {
	t.Helper()
	policy := testPolicy(blocks)
	snapshot, problems := compile.Compile(testNamespace, testDomain, &policy)
	for _, problem := range problems {
		require.False(t, problem.Blocking, "blocking compile problem: %+v", problem)
	}
	return snapshot
}

// testAPI wires an API over in-process counters, with the engine attached so a
// test can spend a budget through the same path the gateway uses.
type testAPI struct {
	api      *API
	app      *fiber.App
	records  *records.Memory
	snapshot *compile.Snapshot
	version  string
	engine   *engine.Engine
	counters counters.Store
}

func newTestAPI(t *testing.T, blocks ...model.Block) *testAPI {
	t.Helper()
	if len(blocks) == 0 {
		blocks = append(quoteBlocks(), orderBlocks()...)
	}

	snapshot := compileSnapshot(t, blocks)
	version := ruleview.Version(snapshot)
	counterStore := memory.New()
	decisionEngine := engine.New(snapshot, counterStore)

	rules := store.New()
	rules.Replace(store.NewRuleSet(map[string]store.Domain{
		testDomain: {Engine: decisionEngine, Snapshot: snapshot, Version: version},
	}))

	commands := records.NewMemory(counterStore)
	api := &API{
		Rules:     rules,
		Namespace: testNamespace,
		Counters:  counterStore,
		Records:   commands,
		Log:       discardLogger{},
	}
	app, err := NewApp(api)
	require.NoError(t, err)

	return &testAPI{
		api:      api,
		app:      app,
		records:  commands,
		snapshot: snapshot,
		version:  version,
		engine:   decisionEngine,
		counters: counterStore,
	}
}

// spend charges the engine as a real request would, so the counters a test
// lists or resets were created by the decision path rather than written by
// hand.
func (h *testAPI) spend(t *testing.T, path string, keys map[string][]string, times int) {
	t.Helper()
	for range times {
		_, err := h.engine.Decide(context.Background(), engine.Request{
			Path: path, Method: http.MethodGet, Keys: keys,
		})
		require.NoError(t, err)
	}
}

// roles is the token role set every request in these tests carries unless it
// says otherwise.
func viewerRoles() []string   { return []string{RoleViewer} }
func operatorRoles() []string { return []string{RoleOperator} }

// call runs one request through the whole app, as an authenticated caller.
func (h *testAPI) call(t *testing.T, method, target string, roles []string, body any) *testResponse {
	t.Helper()

	var reader *strings.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(encoded))
	} else {
		reader = strings.NewReader("")
	}

	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer "+testToken("alice@example.com", roles))
	return h.send(t, request)
}

// callWith runs one request, letting the caller shape the headers — an
// Idempotency-Key, another subject's token — before it goes out.
func (h *testAPI) callWith(
	t *testing.T,
	method, target string,
	roles []string,
	body any,
	prepare func(*http.Request),
) *testResponse {
	t.Helper()

	reader := strings.NewReader("")
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(encoded))
	}

	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer "+testToken("alice@example.com", roles))
	if prepare != nil {
		prepare(request)
	}
	return h.send(t, request)
}

// replaceRules swaps the enforced set, as a rollout does. Counters of rules
// that are gone live on until their TTL, which is what makes them orphans.
func (h *testAPI) replaceRules(t *testing.T, blocks ...model.Block) {
	t.Helper()

	snapshot := compileSnapshot(t, blocks)
	version := ruleview.Version(snapshot)
	h.api.Rules.Replace(store.NewRuleSet(map[string]store.Domain{
		testDomain: {
			Engine:   engine.New(snapshot, h.counters),
			Snapshot: snapshot,
			Version:  version,
		},
	}))
	h.snapshot, h.version = snapshot, version
}

// clock freezes the API's and the record store's time so a test can move it,
// which is how a dead sweep's lease is made to expire without waiting.
func (h *testAPI) clock(t *testing.T) *time.Time {
	t.Helper()

	now := time.Now()
	h.api.Now = func() time.Time { return now }
	h.records.Now = func() time.Time { return now }
	return &now
}

// send runs one prepared request through the app.
//
// The app is exercised whole — routing, middleware, error handler — rather than
// one handler in isolation, because most of what this API promises lives in
// that chain: the request id, the identity, the role gate, and the shape every
// refusal comes back in.
func (h *testAPI) send(t *testing.T, request *http.Request) *testResponse {
	t.Helper()

	// A negative timeout disables the test client's own deadline: these calls
	// talk to an in-process store, and a deadline here would only add flakes.
	response, err := h.app.Test(request, -1)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	validateAgainstSpec(t, request, response.StatusCode, response.Header, body)

	return &testResponse{Code: response.StatusCode, Body: bytes.NewBuffer(body), header: response.Header}
}

// testResponse is one answer, in the shape the assertions below read it.
type testResponse struct {
	Code int
	Body *bytes.Buffer

	header http.Header
}

func (r *testResponse) Header() http.Header { return r.header }

// testToken builds an unsigned JWT payload. The service reads the token and
// never verifies it — the gateway's auth extension did — so a test needs no
// signing key to exercise the identity middleware.
func testToken(subject string, roles []string) string {
	payload, err := json.Marshal(map[string]any{"sub": subject, "roles": roles})
	if err != nil {
		panic(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// tokenWithClaims builds a bearer token carrying an arbitrary payload, for the
// claim shapes testToken's fixed one cannot express.
func tokenWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// decode reads a JSON response body into v, failing on a status other than the
// one expected.
func decode(t *testing.T, recorder *testResponse, status int, v any) {
	t.Helper()
	require.Equal(t, status, recorder.Code, "body: %s", recorder.Body.String())
	if v != nil {
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), v))
	}
}

// errorBody is the part of the TMF envelope the tests assert on.
type errorBody struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Type    string `json:"@type"`
	Meta    struct {
		RequestID    string        `json:"requestId"`
		Fields       []string      `json:"fields"`
		ConflictType string        `json:"conflictType"`
		PartialReset *PartialReset `json:"partialReset"`
	} `json:"meta"`
}

// requireError asserts the status and the catalog code of a refusal.
func requireError(t *testing.T, recorder *testResponse, status int, code errs.ErrorCode) errorBody {
	t.Helper()
	var body errorBody
	decode(t, recorder, status, &body)
	require.Equal(t, code.Code, body.Code, "body: %s", recorder.Body.String())
	require.Equal(t, code.Title, body.Reason)
	require.NotEmpty(t, body.Meta.RequestID)
	require.Equal(t, recorder.Header().Get(RequestIDHeader), body.Meta.RequestID)
	return body
}
