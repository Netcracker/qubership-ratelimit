package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// discardLogger drops what the handlers write. What the log says is not what
// these tests assert; the one line that is a contract, the audit record, has
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

// cascadeBlocks is a FirstMatch cascade: an exempt client, a premium tier, and
// everyone else. It is the shape the applicability analysis exists for: a rule
// is reachable only if no earlier one decided first.
func cascadeBlocks() []model.Block {
	return []model.Block{{
		Name: "cascade",
		Mode: model.ModeFirstMatch,
		Target: model.Target{Routes: []model.Route{{
			Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/invoices/"},
		}}},
		Rules: []model.Rule{
			{
				Name:     "internal",
				Behavior: model.BehaviorBypass,
				Matches: []model.Predicate{{
					Key: model.KeySub, Operator: model.OperatorEquals, Value: "prometheus",
				}},
			},
			{
				Name: "premium",
				Matches: []model.Predicate{{
					Key: "plan", Operator: model.OperatorEquals, Value: "premium",
				}},
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{{Requests: 1000, Period: time.Minute}},
			},
			{
				Name:     "everyone",
				Counters: []string{model.KeySub},
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
					Counters: []string{model.KeySub},
					Rates:    []model.Rate{{Requests: 3, Period: time.Hour}},
				},
				{
					Name: "support",
					Matches: []model.Predicate{{
						Key: "roles", Operator: model.OperatorContains, Value: "support",
					}},
					Counters:      []string{model.KeySub},
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
				Counters: []string{model.KeySub, "order_id"},
				Rates: []model.Rate{
					{Requests: 5, Period: time.Minute},
					{Requests: 20, Period: time.Hour},
				},
			}},
		},
	}
}

// orderCascadeBlocks is a FirstMatch cascade reached through a prefix route
// that produces no capture and through a template route that produces one,
// with the capture-keyed rule ahead of the per-client one: the two routes of
// the example policy's orders block, the prefix route first so that under any
// method the route depends on the method.
func orderCascadeBlocks() []model.Block {
	return []model.Block{{
		Name: "order-ops",
		Mode: model.ModeFirstMatch,
		Target: model.Target{Routes: []model.Route{
			{
				Path:    model.PathMatch{Type: model.PathPrefix, Value: "/api/orders"},
				Methods: []string{http.MethodPost, http.MethodPut},
			},
			{Path: model.PathMatch{Type: model.PathTemplate, Value: "/api/orders/{order_id}/items"}},
		}},
		Rules: []model.Rule{
			{
				Name:     "items-per-order",
				Matches:  []model.Predicate{{Key: "order_id", Operator: model.OperatorExists}},
				Counters: []string{"order_id"},
				Rates:    []model.Rate{{Requests: 10, Period: time.Minute}},
			},
			{
				Name:     "orders-per-client",
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{{Requests: 50, Period: time.Minute}},
			},
		},
	}}
}

// planCascadeBlocks is a FirstMatch cascade whose template capture shadows the
// mapped key plan: through the template route the capture is the plan of the
// request, through the prefix route, first so that the method picks the route,
// the identity's plan applies. The first rule tests the value, so which plan
// the block sees decides it.
func planCascadeBlocks() []model.Block {
	return []model.Block{{
		Name: "plan-ops",
		Mode: model.ModeFirstMatch,
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathPrefix, Value: "/plans"}, Methods: []string{http.MethodPost}},
			{Path: model.PathMatch{Type: model.PathTemplate, Value: "/plans/{plan}/items"}},
		}},
		Rules: []model.Rule{
			{
				Name:     "silver-only",
				Matches:  []model.Predicate{{Key: "plan", Operator: model.OperatorEquals, Value: "silver"}},
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{{Requests: 10, Period: time.Minute}},
			},
			{
				Name:     "per-client",
				Counters: []string{model.KeySub},
				Rates:    []model.Rate{{Requests: 50, Period: time.Minute}},
			},
		},
	}}
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
// identity keys the fixtures read, a scalar plan, lowercased, and an
// array-valued roles. The mappings and the blocks are one object and compile
// as one unit.
func testPolicy(blocks []model.Block) model.Policy {
	return model.Policy{
		Domain: testDomain,
		Mappings: []model.KeyMapping{
			{Key: "plan", Claim: "plan", Normalization: model.NormalizeLowercase},
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
	var blocking []compile.Problem
	for _, problem := range problems {
		if problem.Blocking {
			blocking = append(blocking, problem)
		}
	}
	require.Empty(t, blocking, "compile.Compile(%s) refused the fixture policy", testDomain)
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
		blocks = append(cascadeBlocks(), orderBlocks()...)
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
		Callers:   []string{listedCaller, otherCaller},
		Log:       discardLogger{},
	}
	verifier := Verifier(readingVerifier{})
	api.verifier.Store(&verifier)
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

// The callers of these tests, as the sub claims of their tokens. The API lists
// the first two, so each holds operator; the third is verified and listed
// nowhere, so it holds no role.
const (
	listedCaller   = "system:serviceaccount:" + testNamespace + ":ui-backend"
	otherCaller    = "system:serviceaccount:" + testNamespace + ":ops-backend"
	unlistedCaller = "system:serviceaccount:" + testNamespace + ":intruder"
)

// call runs one request through the whole app, as caller.
func (h *testAPI) call(t *testing.T, method, target string, caller string, body any) *testResponse {
	t.Helper()
	return h.callWith(t, method, target, caller, body, nil)
}

// rawJSON is a request body sent as written, for the bodies json.Marshal does
// not produce, such as a value followed by trailing data.
type rawJSON string

// callWith runs one request as caller, letting the test shape the headers, such
// as an Idempotency-Key or a request id, before it goes out. A body other than a
// rawJSON is sent as its JSON encoding.
func (h *testAPI) callWith(
	t *testing.T,
	method, target string,
	caller string,
	body any,
	prepare func(*http.Request),
) *testResponse {
	t.Helper()

	payload := ""
	switch value := body.(type) {
	case nil:
	case rawJSON:
		payload = string(value)
	default:
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		payload = string(encoded)
	}

	request := httptest.NewRequest(method, target, strings.NewReader(payload))
	if body != nil {
		request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer "+testToken(caller))
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
// The app is exercised whole, with its routing, middleware, and error handler,
// rather than one handler in isolation, because most of what this API promises
// lives in that chain: the request id, the identity, the role gate, and the
// shape every refusal comes back in.
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

// testResponse is one answer, in the shape the assertions of these tests read
// it.
type testResponse struct {
	Code int
	Body *bytes.Buffer

	header http.Header
}

func (r *testResponse) Header() http.Header { return r.header }

// testToken builds the token of a ServiceAccount whose sub claim is subject,
// in the shape the API server issues: sub and the kubernetes.io claim. It is
// unsigned, because readingVerifier stands in for the signature check.
func testToken(subject string) string {
	namespace, name := "", ""
	if parts := strings.Split(subject, ":"); len(parts) == 4 {
		namespace, name = parts[2], parts[3]
	}
	return tokenWithClaims(map[string]any{
		"sub": subject,
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": name},
		},
	})
}

// tokenWithClaims builds an unsigned bearer token carrying claims, for the
// shapes testToken's fixed one cannot express.
func tokenWithClaims(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// readingVerifier accepts every well-formed token and returns its claims, so
// the tests exercise what the API does with a verified token. Verification
// itself is the m2m package's, and identity_test.go pins how the API answers
// each of its refusals.
type readingVerifier struct{}

func (readingVerifier) Verify(_ context.Context, raw string) (*jwt.Token, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", jwt.ErrTokenMalformed, err)
	}
	return parsed, nil
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

// maxListedPages bounds how many pages listPages follows before it fails the
// test as a listing that never ends.
const maxListedPages = 20

// listPages follows a counter listing from target, which already carries a
// query, through every nextCursor, and returns its pages in order. It stops
// the test once the listing runs past maxListedPages pages.
func (h *testAPI) listPages(t *testing.T, target string) []CounterList {
	t.Helper()

	var pages []CounterList
	next := target
	for {
		var page CounterList
		decode(t, h.call(t, http.MethodGet, next, listedCaller, nil), http.StatusOK, &page)
		pages = append(pages, page)
		if page.NextCursor == "" {
			return pages
		}
		require.Less(t, len(pages), maxListedPages, "GET %s: the listing did not end", target)
		next = target + "&cursor=" + url.QueryEscape(page.NextCursor)
	}
}

// subsOf returns the sub axis value of each listed counter, in listing order.
func subsOf(items []CounterView) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Axes[model.KeySub])
	}
	return out
}
