package rls

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	envoycommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// rawToken is what the gateway puts in the token descriptor entry: a live
// credential that must never reach a log line.
const rawToken = "Bearer eyJhbGciOiJSUzI1NiJ9.super-secret-payload.signature"

// recordingLogger captures every log line, and the context it was written with,
// so a test can assert on the message and on what the [request_id=] field would
// resolve to.
type recorder struct {
	mu    sync.Mutex
	buf   strings.Builder
	lastC context.Context
}

func (r *recorder) InfoC(ctx context.Context, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastC = ctx
	r.buf.WriteString(fmt.Sprintf(format, args...) + "\n")
}

func (r *recorder) ErrorC(ctx context.Context, format string, args ...any) {
	r.InfoC(ctx, format, args...)
}

func (r *recorder) output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// requestIDField is what the platform log formatter would print in [request_id=].
func (r *recorder) requestIDField() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return logging.GetValueOrPlaceholder(r.lastC, logging.RequestIdContextName)
}

func recordingLogger() (*recorder, func() string) {
	r := &recorder{}
	return r, r.output
}

func request(domain string, entries map[string]string) *envoyratelimit.RateLimitRequest {
	descriptor := &envoycommon.RateLimitDescriptor{}
	// Sorted iteration is unnecessary here: the server keys on the entry name.
	for key, value := range entries {
		descriptor.Entries = append(descriptor.Entries, &envoycommon.RateLimitDescriptor_Entry{
			Key:   key,
			Value: value,
		})
	}
	return &envoyratelimit.RateLimitRequest{
		Domain:      domain,
		Descriptors: []*envoycommon.RateLimitDescriptor{descriptor},
	}
}

func TestShouldRateLimit_answersOK(t *testing.T) {
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, "gateway.public"))
	log, _ := recordingLogger()

	resp, err := NewServer(ruleStore, log).ShouldRateLimit(
		context.Background(),
		request("gateway.public", map[string]string{"path": "/api/v1/orders", "token": rawToken}),
	)

	require.NoError(t, err)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
}

func TestShouldRateLimit_unknownDomainStillAnswersOK(t *testing.T) {
	// The stub allows everything, including traffic from a domain no policy
	// claims. The metric, not the verdict, is what reports the mismatch.
	log, _ := recordingLogger()

	resp, err := NewServer(store.New(), log).ShouldRateLimit(
		context.Background(),
		request("gateway.typo", map[string]string{"path": "/api/v1/orders"}),
	)

	require.NoError(t, err)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
}

func TestShouldRateLimit_reportsAnUnknownDomain(t *testing.T) {
	// A domain no policy claims means the gateway's filter config and the CR have
	// drifted apart. Nothing else detects it, so the line has to be there.
	const domain = "gateway.typo"
	log, logged := recordingLogger()

	_, err := NewServer(store.New(), log).ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)

	output := logged()
	assert.Contains(t, output, "unknown rate limit domain")
	assert.Contains(t, output, domain)
}

func TestShouldRateLimit_saysNothingAboutAKnownDomain(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, domain))
	log, logged := recordingLogger()

	_, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)

	assert.NotContains(t, logged(), "unknown rate limit domain")
}

func TestShouldRateLimit_neverLogsTheToken(t *testing.T) {
	log, logged := recordingLogger()

	_, err := NewServer(store.New(), log).ShouldRateLimit(
		context.Background(),
		request("gateway.public", map[string]string{"path": "/api/v1/orders", "token": rawToken}),
	)
	require.NoError(t, err)

	output := logged()
	assert.NotContains(t, output, rawToken)
	assert.NotContains(t, output, "super-secret-payload")
	assert.Contains(t, output, "/api/v1/orders")
	assert.Contains(t, output, "gateway.public")
}

func TestShouldRateLimit_deniesPastTheWindowWithRetryAfter(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	first, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)
	second, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode())
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, second.GetOverallCode(),
		"Envoy turns OVER_LIMIT into 429 for the client")
	headers := headerMap(second)
	assert.Equal(t, "1", headers["x-ratelimit-limit"])
	assert.Equal(t, "0", headers["x-ratelimit-remaining"])
	assert.NotEmpty(t, headers["retry-after"], "a refusal waiting can cure carries the hint")
}

func TestShouldRateLimit_doesNotCountAnUnclaimedDomain(t *testing.T) {
	// No policy means no limit to enforce; denying would punish traffic for a
	// configuration mistake on our side.
	log, _ := recordingLogger()
	server := NewServer(store.New(), log)

	for range 3 {
		resp, err := server.ShouldRateLimit(context.Background(), request("gateway.typo", nil))
		require.NoError(t, err)
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
	}
}

func TestSanitizePath_redactsTheQueryString(t *testing.T) {
	// Envoy's :path carries the query, and a query routinely carries the very
	// credential the service must not log.
	assert.Equal(t, "/api/v1/orders?[redacted]",
		sanitizePath("/api/v1/orders?access_token=SECRET&api_key=ALSO-SECRET"))
}

func TestSanitizePath_keepsAPlainPath(t *testing.T) {
	assert.Equal(t, "/api/v1/orders", sanitizePath("/api/v1/orders"))
}

func TestSanitizePath_stripsControlCharacters(t *testing.T) {
	// Without this a caller forges log records by putting a newline in the path.
	assert.Equal(t, "/apiINFO fake log line",
		sanitizePath("/api\r\nINFO fake log line"))
}

func TestSanitizePath_truncatesALongPath(t *testing.T) {
	long := "/" + strings.Repeat("a", 500)

	got := sanitizePath(long)

	assert.Len(t, got, maxLoggedValueLength+len(valueTruncated))
	assert.True(t, strings.HasSuffix(got, valueTruncated))
}

func TestSanitizePath_truncatesOnARuneBoundary(t *testing.T) {
	// A byte cut through a multi-byte rune would leave an invalid sequence.
	got := sanitizePath(strings.Repeat("é", 200))

	assert.True(t, utf8.ValidString(got))
}

func TestLoggableEntries_isEmptyWithoutThoseEntries(t *testing.T) {
	path, requestID := loggableEntries(request("gateway.public", map[string]string{"token": rawToken}))

	assert.Empty(t, path)
	assert.Empty(t, requestID)
}

func TestLoggableEntries_readsThePathAndRequestID(t *testing.T) {
	path, requestID := loggableEntries(request("gateway.public", map[string]string{
		"path":       "/api/v1/orders",
		"request_id": "abc-123",
		"token":      rawToken,
	}))

	assert.Equal(t, "/api/v1/orders", path)
	assert.Equal(t, "abc-123", requestID)
}

func TestShouldRateLimit_putsTheRequestIDInTheLogContext(t *testing.T) {
	// The id must reach the [request_id=] field, not the message body, so the
	// line matches the format every other Qubership service emits.
	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})
	log, logged := recordingLogger()
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, "gateway.public"))

	_, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(), request("gateway.public",
		map[string]string{"path": "/api/v1/orders", "request_id": "corr-42", "token": rawToken}))
	require.NoError(t, err)

	assert.Equal(t, "corr-42", log.requestIDField())
	assert.NotContains(t, logged(), rawToken)
}

func TestSanitizeValue_stripsControlCharactersFromARequestID(t *testing.T) {
	// x-request-id may be set by the client, so it can carry a forged log record.
	_, requestID := loggableEntries(request("gateway.public", map[string]string{
		"request_id": "id\r\nINFO forged",
	}))

	assert.Equal(t, "idINFO forged", requestID)
}

// ruleSetOf builds a rule set of empty-snapshot engines over private
// in-memory counters — the shape BuildRuleSet produces for the stub CRD.
func ruleSetOf(t *testing.T, domains ...string) *store.RuleSet {
	t.Helper()
	engines := make(map[string]*engine.Engine, len(domains))
	for _, d := range domains {
		snap, problems := compile.Compile(d, nil, nil)
		require.Empty(t, problems)
		engines[d] = engine.New(snap, memory.New())
	}
	return store.NewRuleSet(engines)
}

// onePerHourPolicy admits a single request per hour for the whole domain: the
// smallest fixture whose second check refuses.
func onePerHourPolicy() model.Policy {
	return model.Policy{Name: "one", Domain: "gateway.public", Blocks: []model.Block{{
		Name:  "b",
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
}

// ruleSetWith compiles the policies into a single-domain rule set over
// private in-memory counters.
// ruleSetWith compiles the policies into the shared test domain.
func ruleSetWith(t *testing.T, policies ...model.Policy) *store.RuleSet {
	t.Helper()
	const domain = "gateway.public"
	snap, problems := compile.Compile(domain, policies, nil)
	// Informational records — the domain-budget note among them — are fine;
	// only a blocking problem means a broken fixture.
	for _, p := range problems {
		require.False(t, p.Blocking, "blocking compile problem: %+v", p)
	}
	return store.NewRuleSet(map[string]*engine.Engine{domain: engine.New(snap, memory.New())})
}

func headerMap(resp *envoyratelimit.RateLimitResponse) map[string]string {
	out := map[string]string{}
	for _, h := range resp.GetResponseHeadersToAdd() {
		out[h.GetKey()] = h.GetValue()
	}
	return out
}

func TestShouldRateLimit_reportsTheStrictestRuleInHeaders(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Name: "quota", Domain: domain, Blocks: []model.Block{{
		Name:  "b",
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 100, Period: time.Minute}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	first, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)
	second, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)

	assert.Equal(t, "100", headerMap(first)["x-ratelimit-limit"])
	assert.Equal(t, "99", headerMap(first)["x-ratelimit-remaining"])
	assert.Equal(t, "98", headerMap(second)["x-ratelimit-remaining"])
	assert.NotContains(t, headerMap(first), "retry-after", "an admitted request carries no retry hint")
}

func TestShouldRateLimit_chargesHitsAddend(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, model.Policy{Name: "quota", Domain: domain,
		Blocks: []model.Block{{Name: "b", Rules: []model.Rule{{Name: "all",
			Rates: []model.Rate{{Requests: 100, Period: time.Minute}}}}}}}))
	log, _ := recordingLogger()

	req := request(domain, map[string]string{"path": "/api"})
	req.HitsAddend = 5
	resp, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "95", headerMap(resp)["x-ratelimit-remaining"])
}

func TestShouldRateLimit_extractsTheClientFromTheToken(t *testing.T) {
	// A per-client rule keys its bucket by the sub claim of the token
	// descriptor: two clients must not share a counter.
	const domain = "gateway.public"
	p := model.Policy{Name: "per-client", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "each", Counters: []string{model.KeyClient},
			Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	token := func(sub string) string {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
		return "h." + payload + ".s"
	}
	check := func(sub string) envoyratelimit.RateLimitResponse_Code {
		resp, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api", "token": token(sub)}))
		require.NoError(t, err)
		return resp.GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("alice"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("alice"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("bob"),
		"bob must not inherit alice's exhausted bucket")
}

func TestShouldRateLimit_acceptsPreExtractedKeys(t *testing.T) {
	// The direct-consumer form: an entry that is not path, method, token, or
	// request_id arrives as a ready identity key.
	const domain = "gateway.public"
	p := model.Policy{Name: "per-client", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "each", Counters: []string{model.KeyClient},
			Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	check := func(client string) envoyratelimit.RateLimitResponse_Code {
		resp, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"client": client}))
		require.NoError(t, err)
		return resp.GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("alice"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("alice"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("bob"))
}

func TestShouldRateLimit_matchesRoutesByMethod(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Name: "writes", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Target: model.Target{Routes: []model.Route{{
			Path:    model.PathMatch{Type: model.PathPrefix, Value: "/api/"},
			Methods: []string{"POST"},
		}}},
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	check := func(method string) envoyratelimit.RateLimitResponse_Code {
		resp, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api/x", "method": method}))
		require.NoError(t, err)
		return resp.GetOverallCode()
	}

	require.Equal(t, envoyratelimit.RateLimitResponse_OK, check("POST"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("POST"))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("GET"),
		"a GET is outside the POST-only target and stays unlimited")
}

func TestShouldRateLimit_budgetOverflowDeniesRegardlessOfFallback(t *testing.T) {
	// The pinned contract: ErrTooManyBuckets is a configuration violation, so
	// the answer is OVER_LIMIT — never a gRPC error that fail-open would wave
	// through.
	const domain = "gateway.public"
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	policies := make([]model.Policy, 0, 3)
	for pi := range 3 {
		rules := make([]model.Rule, 0, 16)
		for ri := range 16 {
			rates := make([]model.Rate, 0, len(periods))
			for _, pd := range periods {
				rates = append(rates, model.Rate{Requests: 100, Period: pd})
			}
			rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", ri), Rates: rates})
		}
		policies = append(policies, model.Policy{Name: fmt.Sprintf("p%d", pi), Domain: domain,
			Blocks: []model.Block{{Name: "b", Rules: rules}}})
	}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, policies...))
	log, logged := recordingLogger()

	resp, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(),
		request(domain, map[string]string{"path": "/any"}))

	require.NoError(t, err, "the budget violation is an answer, not an error")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	assert.Contains(t, logged(), "bucket budget")
}

// failingCounters refuses every store operation, standing in for an
// unreachable Redis.
type failingCounters struct{}

func (failingCounters) Decide(context.Context, []counters.Bucket, int64) ([]counters.Verdict, error) {
	return nil, errors.New("store is down")
}

func (failingCounters) Peek(context.Context, []counters.Bucket, int64) ([]counters.Verdict, error) {
	return nil, errors.New("store is down")
}

func (failingCounters) Reset(context.Context, []string) error {
	return errors.New("store is down")
}

func TestShouldRateLimit_storeErrorBecomesAGRPCError(t *testing.T) {
	// Envoy's failure_mode_deny is the one switch for fail-open versus
	// fail-closed, so a store outage must surface as a gRPC error — not as a
	// verdict the adapter invented on its own.
	const domain = "gateway.public"
	snap, problems := compile.Compile(domain, []model.Policy{onePerHourPolicy()}, nil)
	require.Empty(t, problems)
	ruleStore := store.New()
	ruleStore.Replace(store.NewRuleSet(map[string]*engine.Engine{
		domain: engine.New(snap, failingCounters{}),
	}))
	log, logged := recordingLogger()

	resp, err := NewServer(ruleStore, log).ShouldRateLimit(context.Background(),
		request(domain, map[string]string{"path": "/api"}))

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.NotContains(t, logged(), "store is down\n429", "the verdict is Envoy's to make")
}
