package rls

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	envoycommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
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

func TestShouldRateLimit_deniesTheSecondRequestInAWindow(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t, domain))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	first, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)
	second, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
	require.NoError(t, err)

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode())
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, second.GetOverallCode(),
		"Envoy turns OVER_LIMIT into 429 for the client")
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
