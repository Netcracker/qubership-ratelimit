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

	envoycommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// rawToken is what the gateway puts in the token descriptor entry: a live
// credential that must never reach a log line.
const rawToken = "Bearer eyJhbGciOiJSUzI1NiJ9.super-secret-payload.signature"

// recorder is a Logger that keeps every line, and the context of the last
// one, so a test can read the messages and the value the [request_id=] field
// of the platform format would print.
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

func (r *recorder) DebugC(ctx context.Context, format string, args ...any) {
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

// testNamespace stands in for the component's own namespace, which is a
// segment of every counter key.
const testNamespace = "biz"

// ruleSetOver compiles a copy of p that names domain, and decides the domain
// over counterStore. A nil p binds the domain with no rules.
func ruleSetOver(t *testing.T, domain string, p *model.Policy, counterStore counters.Store) *store.RuleSet {
	t.Helper()
	if p != nil {
		bound := *p
		bound.Domain = domain
		p = &bound
	}
	snap, problems := compile.Compile(testNamespace, domain, p)
	require.Empty(t, problems, "compile.Compile(%q) of the test policy", domain)
	return store.NewRuleSet(map[string]store.Domain{
		domain: {Engine: engine.New(snap, counterStore), Snapshot: snap},
	})
}

// ruleSetWith binds p to gateway.public over in-memory counters.
func ruleSetWith(t *testing.T, p model.Policy) *store.RuleSet {
	t.Helper()
	return ruleSetOver(t, "gateway.public", &p, memory.New())
}

// newServerOver returns a Server deciding from rules, and the recorder it logs
// to. A nil rules binds no domain.
func newServerOver(rules *store.RuleSet, opts ...Option) (*Server, *recorder) {
	ruleStore := store.New()
	ruleStore.Replace(rules)
	log := &recorder{}
	return NewServer(ruleStore, log, opts...), log
}

// domainWidePolicy limits every check of its domain with one rule, b/all, of
// requests per period.
func domainWidePolicy(requests int64, period time.Duration) model.Policy {
	return model.Policy{Blocks: []model.Block{{
		Name:  "b",
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: requests, Period: period}}}},
	}}}
}

// perClientPerHourPolicy limits each value of the sub key with one rule,
// b/each, of requests per hour.
func perClientPerHourPolicy(requests int64) model.Policy {
	return model.Policy{Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "each", Counters: []string{model.KeySub},
			Rates: []model.Rate{{Requests: requests, Period: time.Hour}}}},
	}}}
}

// request builds a check of domain that carries one descriptor per entries
// map, in their order; with no map it carries no descriptor. The order of the
// entries within a descriptor is the map's, which the server does not depend
// on: it keys on the entry name.
func request(domain string, descriptors ...map[string]string) *envoyratelimit.RateLimitRequest {
	out := &envoyratelimit.RateLimitRequest{Domain: domain}
	for _, entries := range descriptors {
		descriptor := &envoycommon.RateLimitDescriptor{}
		for key, value := range entries {
			descriptor.Entries = append(descriptor.Entries, &envoycommon.RateLimitDescriptor_Entry{
				Key: key, Value: value,
			})
		}
		out.Descriptors = append(out.Descriptors, descriptor)
	}
	return out
}

// checkOfClients builds a check of gateway.public that carries n descriptors,
// each with a sub entry of its own client.
func checkOfClients(n int) *envoyratelimit.RateLimitRequest {
	descriptors := make([]map[string]string, 0, n)
	for i := range n {
		descriptors = append(descriptors, map[string]string{model.KeySub: fmt.Sprintf("client-%d", i)})
	}
	return request("gateway.public", descriptors...)
}

// tokenWithSub builds a token whose payload carries the sub claim, between
// placeholder header and signature segments.
func tokenWithSub(sub string) string {
	return "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+sub+`"}`)) + ".s"
}

// shouldRateLimit runs one check that returns a response, not an error.
func shouldRateLimit(
	t *testing.T, server *Server, req *envoyratelimit.RateLimitRequest,
) *envoyratelimit.RateLimitResponse {
	t.Helper()
	resp, err := server.ShouldRateLimit(context.Background(), req)
	require.NoError(t, err, "ShouldRateLimit(%v)", req)
	return resp
}

func headerMap(resp *envoyratelimit.RateLimitResponse) map[string]string {
	out := map[string]string{}
	for _, h := range resp.GetResponseHeadersToAdd() {
		out[h.GetKey()] = h.GetValue()
	}
	return out
}

func TestShouldRateLimit_admitsACheckOfADomainWithoutRules(t *testing.T) {
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))

	resp := shouldRateLimit(t, server,
		request("gateway.public", map[string]string{"path": "/api/v1/orders", "token": rawToken}))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
}

// A domain no policy claims has no limit to enforce, so its traffic passes;
// the log line and the metrics report the mismatch, not the verdict.
func TestShouldRateLimit_admitsACheckOfAnUnknownDomain(t *testing.T) {
	server, _ := newServerOver(nil)

	resp := shouldRateLimit(t, server, request("gateway.typo", map[string]string{"path": "/api/v1/orders"}))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
}

// A check of an unknown domain charges no counter, so repeating it never
// refuses: the policy mismatch is a configuration mistake on our side, not the
// caller's.
func TestShouldRateLimit_admitsEveryRepeatedCheckOfAnUnknownDomain(t *testing.T) {
	server, _ := newServerOver(nil)

	for i := range 3 {
		resp := shouldRateLimit(t, server, request("gateway.typo", nil))
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(), "check %d of gateway.typo", i+1)
	}
}

// A domain no policy claims means the gateway's filter config and the policies
// have drifted apart, and this log line is the only report that names the
// domain.
func TestShouldRateLimit_logsAnUnknownDomain(t *testing.T) {
	server, log := newServerOver(nil)

	shouldRateLimit(t, server, request("gateway.typo", nil))

	assert.Contains(t, log.output(), "unknown rate limit domain")
	assert.Contains(t, log.output(), "domain=gateway.typo")
}

// A check of a domain a policy claims writes no unknown-domain line.
// TestShouldRateLimit_logsAnUnknownDomain is the control, where the same check
// of a domain no policy claims writes it.
func TestShouldRateLimit_logsNoUnknownDomainLineForAClaimedDomain(t *testing.T) {
	server, log := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))

	shouldRateLimit(t, server, request("gateway.public", nil))

	assert.NotContains(t, log.output(), "unknown rate limit domain")
}

// The unknown domain is chosen by whoever calls the port, so it is logged the
// way the path is: without control characters, so that a newline in it cannot
// forge a second record.
func TestShouldRateLimit_stripsControlCharactersFromTheUnknownDomainItLogs(t *testing.T) {
	server, log := newServerOver(nil)

	shouldRateLimit(t, server, request(
		"gateway.typo\nINFO unknown rate limit domain: no RateLimitPolicy is bound to it domain=forged", nil))

	output := log.output()
	assert.Equal(t, 1, strings.Count(output, "\n"), "log lines in %q", output)
	assert.Contains(t, output, "domain=gateway.typoINFO unknown")
}

// The unknown domain is logged truncated, the way the path is, so its length
// cannot flood the log.
func TestShouldRateLimit_truncatesTheUnknownDomainItLogs(t *testing.T) {
	server, log := newServerOver(nil)

	shouldRateLimit(t, server, request("gateway."+strings.Repeat("x", 100_000), nil))

	assert.Less(t, len(log.output()), 2*maxLoggedValueLength+512,
		"length of the log of one check of a domain of 100008 bytes")
}

// The token entry is a live credential and stays out of every log line. The
// line still carries the domain and the path, so it was written.
func TestShouldRateLimit_leavesTheTokenOutOfTheLog(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules func(*testing.T) *store.RuleSet
	}{
		{"an unknown domain", func(*testing.T) *store.RuleSet { return nil }},
		{"a domain without rules", func(t *testing.T) *store.RuleSet {
			return ruleSetOver(t, "gateway.public", nil, memory.New())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, log := newServerOver(tc.rules(t))

			shouldRateLimit(t, server,
				request("gateway.public", map[string]string{"path": "/api/v1/orders", "token": rawToken}))

			output := log.output()
			assert.NotContains(t, output, rawToken)
			assert.NotContains(t, output, "super-secret-payload")
			assert.Contains(t, output, "domain=gateway.public")
			assert.Contains(t, output, "path=/api/v1/orders")
		})
	}
}

// One request per hour admits the first check and refuses the second, which
// Envoy turns into a 429, with a retry hint of the hour the window takes to
// admit again.
func TestShouldRateLimit_refusesACheckPastTheLimitWithARetryHint(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	first := shouldRateLimit(t, server, request("gateway.public", nil))
	require.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first check of one per hour")

	second := shouldRateLimit(t, server, request("gateway.public", nil))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, second.GetOverallCode())
	headers := headerMap(second)
	assert.Equal(t, "1", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "0", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.Equal(t, "3600", headers["retry-after"], "retry-after")
}

// A refusal leaves a log line that names the domain and the path.
func TestShouldRateLimit_logsARefusal(t *testing.T) {
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))

	shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))

	assert.Contains(t, log.output(), "rate limit refused domain=gateway.public path=/api")
}

// Envoy's :path carries the query, and a query routinely carries the very
// credential the service must not log.
func TestSanitizePath_redactsTheQueryString(t *testing.T) {
	assert.Equal(t, "/api/v1/orders?[redacted]",
		sanitizePath("/api/v1/orders?access_token=SECRET&api_key=ALSO-SECRET"))
}

func TestSanitizePath_keepsAPathWithoutAQueryAsItIs(t *testing.T) {
	assert.Equal(t, "/api/v1/orders", sanitizePath("/api/v1/orders"))
}

// A newline in the path forges a second log record, so the logged path keeps
// no control character.
func TestSanitizePath_stripsControlCharacters(t *testing.T) {
	assert.Equal(t, "/apiINFO fake log line", sanitizePath("/api\r\nINFO fake log line"))
}

// A logged path keeps its first 256 bytes and marks the cut.
func TestSanitizePath_truncatesAPathPast256Bytes(t *testing.T) {
	assert.Equal(t, "/"+strings.Repeat("a", 255)+"[truncated]", sanitizePath("/"+strings.Repeat("a", 500)))
}

// A byte cut through a multi-byte rune leaves an invalid UTF-8 sequence, so a
// rune that crosses the cut at 256 bytes is dropped whole. An é is two bytes:
// 200 of them are cut between two runes, and a leading slash moves the cut
// into the middle of one.
func TestSanitizePath_truncatesOnARuneBoundary(t *testing.T) {
	for _, tc := range []struct{ name, path, want string }{
		{"a cut between two runes", strings.Repeat("é", 200), strings.Repeat("é", 128) + "[truncated]"},
		{"a cut inside a rune", "/" + strings.Repeat("é", 200), "/" + strings.Repeat("é", 127) + "[truncated]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizePath(tc.path))
		})
	}
}

func TestLoggableEntries_returnsNothingWithoutAPathOrARequestID(t *testing.T) {
	path, requestID := loggableEntries(request("gateway.public", map[string]string{"token": rawToken}))

	assert.Empty(t, path, "path")
	assert.Empty(t, requestID, "request id")
}

func TestLoggableEntries_returnsThePathAndTheRequestID(t *testing.T) {
	path, requestID := loggableEntries(request("gateway.public", map[string]string{
		"path":       "/api/v1/orders",
		"request_id": "abc-123",
		"token":      rawToken,
	}))

	assert.Equal(t, "/api/v1/orders", path, "path")
	assert.Equal(t, "abc-123", requestID, "request id")
}

// x-request-id may be set by the client, so it can carry a forged log record.
func TestLoggableEntries_stripsControlCharactersFromTheRequestID(t *testing.T) {
	_, requestID := loggableEntries(request("gateway.public", map[string]string{
		"request_id": "id\r\nINFO forged",
	}))

	assert.Equal(t, "idINFO forged", requestID)
}

// The request id reaches the [request_id=] field of the platform format, not
// the message body, so the line matches the format every other Qubership
// service emits. The provider registry of ctxmanager is global and has no way
// to unregister, so the tests that run after this one see the provider too.
func TestShouldRateLimit_putsTheRequestIDInTheLogContext(t *testing.T) {
	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})
	server, log := newServerOver(ruleSetOver(t, "gateway.public", nil, memory.New()))

	shouldRateLimit(t, server, request("gateway.public",
		map[string]string{"path": "/api/v1/orders", "request_id": "corr-42", "token": rawToken}))

	assert.Equal(t, "corr-42", log.requestIDField())
}

// An admission of 100 per minute leaves 99, and the bucket is full again one
// second later, rounded up from the 0.6 s one request takes to return.
func TestShouldRateLimit_anAdmissionCarriesTheXRateLimitHeaders(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))

	headers := headerMap(shouldRateLimit(t, server, request("gateway.public", nil)))

	assert.Equal(t, "100", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "99", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.Equal(t, "1", headers["x-ratelimit-reset"], "x-ratelimit-reset")
	assert.NotContains(t, headers, "retry-after", "an admission carries no retry hint")
}

func TestShouldRateLimit_aSecondAdmissionLowersTheRemainingCount(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
	shouldRateLimit(t, server, request("gateway.public", nil))

	second := shouldRateLimit(t, server, request("gateway.public", nil))

	assert.Equal(t, "98", headerMap(second)["x-ratelimit-remaining"], "x-ratelimit-remaining of 100 per minute")
}

// The request's hits_addend is the cost of every descriptor, and a
// descriptor's own hits_addend overrides it for that descriptor, as the
// protocol defines it. The descriptor's value used to be ignored, and a caller
// setting it was charged the request's cost, one by default.
func TestShouldRateLimit_chargesTheCostTheHitsAddendSets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		request    uint32
		descriptor *wrapperspb.UInt64Value
		remaining  string
	}{
		{"the descriptor's cost", 0, wrapperspb.UInt64(5), "95"},
		{"the descriptor's cost over the request's", 2, wrapperspb.UInt64(5), "95"},
		{"the request's cost without a descriptor cost", 7, nil, "93"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
			req := request("gateway.public", map[string]string{"path": "/api"})
			req.HitsAddend = tc.request
			req.Descriptors[0].HitsAddend = tc.descriptor

			resp := shouldRateLimit(t, server, req)

			assert.Equal(t, tc.remaining, headerMap(resp)["x-ratelimit-remaining"],
				"x-ratelimit-remaining of 100 per minute after a request cost of %d and a descriptor cost of %v",
				tc.request, tc.descriptor)
		})
	}
}

// zeroCostCheck builds a check of gateway.public whose request cost is 7 and
// whose one descriptor sets an explicit hits_addend of zero.
func zeroCostCheck() *envoyratelimit.RateLimitRequest {
	req := request("gateway.public", map[string]string{"path": "/api"})
	req.HitsAddend = 7
	req.Descriptors[0].HitsAddend = wrapperspb.UInt64(0)
	return req
}

// A descriptor whose hits_addend is an explicit zero is checked without
// charging, as the protocol's override reads: the field can be unset, so a zero
// is the caller's choice and not the default. After three such checks, two
// per minute still admit two checks of cost one. A zero used to be charged as
// one, under the name of the protocol default.
func TestShouldRateLimit_anExplicitZeroDescriptorCostChargesNothing(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(2, time.Minute)))
	for i := range 3 {
		resp := shouldRateLimit(t, server, zeroCostCheck())
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
			"zero-cost check %d of two per minute", i+1)
	}

	for i := range 2 {
		resp := shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
			"check %d of cost one after three zero-cost checks of two per minute", i+1)
	}
}

// A check of zero cost reads the bucket without charging it, so a spent bucket
// still refuses it.
func TestShouldRateLimit_refusesAZeroCostCheckOfASpentBucket(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(2, time.Minute)))
	for i := range 2 {
		resp := shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))
		require.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
			"check %d of cost one of two per minute", i+1)
	}

	resp := shouldRateLimit(t, server, zeroCostCheck())

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
}

// The bound on a descriptor cost is the number docs/limits.md documents: a
// cost of 1000000000 is decided like any other, and one more is refused as a
// protocol violation.
func TestShouldRateLimit_refusesADescriptorCostOnlyPastOneBillion(t *testing.T) {
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
	atTheBound := request("gateway.public", map[string]string{"path": "/api"})
	atTheBound.Descriptors[0].HitsAddend = wrapperspb.UInt64(1_000_000_000)
	pastTheBound := request("gateway.public", map[string]string{"path": "/api"})
	pastTheBound.Descriptors[0].HitsAddend = wrapperspb.UInt64(1_000_000_001)

	shouldRateLimit(t, server, atTheBound)
	assert.NotContains(t, log.output(), "over the limit of", "log after a descriptor cost of 1000000000")

	resp := shouldRateLimit(t, server, pastTheBound)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	assert.Contains(t, log.output(), "over the limit of 1000000000")
}

// invalidCosts lists the descriptor costs the engine cannot charge: a refill
// request, which would let a caller top up its own counters, and a cost past
// what Envoy itself sends. Each row sets its cost on a descriptor.
func invalidCosts() []struct {
	name string
	set  func(*envoycommon.RateLimitDescriptor)
} {
	return []struct {
		name string
		set  func(*envoycommon.RateLimitDescriptor)
	}{
		{"is_negative_hits", func(d *envoycommon.RateLimitDescriptor) {
			d.HitsAddend, d.IsNegativeHits = wrapperspb.UInt64(5), true
		}},
		{"a cost over the maximum", func(d *envoycommon.RateLimitDescriptor) {
			d.HitsAddend = wrapperspb.UInt64(maxHitsAddend + 1)
		}},
	}
}

// A descriptor cost the engine cannot charge is refused as a protocol
// violation: the response is OVER_LIMIT, not an error.
func TestShouldRateLimit_refusesADescriptorCostItCannotCharge(t *testing.T) {
	for _, tc := range invalidCosts() {
		t.Run(tc.name, func(t *testing.T) {
			server, log := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
			req := request("gateway.public", map[string]string{"path": "/api"})
			tc.set(req.Descriptors[0])

			resp := shouldRateLimit(t, server, req)

			assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
			assert.Contains(t, log.output(), "descriptor 0")
		})
	}
}

// A refused cost is refused before any decision, so it charges nothing: the
// check of cost one after it finds 99 of 100 per minute left.
func TestShouldRateLimit_aDescriptorCostItCannotChargeLeavesTheCounterUntouched(t *testing.T) {
	for _, tc := range invalidCosts() {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
			req := request("gateway.public", map[string]string{"path": "/api"})
			tc.set(req.Descriptors[0])
			shouldRateLimit(t, server, req)

			plain := shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))

			assert.Equal(t, "99", headerMap(plain)["x-ratelimit-remaining"], "x-ratelimit-remaining of 100 per minute")
		})
	}
}

// A per-client rule keys its bucket by the sub claim of the token entry, so
// two clients do not share a counter.
func TestShouldRateLimit_keysAPerClientRuleByTheSubClaimOfTheToken(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	check := func(sub string) envoyratelimit.RateLimitResponse_Code {
		return shouldRateLimit(t, server, request("gateway.public",
			map[string]string{"path": "/api", "token": tokenWithSub(sub)})).GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("alice"), "the first check of alice")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("alice"), "the second check of alice")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("bob"),
		"the first check of bob after alice's bucket is spent")
}

// The direct-consumer form: an entry that is not path, method, token, or
// request_id arrives as a ready identity key.
func TestShouldRateLimit_keysAPerClientRuleByAPreExtractedSubEntry(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	check := func(client string) envoyratelimit.RateLimitResponse_Code {
		return shouldRateLimit(t, server, request("gateway.public", map[string]string{"sub": client})).GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("alice"), "the first check of alice")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("alice"), "the second check of alice")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("bob"),
		"the first check of bob after alice's bucket is spent")
}

func TestShouldRateLimit_limitsOnlyTheMethodsItsRouteNames(t *testing.T) {
	p := model.Policy{Blocks: []model.Block{{
		Name: "b",
		Target: model.Target{Routes: []model.Route{{
			Path:    model.PathMatch{Type: model.PathPrefix, Value: "/api/"},
			Methods: []string{"POST"},
		}}},
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	server, _ := newServerOver(ruleSetWith(t, p))
	check := func(method string) envoyratelimit.RateLimitResponse_Code {
		return shouldRateLimit(t, server, request("gateway.public",
			map[string]string{"path": "/api/x", "method": method})).GetOverallCode()
	}

	require.Equal(t, envoyratelimit.RateLimitResponse_OK, check("POST"), "the first POST")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("POST"), "the second POST")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("GET"),
		"a GET of a POST-only route after the POST bucket is spent")
}

// shadowPolicy limits every check of its domain with one shadow rule, b/trial,
// of requests per period.
func shadowPolicy(requests int64, period time.Duration) model.Policy {
	return model.Policy{Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "trial", Behavior: model.BehaviorShadow,
			Rates: []model.Rate{{Requests: requests, Period: period}}}},
	}}}
}

// A shadow rule reports what it would refuse and never refuses.
func TestShouldRateLimit_admitsACheckOverAShadowRuleLimit(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, shadowPolicy(1, time.Hour)))

	for i := range 2 {
		resp := shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/api"}))
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
			"check %d of a shadow rule of one per hour", i+1)
	}
}

// rulesFillingTheBucketBudget returns 32 rules of four windows each, the 128
// buckets one decision may touch; each rule counts by keys.
func rulesFillingTheBucketBudget(keys ...string) []model.Rule {
	periods := []time.Duration{time.Minute, time.Hour, 30 * time.Second, 10 * time.Second}
	rules := make([]model.Rule, 0, 32)
	for ri := range 32 {
		rates := make([]model.Rate, 0, len(periods))
		for _, pd := range periods {
			rates = append(rates, model.Rate{Requests: 100, Period: pd})
		}
		rules = append(rules, model.Rule{Name: fmt.Sprintf("r%d", ri), Counters: keys, Rates: rates})
	}
	return rules
}

// ErrTooManyBuckets is a configuration violation, so the response is
// OVER_LIMIT, never a gRPC error that fail-open would admit.
//
// The compiler refuses a generation over the budget, so the oversized snapshot
// here is built by adding a block to a compiled one: the only way an adapter
// ever meets this error.
func TestShouldRateLimit_refusesADecisionOverTheBucketBudget(t *testing.T) {
	const domain = "gateway.public"
	atTheBudget := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b", Rules: rulesFillingTheBucketBudget(),
	}}}
	snap, problems := compile.Compile(testNamespace, domain, &atTheBudget)
	require.Empty(t, problems, "32 rules of four windows each are exactly the budget")
	smuggled := snap.Blocks[0]
	smuggled.Name, smuggled.Rules = "smuggled", smuggled.Rules[:1]
	snap.Blocks = append(snap.Blocks, smuggled)
	server, log := newServerOver(store.NewRuleSet(map[string]store.Domain{
		domain: {Engine: engine.New(snap, memory.New()), Snapshot: snap},
	}))

	resp := shouldRateLimit(t, server, request(domain, map[string]string{"path": "/any"}))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	assert.Contains(t, log.output(), "bucket budget")
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

// Envoy's failure_mode_deny is the one switch for fail-open versus
// fail-closed, so a store outage is a gRPC error and not a verdict the adapter
// makes up on its own.
func TestShouldRateLimit_returnsUnavailableWhenTheStoreFails(t *testing.T) {
	p := domainWidePolicy(1, time.Hour)
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", &p, failingCounters{}))

	resp, err := server.ShouldRateLimit(context.Background(),
		request("gateway.public", map[string]string{"path": "/api"}))

	assert.Equal(t, codes.Unavailable, status.Code(err), "status of the error %v", err)
	assert.Nil(t, resp)
}

// Each descriptor is its own decision. Merged into one request, two
// descriptors would give the rule a two-valued sub key, which no rule matches,
// and both clients would pass unlimited.
func TestShouldRateLimit_decidesEachDescriptorOnItsOwn(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	twoClients := func() *envoyratelimit.RateLimitRequest {
		return request("gateway.public", map[string]string{"sub": "alice"}, map[string]string{"sub": "bob"})
	}

	first := shouldRateLimit(t, server, twoClients())
	second := shouldRateLimit(t, server, twoClients())

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first check of alice and bob")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, second.GetOverallCode(),
		"the second check of alice and bob")
}

// One refused descriptor refuses the check, and the response carries the
// numbers of the refused decision: its retry hint, which the admitted one does
// not have.
func TestShouldRateLimit_refusesACheckWhenAnyDescriptorRefuses(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	first := shouldRateLimit(t, server, request("gateway.public", map[string]string{"sub": "alice"}))
	require.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first check of alice")

	mixed := shouldRateLimit(t, server,
		request("gateway.public", map[string]string{"sub": "alice"}, map[string]string{"sub": "bob"}))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, mixed.GetOverallCode())
	assert.Equal(t, "3600", headerMap(mixed)["retry-after"], "retry-after of a check of a spent alice and a fresh bob")
}

// A direct consumer that sends no descriptor at all still meets the
// domain-wide rules.
func TestShouldRateLimit_limitsACheckWithoutDescriptorsByTheDomainWideRule(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))

	first := shouldRateLimit(t, server, request("gateway.public"))
	second := shouldRateLimit(t, server, request("gateway.public"))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first bare check")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, second.GetOverallCode(), "the second bare check")
}

// The identity layer never emits an empty value, so an empty entry value means
// the key is absent, not a shared "" bucket: the per-client rule does not
// apply. TestShouldRateLimit_keysAPerClientRuleByAPreExtractedSubEntry is the
// control, where a second check of a non-empty sub is refused.
func TestShouldRateLimit_treatsAnEmptyDescriptorValueAsAnAbsentKey(t *testing.T) {
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))

	for i := range 3 {
		resp := shouldRateLimit(t, server, request("gateway.public", map[string]string{"sub": ""}))
		assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(), "check %d with an empty sub", i+1)
	}
}

// A check may carry 16 descriptors. One more is a protocol violation, refused
// with OVER_LIMIT and never with an error the fallback policy could admit. The
// first violation line in a one-second window reports no suppressed lines.
func TestShouldRateLimit_refusesACheckOnlyPast16Descriptors(t *testing.T) {
	atTheBound, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	resp := shouldRateLimit(t, atTheBound, checkOfClients(16))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(), "a check of 16 fresh clients")

	pastTheBound, log := newServerOver(ruleSetWith(t, perClientPerHourPolicy(1)))
	resp = shouldRateLimit(t, pastTheBound, checkOfClients(17))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode(), "a check of 17 fresh clients")
	assert.Contains(t, log.output(), "carries 17 descriptors, over the limit of 16")
	assert.Contains(t, log.output(), "suppressed=0")
}

// failAfterStore delegates to an in-memory store until its budget of Decide
// calls runs out, then refuses every Decide: a store that fails mid-check.
type failAfterStore struct {
	inner counters.Store
	limit int
	calls int
}

func (f *failAfterStore) Decide(ctx context.Context, buckets []counters.Bucket, cost int64) ([]counters.Verdict, error) {
	f.calls++
	if f.calls > f.limit {
		return nil, errors.New("store is down")
	}
	return f.inner.Decide(ctx, buckets, cost)
}

func (f *failAfterStore) Peek(ctx context.Context, buckets []counters.Bucket, cost int64) ([]counters.Verdict, error) {
	return f.inner.Peek(ctx, buckets, cost)
}

func (f *failAfterStore) Reset(ctx context.Context, keys []string) error {
	return f.inner.Reset(ctx, keys)
}

// One descriptor was already refused when the store failed on the next one.
// The verdict is known, so the check is refused with the refused decision's
// headers, and not turned into an error that fail-open would admit. The store
// serves the first two Decide calls, both alice's, and fails bob's.
func TestShouldRateLimit_refusesACheckWhenTheStoreFailsAfterADescriptorRefused(t *testing.T) {
	p := perClientPerHourPolicy(1)
	server, _ := newServerOver(ruleSetOver(t, "gateway.public", &p, &failAfterStore{inner: memory.New(), limit: 2}))
	first := shouldRateLimit(t, server, request("gateway.public", map[string]string{"sub": "alice"}))
	require.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first check of alice")

	resp := shouldRateLimit(t, server,
		request("gateway.public", map[string]string{"sub": "alice"}, map[string]string{"sub": "bob"}))

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	assert.Equal(t, "3600", headerMap(resp)["retry-after"], "retry-after of alice's refusal")
}

// exemptPrefix and exemptDomain stand in for what the service passes to
// WithExemptPath: the base path of its management API, and the domain of the
// gateway that routes to it.
const (
	exemptPrefix = "/ratelimit/v1"
	exemptDomain = "gateway.private"
)

// exemptDomainRules binds one request per hour on every path of exemptDomain,
// counted in counterStore: failingCounters for a store that is down, so that a
// check that is decided fails, or memory.New for one that counts.
func exemptDomainRules(t *testing.T, counterStore counters.Store) *store.RuleSet {
	t.Helper()
	p := domainWidePolicy(1, time.Hour)
	return ruleSetOver(t, exemptDomain, &p, counterStore)
}

// The exempt paths are the prefix and everything under it by whole segments,
// with or without a query string. The counter store of the domain is down, so
// only a check that is not decided returns OK.
func TestShouldRateLimit_admitsAnExemptPathWhileTheStoreIsDown(t *testing.T) {
	server, _ := newServerOver(exemptDomainRules(t, failingCounters{}),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))

	for _, tc := range []struct{ name, path string }{
		{"the prefix itself", "/ratelimit/v1"},
		{"one segment under the prefix", "/ratelimit/v1/status"},
		{"several segments under the prefix", "/ratelimit/v1/domains/gateway.public/rules"},
		{"a query string after the prefix", "/ratelimit/v1?limited=true"},
		{"a query string after a deeper path", "/ratelimit/v1/domains/gateway.public/counters?limited=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := server.ShouldRateLimit(context.Background(),
				request(exemptDomain, map[string]string{"path": tc.path, "method": "GET"}))

			require.NoError(t, err, "ShouldRateLimit(path=%q)", tc.path)
			assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
				"ShouldRateLimit(path=%q)", tc.path)
		})
	}
}

// A path that shares characters with the prefix, without lying under it by
// whole segments, is decided like any other path of the domain: with the
// counter store down the check fails.
func TestShouldRateLimit_decidesAPathOutsideTheExemptPrefix(t *testing.T) {
	server, _ := newServerOver(exemptDomainRules(t, failingCounters{}),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))

	for _, tc := range []struct{ name, path string }{
		{"a longer last segment", "/ratelimit/v10/status"},
		{"a suffix on the last segment", "/ratelimit/v1beta"},
		{"the parent of the prefix", "/ratelimit"},
		{"the prefix deeper in the path", "/api/ratelimit/v1/status"},
		{"the prefix in the query string", "/api?next=/ratelimit/v1/status"},
		{"an unrelated path", "/api/v1/orders"},
		{"an empty path", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.ShouldRateLimit(context.Background(),
				request(exemptDomain, map[string]string{"path": tc.path, "method": "GET"}))

			assert.Equal(t, codes.Unavailable, status.Code(err), "ShouldRateLimit(path=%q)", tc.path)
		})
	}
}

// The exemption holds in the domains WithExemptPath names and in no other: the
// same path in another domain leads to another backend, and is decided.
func TestShouldRateLimit_decidesAnExemptPathInAnotherDomain(t *testing.T) {
	const otherDomain = "gateway.public"
	p := domainWidePolicy(1, time.Hour)
	server, _ := newServerOver(ruleSetOver(t, otherDomain, &p, failingCounters{}),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))

	_, err := server.ShouldRateLimit(context.Background(),
		request(otherDomain, map[string]string{"path": "/ratelimit/v1/status"}))

	assert.Equal(t, codes.Unavailable, status.Code(err),
		"ShouldRateLimit(domain=%q, path=/ratelimit/v1/status)", otherDomain)
}

// A server exempts nothing unless WithExemptPath gives it both a prefix and a
// domain. An empty prefix in particular does not turn into every path.
func TestShouldRateLimit_exemptsNoPathWithoutAPrefixAndADomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"no option", nil},
		{"an empty prefix", []Option{WithExemptPath("", []string{exemptDomain})}},
		{"no domains", []Option{WithExemptPath(exemptPrefix, nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(exemptDomainRules(t, failingCounters{}), tc.opts...)

			_, err := server.ShouldRateLimit(context.Background(),
				request(exemptDomain, map[string]string{"path": "/ratelimit/v1/status"}))

			assert.Equal(t, codes.Unavailable, status.Code(err), "ShouldRateLimit(path=/ratelimit/v1/status)")
		})
	}
}

// An exempt check charges no counter. The domain admits one request per hour:
// two exempt checks leave that request for the first check of another path,
// and the second check of that path is refused.
func TestShouldRateLimit_anExemptCheckChargesNoCounter(t *testing.T) {
	server, _ := newServerOver(exemptDomainRules(t, memory.New()),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))
	check := func(path string) envoyratelimit.RateLimitResponse_Code {
		return shouldRateLimit(t, server, request(exemptDomain, map[string]string{"path": path})).GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("/ratelimit/v1/status"), "the first exempt check")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("/ratelimit/v1/status"), "the second exempt check")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("/api"), "the first check of /api")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("/api"), "the second check of /api")
}

// An exempt descriptor is dropped and the descriptor beside it is decided on
// its own: the second check is refused because the first one charged the one
// request per hour for /api.
func TestShouldRateLimit_decidesTheDescriptorBesideAnExemptOne(t *testing.T) {
	server, _ := newServerOver(exemptDomainRules(t, memory.New()),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))
	check := func() envoyratelimit.RateLimitResponse_Code {
		return shouldRateLimit(t, server, request(exemptDomain,
			map[string]string{"path": "/ratelimit/v1/status"}, map[string]string{"path": "/api"})).GetOverallCode()
	}

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check(), "the first check")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check(), "the second check")
}

// The bound on a check's cost covers the check as a whole: the costs of its
// descriptors add up to at most 1000000000, so spreading the largest cost over
// several descriptors does not multiply it. A check of the same two
// descriptors at cost one is the control.
func TestShouldRateLimit_refusesDescriptorCostsThatAddUpPastOneBillion(t *testing.T) {
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
	split := request("gateway.public", map[string]string{"path": "/a"}, map[string]string{"path": "/b"})
	split.Descriptors[0].HitsAddend = wrapperspb.UInt64(600_000_000)
	split.Descriptors[1].HitsAddend = wrapperspb.UInt64(600_000_000)

	resp := shouldRateLimit(t, server, split)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode(),
		"two descriptors of cost 600000000")
	assert.Contains(t, log.output(), "a total cost of 1200000000, over the limit of 1000000000")

	resp = shouldRateLimit(t, server,
		request("gateway.public", map[string]string{"path": "/a"}, map[string]string{"path": "/b"}))
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(), "two descriptors of cost one")
}

// A request-level hits_addend is the cost of each descriptor, so a request
// cost of 2000000000, past the bound, is refused the same way.
func TestShouldRateLimit_refusesARequestCostPastOneBillion(t *testing.T) {
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(100, time.Minute)))
	wide := request("gateway.public", map[string]string{"path": "/a"})
	wide.HitsAddend = 2_000_000_000

	resp := shouldRateLimit(t, server, wide)

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	assert.Contains(t, log.output(), "a total cost of 2000000000")
}
