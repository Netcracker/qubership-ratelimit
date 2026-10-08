package management

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_refusesACallWithoutABearerToken(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]string{
		"no header at all":    "",
		"another scheme":      "Basic YWxpY2U6c2VjcmV0",
		"an empty credential": "Bearer ",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			if header != "" {
				request.Header.Set("Authorization", header)
			}
			recorder := h.send(t, request)

			requireError(t, recorder, http.StatusUnauthorized, CodeUnauthorized)
			require.Equal(t, "Bearer", recorder.Header().Get("WWW-Authenticate"),
				"a 401 says what credential to present")
		})
	}
}

// refusingVerifier refuses every token with err, the way the platform's
// verifier reports each class of a bad token.
type refusingVerifier struct{ err error }

func (v refusingVerifier) Verify(context.Context, string) (*jwt.Token, error) { return nil, v.err }

// Every refusal is 401, and the detail names the class of the refusal, never
// the token, in the body or in the log.
func TestIdentity_answersEachRefusalOfTheVerifierWith401(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		detail string
	}{
		{"malformed", fmt.Errorf("%w: token contains an invalid number of segments", jwt.ErrTokenMalformed), "not a well-formed JWT"},
		{"expired", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenExpired), "has expired"},
		{"not valid yet", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenNotValidYet), "not valid yet"},
		{"issued in the future", fmt.Errorf("%w: issued later", jwt.ErrTokenUsedBeforeIssued), "not valid yet"},
		{"another audience", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenInvalidAudience), "not issued for the audience"},
		{"another issuer", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenInvalidIssuer), "not issued by this cluster"},
		{"a bad signature", fmt.Errorf("%w: crypto/rsa: verification error", jwt.ErrTokenSignatureInvalid), "signature of the bearer token could not be verified"},
		{"a key the cluster does not hold", fmt.Errorf("%w: %w", jwt.ErrTokenUnverifiable, jwkset.ErrKeyNotFound), "signed with a key this cluster does not hold"},
		{"alg none", fmt.Errorf("%w: 'none' signature type is not allowed", jwt.ErrTokenUnverifiable), "signature of the bearer token could not be verified"},
		{"anything else", errors.New("boom"), "was not accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			log := &recordingLogger{}
			h.api.Log = log
			var verifier Verifier = refusingVerifier{err: tc.err}
			h.api.verifier.Store(&verifier)
			token := testToken(listedCaller)

			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			request.Header.Set("Authorization", "Bearer "+token)
			recorder := h.send(t, request)

			body := requireError(t, recorder, http.StatusUnauthorized, CodeUnauthorized)
			require.Contains(t, body.Message, tc.detail)
			require.NotContains(t, recorder.Body.String(), token)
			for _, line := range log.lines {
				require.NotContains(t, line.message, token)
			}
		})
	}
}

// A token the verifier accepts is still refused when it is not a ServiceAccount
// token: the identity provider's tokens carry no kubernetes.io claim, and a
// token without a subject names nobody to audit.
func TestIdentity_refusesAVerifiedTokenThatIsNotAServiceAccounts(t *testing.T) {
	h := newTestAPI(t)

	for name, token := range map[string]string{
		"an identity provider's token": tokenWithClaims(map[string]any{
			"sub": "alice", "realm_access": map[string]any{"roles": []string{"operator"}}}),
		"no subject": tokenWithClaims(map[string]any{
			"kubernetes.io": map[string]any{"namespace": testNamespace}}),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			request.Header.Set("Authorization", "Bearer "+token)

			requireError(t, h.send(t, request), http.StatusUnauthorized, CodeUnauthorized)
		})
	}
}

// A listed caller holds operator, which subsumes viewer: it reads and mutates.
// A verified caller listed nowhere holds no role and is refused both.
func TestAuthorization_grantsOperatorToTheListedCallersAlone(t *testing.T) {
	h := newTestAPI(t)

	require.Equal(t, http.StatusOK, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code)
	require.Equal(t, http.StatusOK,
		h.reset(t, "ruleId=orders/per-client&axis.sub=alice", "key-1", listedCaller).Code)

	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", unlistedCaller, nil),
		http.StatusForbidden, CodeForbidden)
	requireError(t, h.reset(t, "ruleId=orders/per-client&axis.sub=alice", "key-2", unlistedCaller),
		http.StatusForbidden, CodeForbidden)
}

// Identity comes from exactly one place. A header the service trusted would be
// a header an attacker forges.
func TestIdentity_readsNoAuxiliaryIdentityHeader(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+testToken(unlistedCaller))
	request.Header.Set("X-Forwarded-User", listedCaller)
	request.Header.Set("X-Remote-Group", "operator")

	requireError(t, h.send(t, request), http.StatusForbidden, CodeForbidden)
}

// Until the verifier is built every call is refused with 503 under its own
// code, a token or not, and the API serves without a restart once the
// construction that kept failing succeeds.
func TestIdentity_refusesEveryCallUntilTheVerifierIsBuilt(t *testing.T) {
	first, longest := verifierRetryFirst, verifierRetryMax
	verifierRetryFirst, verifierRetryMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { verifierRetryFirst, verifierRetryMax = first, longest })

	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log
	h.api.verifier.Store(nil)
	var failures atomic.Int32
	release := make(chan struct{})
	h.api.NewVerifier = func(context.Context) (Verifier, error) {
		select {
		case <-release:
			return readingVerifier{}, nil
		default:
			failures.Add(1)
			return nil, errors.New("Get https://kubernetes.default.svc/.well-known/openid-configuration: refused, " +
				"possible reasons are:\n1. a base image without the CA\n2. no route to the API server")
		}
	}

	refused := h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil)
	requireError(t, refused, http.StatusServiceUnavailable, CodeVerifierUnavailable)
	require.Equal(t, "5", refused.Header().Get("Retry-After"))
	anonymous := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	requireError(t, h.send(t, anonymous), http.StatusServiceUnavailable, CodeVerifierUnavailable)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.api.StartBackground(ctx)
	require.Eventually(t, func() bool { return failures.Load() >= 3 }, 5*time.Second, time.Millisecond,
		"the construction is not retried")
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil),
		http.StatusServiceUnavailable, CodeVerifierUnavailable)

	close(release)
	require.Eventually(t, func() bool {
		return h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code == http.StatusOK
	}, 5*time.Second, 5*time.Millisecond, "the API does not serve once the verifier is built")

	// A builder error that spans lines is logged as one record.
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, line := range log.lines {
		require.NotContains(t, line.message, "\n", "a log record spans several lines")
	}
}

// The id lands in the log and the audit journal verbatim, so a value that
// could forge a record is refused, never sanitized, and the refusal is
// reported under a generated id rather than the offending one.
// TestApp_answersWithExactlyOneRequestID holds the log-safe value that
// round-trips.
func TestRequestID_refusesAValueThatCouldForgeALogRecord(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", listedCaller, nil, func(request *http.Request) {
		request.Header.Set(RequestIDHeader, "id\nlevel=error msg=\"forged\"")
	})

	requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	assert.Regexp(t, requestIDPattern, recorder.Header().Get(RequestIDHeader), "the id the refusal is reported under")
	assert.NotContains(t, recorder.Body.String(), "forged")
}

func TestLogSafe_dropsWhatCouldForgeARecord(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{name: "a newline", raw: "alice\nlevel=info", want: "alicelevel=info"},
		{name: "a carriage return, a tab, and a NUL", raw: "alice\r\t\x00", want: "alice"},
		{
			name: "a value over the length bound",
			raw:  strings.Repeat("x", 1000),
			want: strings.Repeat("x", maxLoggedValueLength),
		},
		{
			// A 63-byte namespace and a 253-byte name: the longest caller
			// subject reaches the audit line whole.
			name: "the longest caller subject",
			raw:  "system:serviceaccount:" + strings.Repeat("n", 63) + ":" + strings.Repeat("s", 253),
			want: "system:serviceaccount:" + strings.Repeat("n", 63) + ":" + strings.Repeat("s", 253),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, logSafe(tc.raw), "logSafe(%q)", tc.raw)
		})
	}
}
