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
		{"malformed", fmt.Errorf("%w: token contains an invalid number of segments", jwt.ErrTokenMalformed),
			"not a well-formed JWT"},
		{"expired", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenExpired), "has expired"},
		{"not valid yet", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenNotValidYet), "not valid yet"},
		{"issued in the future", fmt.Errorf("%w: issued later", jwt.ErrTokenUsedBeforeIssued), "not valid yet"},
		{"another audience", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenInvalidAudience),
			"not issued for the audience"},
		{"another issuer", fmt.Errorf("token has invalid claims: %w", jwt.ErrTokenInvalidIssuer),
			"not issued by this cluster"},
		{"a bad signature", fmt.Errorf("%w: crypto/rsa: verification error", jwt.ErrTokenSignatureInvalid),
			"signature of the bearer token could not be verified"},
		{"a key the cluster does not hold", fmt.Errorf("%w: %w", jwt.ErrTokenUnverifiable, jwkset.ErrKeyNotFound),
			"signed with a key this cluster does not hold"},
		{"alg none", fmt.Errorf("%w: 'none' signature type is not allowed", jwt.ErrTokenUnverifiable),
			"signature of the bearer token could not be verified"},
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
			assert.Contains(t, body.Message, tc.detail, "the 401 detail for the verifier error %q", tc.err)
			assert.NotContains(t, recorder.Body.String(), token, "the 401 body")
			assert.NotContains(t, log.find(t, "management API refused a bearer token").message, token,
				"the log record of the refusal")
			log.mu.Lock()
			defer log.mu.Unlock()
			require.NotEmpty(t, log.lines, "log records of the refused call")
			for _, line := range log.lines {
				assert.NotContains(t, line.message, token, "a log record of the refused call")
			}
		})
	}
}

// A token the verifier accepts is still refused when it is not a ServiceAccount
// token: the identity provider's tokens carry no kubernetes.io claim, and a
// token without a subject, or with an empty one, names nobody to audit.
func TestIdentity_refusesAVerifiedTokenThatIsNotAServiceAccounts(t *testing.T) {
	h := newTestAPI(t)

	for name, token := range map[string]string{
		"an identity provider's token": tokenWithClaims(map[string]any{
			"sub": "alice", "realm_access": map[string]any{"roles": []string{"operator"}}}),
		"no subject": tokenWithClaims(map[string]any{
			"kubernetes.io": map[string]any{"namespace": testNamespace}}),
		"an empty subject": tokenWithClaims(map[string]any{
			"sub": "", "kubernetes.io": map[string]any{"namespace": testNamespace}}),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			request.Header.Set("Authorization", "Bearer "+token)

			requireError(t, h.send(t, request), http.StatusUnauthorized, CodeUnauthorized)
		})
	}
}

// A listed caller holds operator, which subsumes viewer: it reads and mutates.
// A verified caller listed nowhere holds no role, so the read and the reset a
// listed caller runs are refused to it.
func TestAuthorization_grantsOperatorToTheListedCallersAlone(t *testing.T) {
	t.Run("a read", func(t *testing.T) {
		h := newTestAPI(t)

		listed := h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil)
		require.Equal(t, http.StatusOK, listed.Code, "GET /domains as %s: %s", listedCaller, listed.Body.String())

		requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", unlistedCaller, nil),
			http.StatusForbidden, CodeForbidden)
	})

	t.Run("a reset", func(t *testing.T) {
		h := newTestAPI(t)

		listed := h.reset(t, addressAlice, "key-1", listedCaller)
		require.Equal(t, http.StatusOK, listed.Code, "the reset as %s: %s", listedCaller, listed.Body.String())

		requireError(t, h.reset(t, addressAlice, "key-2", unlistedCaller), http.StatusForbidden, CodeForbidden)
	})
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
// code and with a Retry-After, before the token is looked at: a call without
// one is refused the same way, not with 401.
func TestIdentity_refusesEveryCallWith503UntilTheVerifierIsBuilt(t *testing.T) {
	for name, header := range map[string]string{
		"a listed caller's token": "Bearer " + testToken(listedCaller),
		"no bearer token":         "",
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestAPI(t)
			h.api.verifier.Store(nil)

			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			if header != "" {
				request.Header.Set("Authorization", header)
			}
			recorder := h.send(t, request)

			requireError(t, recorder, http.StatusServiceUnavailable, CodeVerifierUnavailable)
			assert.Equal(t, "5", recorder.Header().Get("Retry-After"), "Retry-After of the 503")
		})
	}
}

// shortenVerifierRetry makes buildVerifier retry a failed construction within
// milliseconds for the rest of the test.
func shortenVerifierRetry(t *testing.T) {
	t.Helper()
	first, longest := verifierRetryFirst, verifierRetryMax
	verifierRetryFirst, verifierRetryMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { verifierRetryFirst, verifierRetryMax = first, longest })
}

// A construction of the verifier that keeps failing is retried, the calls in
// between are refused with 503, and the API serves without a restart once the
// construction succeeds.
func TestIdentity_servesOnceAFailingConstructionOfTheVerifierSucceeds(t *testing.T) {
	shortenVerifierRetry(t)
	h := newTestAPI(t)
	h.api.verifier.Store(nil)
	var failures atomic.Int32
	release := make(chan struct{})
	h.api.NewVerifier = func(context.Context) (Verifier, error) {
		select {
		case <-release:
			return readingVerifier{}, nil
		default:
			failures.Add(1)
			return nil, errors.New("Get https://kubernetes.default.svc/.well-known/openid-configuration: refused")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	h.api.StartBackground(ctx)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.GreaterOrEqual(c, failures.Load(), int32(3), "failed constructions of the verifier")
	}, 5*time.Second, time.Millisecond, "waiting for StartBackground to retry a failing construction")
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil),
		http.StatusServiceUnavailable, CodeVerifierUnavailable)

	close(release)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, http.StatusOK, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code,
			"GET /domains as %s", listedCaller)
	}, 5*time.Second, 5*time.Millisecond, "waiting for the API to serve once the construction succeeds")
}

// A failed construction of the verifier is logged as one record however many
// lines the builder's error spans, since every line after the first would
// reach the log without a timestamp.
func TestIdentity_logsAFailedConstructionOfTheVerifierOnOneLine(t *testing.T) {
	shortenVerifierRetry(t)
	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log
	h.api.verifier.Store(nil)
	var attempts atomic.Int32
	h.api.NewVerifier = func(context.Context) (Verifier, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("Get https://kubernetes.default.svc/.well-known/openid-configuration: refused, " +
				"possible reasons are:\n1. a base image without the CA\n2. no route to the API server")
		}
		return readingVerifier{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	h.api.StartBackground(ctx)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, http.StatusOK, h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code,
			"GET /domains as %s", listedCaller)
	}, 5*time.Second, 5*time.Millisecond, "waiting for the second construction of the verifier")

	line := log.find(t, "management API token verifier unavailable")
	assert.NotContains(t, line.message, "\n", "the log record of the failed construction")
	assert.Contains(t, line.message,
		"possible reasons are: 1. a base image without the CA 2. no route to the API server",
		"the log record of the failed construction")
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

// A verified token whose sub claim is not a string names no caller, even with
// the kubernetes.io claim of a ServiceAccount token, and is refused with 401
// like a token without a subject.
func TestIdentity_refusesATokenWhoseSubjectIsNotAString(t *testing.T) {
	h := newTestAPI(t)
	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+tokenWithClaims(map[string]any{
		"sub": 42, "kubernetes.io": map[string]any{"namespace": testNamespace}}))

	requireError(t, h.send(t, request), http.StatusUnauthorized, CodeUnauthorized)
}

// retryWaits returns the wait each failed construction of the verifier logged,
// in the order of the failures.
func retryWaits(log *recordingLogger) []string {
	const prefix = "management API token verifier unavailable, retrying in "

	log.mu.Lock()
	defer log.mu.Unlock()
	var out []string
	for _, line := range log.lines {
		if rest, found := strings.CutPrefix(line.message, prefix); found {
			wait, _, _ := strings.Cut(rest, ":")
			out = append(out, wait)
		}
	}
	return out
}

// A failed construction of the verifier is retried after a wait that doubles
// with each failure up to verifierRetryMax. The log line of each failure names
// its wait, and the runbook quotes those lines. With a first wait of 1ms and a
// cap of 4ms, five failures wait 1ms, 2ms, 4ms, 4ms, and 4ms.
func TestIdentity_doublesTheWaitBetweenConstructionsUpToTheCap(t *testing.T) {
	first, longest := verifierRetryFirst, verifierRetryMax
	verifierRetryFirst, verifierRetryMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { verifierRetryFirst, verifierRetryMax = first, longest })

	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log
	h.api.verifier.Store(nil)
	var constructions atomic.Int32
	h.api.NewVerifier = func(context.Context) (Verifier, error) {
		if constructions.Add(1) <= 5 {
			return nil, errors.New("OIDC discovery refused the connection")
		}
		return readingVerifier{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.api.StartBackground(ctx)
	require.Eventually(t, func() bool { return h.api.verifier.Load() != nil }, 5*time.Second, time.Millisecond,
		"waiting for StartBackground to build the verifier on the sixth construction")

	assert.Equal(t, []string{"1ms", "2ms", "4ms", "4ms", "4ms"}, retryWaits(log),
		"the waits the five failed constructions logged")
}

// The constructions of the verifier stop when their context ends during the
// wait between two of them: the runner's context ends when the process shuts
// down, and a wait can last verifierRetryMax. The first wait here is an hour,
// and the context ends while it runs, so only a wait that watches the context
// returns in time.
func TestIdentity_stopsConstructingTheVerifierWhenItsContextEndsDuringAWait(t *testing.T) {
	first := verifierRetryFirst
	verifierRetryFirst = time.Hour
	t.Cleanup(func() { verifierRetryFirst = first })

	h := newTestAPI(t)
	log := &recordingLogger{}
	h.api.Log = log
	h.api.verifier.Store(nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var constructions atomic.Int32
	h.api.NewVerifier = func(context.Context) (Verifier, error) {
		constructions.Add(1)
		return nil, errors.New("OIDC discovery refused the connection")
	}

	done := make(chan struct{})
	go func() {
		h.api.buildVerifier(ctx)
		close(done)
	}()
	require.Eventually(t, func() bool { return len(retryWaits(log)) == 1 }, 5*time.Second, time.Millisecond,
		"waiting for the failure line of the first construction")
	// buildVerifier writes the failure line right before its wait starts; the
	// pause puts the end of the context inside the wait.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("buildVerifier was still in its hour-long wait 5s after its context ended")
	}
	assert.Equal(t, int32(1), constructions.Load(), "constructions of the verifier")
}

// A caller's request id of 128 characters, the longest the pattern admits,
// runs through to the response unchanged.
func TestRequestID_roundTripsAnIDOfTheLongestLength(t *testing.T) {
	h := newTestAPI(t)
	id := strings.Repeat("a", 128)

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", listedCaller, nil, func(request *http.Request) {
		request.Header.Set(RequestIDHeader, id)
	})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	assert.Equal(t, []string{id}, recorder.Header().Values(RequestIDHeader))
}

// A request id of 129 characters is one over the longest the pattern admits,
// and is refused under the name of the header.
func TestRequestID_refusesAnIDOneCharacterOverTheLongestLength(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", listedCaller, nil, func(request *http.Request) {
		request.Header.Set(RequestIDHeader, strings.Repeat("a", 129))
	})

	body := requireError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	assert.Equal(t, []string{RequestIDHeader}, body.Meta.Fields)
}

// A recorded value is cut at maxLoggedValueLength bytes: a value of exactly the
// bound is kept whole, and a value one byte longer is cut to the bound.
// TestLogSafe_dropsWhatCouldForgeARecord holds a value far over it.
func TestLogSafe_cutsAValueAtTheLengthBound(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{
			name: "a value of exactly the bound",
			raw:  strings.Repeat("x", maxLoggedValueLength),
			want: strings.Repeat("x", maxLoggedValueLength),
		},
		{
			name: "a value one byte over the bound",
			raw:  strings.Repeat("x", maxLoggedValueLength+1),
			want: strings.Repeat("x", maxLoggedValueLength),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logSafe(tc.raw)
			assert.Equal(t, tc.want, got, "logSafe of a value of %d bytes returned %d bytes", len(tc.raw), len(got))
		})
	}
}
