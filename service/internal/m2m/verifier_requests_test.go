package m2m

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The paths of the OIDC discovery and of the key set the cluster serves.
const (
	discoveryPath = "/.well-known/openid-configuration"
	keySetPath    = "/openid/v1/jwks"
)

// roundTripFunc is an [http.RoundTripper] made of a function: a Config.Transport
// that replaces some request the verifier sends to the API server.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements [http.RoundTripper].
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// authorizations is a Config.Transport that records the Authorization header of
// every request the verifier sends to the API server, by path, and passes the
// request on.
type authorizations struct {
	mu   sync.Mutex
	sent map[string][]string
}

// RoundTrip implements [http.RoundTripper].
func (a *authorizations) RoundTrip(request *http.Request) (*http.Response, error) {
	a.mu.Lock()
	if a.sent == nil {
		a.sent = map[string][]string{}
	}
	a.sent[request.URL.Path] = append(a.sent[request.URL.Path], request.Header.Get("Authorization"))
	a.mu.Unlock()
	return http.DefaultTransport.RoundTrip(request)
}

// byPath returns the headers recorded so far.
func (a *authorizations) byPath() map[string][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return maps.Clone(a.sent)
}

// The pod's token is read afresh for every request to the API server, because
// the kubelet rotates it: after the read that names the issuer, the discovery
// carries the second read and the key set the third.
func TestNewVerifier_readsThePodsTokenAfreshForEveryRequest(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	own, err := c.podToken()
	require.NoError(t, err)
	var reads atomic.Int32
	// Each read returns the pod's token with the number of the read appended,
	// so a request shows which read it carries.
	podToken := func() (string, error) { return own + strconv.Itoa(int(reads.Add(1))), nil }
	sent := &authorizations{}

	_, err = NewVerifier(ctx, Config{Audience: audience, Token: podToken, Transport: sent})

	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		discoveryPath: {"Bearer " + own + "2"},
		keySetPath:    {"Bearer " + own + "3"},
	}, sent.byPath())
}

// With Anonymous set, neither the discovery nor the fetch of the key set
// carries the pod's token. TestNewVerifier_readsThePodsTokenAfreshForEveryRequest
// holds the requests that carry it.
func TestNewVerifier_sendsNoTokenToTheAPIServerWhenAnonymous(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sent := &authorizations{}

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Anonymous: true, Transport: sent})

	require.NoError(t, err)
	assert.Equal(t, map[string][]string{discoveryPath: {""}, keySetPath: {""}}, sent.byPath())
}

// errNoPodToken is what reading a missing projected token returns.
var errNoPodToken = errors.New("open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory")

// A pod token that cannot be read fails the construction with the error of the
// read.
func TestNewVerifier_failsWithTheErrorOfAPodTokenItCannotRead(t *testing.T) {
	_, err := NewVerifier(context.Background(), Config{Audience: audience,
		Token: func() (string, error) { return "", errNoPodToken }})

	assert.ErrorIs(t, err, errNoPodToken)
}

// A pod token that cannot be read for a request to the API server fails the
// request, and the construction with it, with the error of the read. Only the
// first read, which names the issuer, succeeds here.
func TestNewVerifier_failsWhenThePodTokenCannotBeReadForARequest(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var reads atomic.Int32
	podToken := func() (string, error) {
		if reads.Add(1) == 1 {
			return c.podToken()
		}
		return "", errNoPodToken
	}

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: podToken})

	assert.ErrorIs(t, err, errNoPodToken)
}

// discoveryAnswering is a Config.Transport that answers the OIDC discovery with
// status and body, and passes every other request on to the cluster.
func discoveryAnswering(status int, body string) http.RoundTripper {
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != discoveryPath {
			return http.DefaultTransport.RoundTrip(request)
		}
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(status)
		_, _ = recorder.WriteString(body)
		return recorder.Result(), nil
	})
}

// A discovery that answers with a status other than 200 fails the
// construction, although its body names the key set, and the error names the
// discovery call.
func TestNewVerifier_failsOnADiscoveryThatAnswersAnError(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport := discoveryAnswering(http.StatusInternalServerError, `{"jwks_uri":"`+c.server.URL+keySetPath+`"}`)

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Transport: transport})

	assert.ErrorContains(t, err, "OIDC discovery at "+c.server.URL+discoveryPath)
}

// A discovery whose body is not JSON fails the construction with the error of
// the decoder.
func TestNewVerifier_failsOnADiscoveryThatIsNotJSON(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport := discoveryAnswering(http.StatusOK, "<html>sign in</html>")

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Transport: transport})

	var syntax *json.SyntaxError
	assert.ErrorAs(t, err, &syntax)
}

// A discovery that names no key set fails the construction, and the error
// names the discovery call.
func TestNewVerifier_failsOnADiscoveryThatNamesNoKeySet(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport := discoveryAnswering(http.StatusOK, `{"issuer":"`+c.server.URL+`"}`)

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Transport: transport})

	assert.ErrorContains(t, err, "OIDC discovery at "+c.server.URL+discoveryPath)
}

// A failed refresh of the key set reaches Config.Log as one line, whatever
// lines its error spans, with the URL of the key set. A token under a key id
// the set does not hold makes the verifier refresh the set.
func TestNewVerifier_logsAFailedRefreshOfTheKeySetOnOneLine(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var refusing atomic.Bool
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if refusing.Load() {
			return nil, errors.New("connection refused, possible reasons are:\n1. a NetworkPolicy\n2. no route")
		}
		return http.DefaultTransport.RoundTrip(request)
	})
	var mu sync.Mutex
	var logged []string
	log := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Transport: transport, Log: log})
	require.NoError(t, err)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	refusing.Store(true)

	_, err = verifier.Verify(ctx, c.token(t, stranger, "idp", nil))

	require.Error(t, err, "Verify of a token under a key id the key set does not hold")
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, logged, 1, "lines Config.Log received")
	assert.NotContains(t, logged[0], "\n")
	assert.Contains(t, logged[0], "refresh the key set at "+c.server.URL+keySetPath+": ")
	assert.Contains(t, logged[0], "possible reasons are: 1. a NetworkPolicy 2. no route")
}
