package m2m

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const audience = "netcracker"

// cluster stands in for the API server: an issuer whose OIDC discovery and key
// set the verifier reads, and the key that signs its ServiceAccount tokens.
type cluster struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	podAuth atomic.Value // the Authorization header of the last discovery request
	keysOut atomic.Bool  // the key set answers 503 while set
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	c := &cluster{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		c.podAuth.Store(r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": c.server.URL, "jwks_uri": c.server.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if c.keysOut.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "cluster", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	c.server = httptest.NewServer(mux)
	t.Cleanup(c.server.Close)
	return c
}

// podToken is the pod's own token: only its issuer is read, so it is unsigned.
func (c *cluster) podToken() (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": c.server.URL}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
}

// token signs claims over a ServiceAccount token's defaults with key under kid;
// a claim overridden with nil is left out.
func (c *cluster) token(t *testing.T, key *rsa.PrivateKey, kid string, override jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": c.server.URL, "aud": []string{audience}, "sub": "system:serviceaccount:biz:ui-backend",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{"namespace": "biz", "serviceaccount": map[string]any{"name": "ui-backend"}},
	}
	for name, value := range override {
		if value == nil {
			delete(claims, name)
			continue
		}
		claims[name] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// The verifier checks a token as the platform's Kubernetes verifier does:
// signature, issuer, audience, and expiry, each refused with the jwt sentinel
// the management API maps onto its 401 detail.
func TestNewVerifier_checksATokenAsThePlatformDoes(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)

	verified, err := verifier.Verify(ctx, c.token(t, c.key, "cluster", nil))
	require.NoError(t, err)
	subject, err := verified.Claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:biz:ui-backend", subject)

	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		{"expired", c.token(t, c.key, "cluster", jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}),
			jwt.ErrTokenExpired},
		{"another audience", c.token(t, c.key, "cluster", jwt.MapClaims{"aud": []string{"other"}}),
			jwt.ErrTokenInvalidAudience},
		{"another issuer", c.token(t, c.key, "cluster", jwt.MapClaims{"iss": "https://idp.example"}),
			jwt.ErrTokenInvalidIssuer},
		{"another key under the cluster's key id", c.token(t, stranger, "cluster", nil), jwt.ErrTokenSignatureInvalid},
		{"an unknown key id", c.token(t, stranger, "idp", nil), jwt.ErrTokenUnverifiable},
		{"no expiry", c.token(t, c.key, "cluster", jwt.MapClaims{"exp": nil}), jwt.ErrTokenRequiredClaimMissing},
		{"an HMAC signature under the cluster's key id", hmacToken(t, c), jwt.ErrTokenSignatureInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(ctx, tc.token)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// hmacToken is a token of the cluster's issuer and audience signed with HS256
// under the cluster's key id: an algorithm no API server signs with, which the
// verifier refuses before it looks a key up.
func hmacToken(t *testing.T, c *cluster) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": c.server.URL, "aud": []string{audience}, "sub": "system:serviceaccount:biz:ui-backend",
		"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	token.Header["kid"] = "cluster"
	signed, err := token.SignedString([]byte("a shared secret"))
	require.NoError(t, err)
	return signed
}

// The discovery is read with the pod's own token as the bearer, which the API
// server requires of it, and without one on GKE, which requires the opposite.
func TestNewVerifier_readsTheDiscoveryWithThePodsToken(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	own, err := c.podToken()
	require.NoError(t, err)

	_, err = NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)
	assert.Equal(t, "Bearer "+own, c.podAuth.Load())

	_, err = NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Anonymous: true})
	require.NoError(t, err)
	assert.Equal(t, "", c.podAuth.Load())
}

// A discovery that accepts the connection and never answers is given up after
// the timeout, so the caller's retry runs; the platform's own verifier waited
// on it for as long as the server held the response.
func TestNewVerifier_givesUpOnADiscoveryThatDoesNotAnswer(t *testing.T) {
	release := make(chan struct{})
	held := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(held.Close)
	t.Cleanup(func() { close(release) })
	podToken := func() (string, error) {
		return jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": held.URL}).
			SignedString(jwt.UnsafeAllowNoneSignatureType)
	}

	start := time.Now()
	_, err := NewVerifier(context.Background(),
		Config{Audience: audience, Token: podToken, Timeout: 100 * time.Millisecond})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC discovery")
	assert.Less(t, time.Since(start), 5*time.Second, "the discovery was waited on past its timeout")
}

// A pod token without an issuer names no discovery to read.
func TestNewVerifier_refusesAPodTokenWithoutAnIssuer(t *testing.T) {
	podToken := func() (string, error) {
		return jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "x"}).
			SignedString(jwt.UnsafeAllowNoneSignatureType)
	}
	_, err := NewVerifier(context.Background(), Config{Audience: audience, Token: podToken})
	assert.ErrorContains(t, err, "carries no issuer")
}

// A key set that does not answer fails the construction, so the caller keeps
// retrying and answers 503 meanwhile, rather than holding a verifier without
// keys that refuses every token with 401.
func TestNewVerifier_failsWhenTheKeySetDoesNotAnswer(t *testing.T) {
	c := newCluster(t)
	c.keysOut.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Timeout: time.Second})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch the key set")
}

// A token signed with a key the key set does not hold, such as the identity
// provider's, is refused without waiting out the refresh limiter: the first
// one refreshes the key set, and the next ones in the same window are refused
// within unknownKeyWait.
func TestNewVerifier_refusesAnUnknownKeyWithoutWaitingForTheRefresh(t *testing.T) {
	// A window short enough that the limiter's next refresh is within the
	// one minute it would otherwise wait for it.
	window := unknownKeyRefresh
	unknownKeyRefresh = 3 * time.Second
	t.Cleanup(func() { unknownKeyRefresh = window })
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for range 3 {
		start := time.Now()
		_, err := verifier.Verify(ctx, c.token(t, stranger, "idp", nil))
		assert.ErrorIs(t, err, jwt.ErrTokenUnverifiable)
		assert.Less(t, time.Since(start), unknownKeyWait+500*time.Millisecond,
			"an unknown key waited on the refresh limiter")
	}
}

// A pod token that is not a JWT names no issuer to read the discovery of.
func TestNewVerifier_refusesAPodTokenThatIsNotAJWT(t *testing.T) {
	for _, own := range []string{"opaque", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[]")) + ".c"} {
		_, err := NewVerifier(context.Background(), Config{Audience: audience,
			Token: func() (string, error) { return own, nil }})
		assert.ErrorContains(t, err, "the pod's ServiceAccount token", "pod token %q", own)
	}
}
