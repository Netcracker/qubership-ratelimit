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

	"github.com/MicahParks/jwkset"
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

// token signs claims over a ServiceAccount token's defaults with key under kid,
// with RS256 as the API server does; a claim overridden with nil is left out.
func (c *cluster) token(t *testing.T, key *rsa.PrivateKey, kid string, override jwt.MapClaims) string {
	t.Helper()
	return c.signed(t, jwt.SigningMethodRS256, key, kid, override)
}

// signed signs claims over a ServiceAccount token's defaults with method and
// key under kid; a claim overridden with nil is left out.
func (c *cluster) signed(t *testing.T, method jwt.SigningMethod, key any, kid string,
	override jwt.MapClaims) string {
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
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// A token of the cluster passes every check of the platform's Kubernetes
// verifier, and its expiry is read with the platform's 30 s of leeway. It is
// the control of TestNewVerifier_refusesATokenThatFailsOneCheck, whose rows
// each differ from these in one claim or in the signature.
func TestNewVerifier_acceptsATokenOfTheCluster(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"the API server's defaults", c.token(t, c.key, "cluster", nil)},
		{"expired inside the leeway", c.token(t, c.key, "cluster",
			jwt.MapClaims{"exp": time.Now().Add(-15 * time.Second).Unix()})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verified, err := verifier.Verify(ctx, tc.token)
			require.NoError(t, err, "Verify of a token the cluster signed")
			subject, err := verified.Claims.GetSubject()
			require.NoError(t, err, "the sub claim of the verified token")
			assert.Equal(t, "system:serviceaccount:biz:ui-backend", subject, "the sub claim of the verified token")
		})
	}
}

// A token that fails one check of the platform's Kubernetes verifier, the
// signature, the issuer, the audience, or the expiry, is refused with the
// sentinel the management API maps onto its 401 detail.
func TestNewVerifier_refusesATokenThatFailsOneCheck(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)

	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		{"expired", c.token(t, c.key, "cluster", jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}),
			jwt.ErrTokenExpired},
		{"expired past the leeway", c.token(t, c.key, "cluster",
			jwt.MapClaims{"exp": time.Now().Add(-45 * time.Second).Unix()}), jwt.ErrTokenExpired},
		{"another audience", c.token(t, c.key, "cluster", jwt.MapClaims{"aud": []string{"other"}}),
			jwt.ErrTokenInvalidAudience},
		{"another issuer", c.token(t, c.key, "cluster", jwt.MapClaims{"iss": "https://idp.example"}),
			jwt.ErrTokenInvalidIssuer},
		{"another key under the cluster's key id", c.token(t, stranger, "cluster", nil), jwt.ErrTokenSignatureInvalid},
		{"an unknown key id", c.token(t, stranger, "idp", nil), jwkset.ErrKeyNotFound},
		{"no expiry", c.token(t, c.key, "cluster", jwt.MapClaims{"exp": nil}), jwt.ErrTokenRequiredClaimMissing},
		// HS256 is an algorithm no API server signs with, refused before a
		// key is looked up.
		{"an HMAC signature under the cluster's key id",
			c.signed(t, jwt.SigningMethodHS256, []byte("a shared secret"), "cluster", nil),
			jwt.ErrTokenSignatureInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(ctx, tc.token)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// The discovery is read with the pod's own token as the bearer, which the API
// server requires of it, and without one on GKE, which requires the opposite.
func TestNewVerifier_readsTheDiscoveryWithThePodsTokenUnlessAnonymous(t *testing.T) {
	t.Run("the pod's token by default", func(t *testing.T) {
		c := newCluster(t)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		own, err := c.podToken()
		require.NoError(t, err)

		_, err = NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})

		require.NoError(t, err)
		assert.Equal(t, "Bearer "+own, c.podAuth.Load(), "Authorization of the discovery request")
	})

	t.Run("no token when Anonymous is set", func(t *testing.T) {
		c := newCluster(t)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Anonymous: true})

		require.NoError(t, err)
		assert.Equal(t, "", c.podAuth.Load(), "Authorization of the discovery request")
	})
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

	built := make(chan error, 1)
	go func() {
		_, err := NewVerifier(context.Background(),
			Config{Audience: audience, Token: podToken, Timeout: 100 * time.Millisecond})
		built <- err
	}()

	select {
	case err := <-built:
		assert.ErrorIs(t, err, context.DeadlineExceeded, "NewVerifier with a 100ms timeout")
		assert.ErrorContains(t, err, "OIDC discovery", "NewVerifier with a 100ms timeout")
	case <-time.After(5 * time.Second):
		t.Fatal("NewVerifier with a 100ms timeout was still waiting on the discovery after 5s")
	}
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

// A key set that cannot be fetched, here one the API server answers with 503,
// fails the construction, so the caller keeps retrying and answers 503
// meanwhile, rather than holding a verifier without keys that refuses every
// token with 401.
func TestNewVerifier_failsWhenTheKeySetCannotBeFetched(t *testing.T) {
	c := newCluster(t)
	c.keysOut.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken, Timeout: time.Second})

	assert.ErrorContains(t, err, "fetch the key set", "NewVerifier with the key set answering 503")
}

// A token signed with a key the key set does not hold, such as the identity
// provider's, is refused without waiting out the refresh limiter: the first
// one refreshes the key set, and the next ones in the same window are refused
// at once.
func TestNewVerifier_refusesAnUnknownKeyWithoutWaitingForTheRefresh(t *testing.T) {
	// A 3 s window puts the limiter's next refresh well inside the minute
	// keyfunc waits for it by default, so a verifier that does not bound the
	// wait itself refuses the second token only after about 3 s.
	window := 3 * time.Second
	previous := unknownKeyRefresh
	unknownKeyRefresh = window
	t.Cleanup(func() { unknownKeyRefresh = previous })
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := c.token(t, stranger, "idp", nil)

	for attempt := 1; attempt <= 3; attempt++ {
		start := time.Now()
		_, err := verifier.Verify(ctx, token)
		elapsed := time.Since(start)

		assert.ErrorIs(t, err, jwt.ErrTokenUnverifiable, "Verify under an unknown key id, attempt %d", attempt)
		assert.Less(t, elapsed, window/2, "Verify under an unknown key id, attempt %d", attempt)
	}
}

// A pod token that is not a JWT names no issuer to read the discovery of.
func TestNewVerifier_refusesAPodTokenThatIsNotAJWT(t *testing.T) {
	for _, tc := range []struct {
		name string
		own  string
	}{
		{"one segment", "opaque"},
		{"a payload that is not base64url", "a.!!!.c"},
		{"a payload that is not a JSON object", "a." + base64.RawURLEncoding.EncodeToString([]byte("[]")) + ".c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(context.Background(), Config{Audience: audience,
				Token: func() (string, error) { return tc.own, nil }})
			assert.ErrorContains(t, err, "the pod's ServiceAccount token", "NewVerifier with pod token %q", tc.own)
		})
	}
}
