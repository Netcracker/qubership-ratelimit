// Package m2m verifies the Kubernetes ServiceAccount tokens the platform's
// machine-to-machine clients send: it composes the platform's token verifier
// with a deadline on every request to the API server.
package m2m

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"
	"golang.org/x/time/rate"
)

// The rules of the platform's Kubernetes verifier, which a token is checked
// against here as well: a leeway on every time claim, the key set fetched
// again once a day and at most every five minutes for an unknown key.
const (
	leeway        = 30 * time.Second
	keySetRefresh = 24 * time.Hour
)

// unknownKeyRefresh is the least time between two refreshes of the key set
// for a key it does not hold. Tests shorten it.
var unknownKeyRefresh = 5 * time.Minute

// unknownKeyWait bounds how long a token signed with a key the key set does
// not hold waits for the refresh limiter before it is refused. The limiter
// allows one refresh per unknownKeyRefresh, and without the bound a request
// in the last minute of that window waits for it.
const unknownKeyWait = time.Second

// DefaultTimeout bounds one request to the API server: the OIDC discovery and
// each fetch of the key set.
const DefaultTimeout = 10 * time.Second

// Config is what NewVerifier needs from the pod.
type Config struct {
	// Audience is the audience a token has to be issued for.
	Audience string

	// Token returns the pod's own ServiceAccount token. Its issuer is the
	// issuer a caller's token has to carry, and it authenticates the requests
	// to the API server unless Anonymous is set. It is called on every
	// request, because the kubelet rotates the projected token.
	Token func() (string, error)

	// Anonymous sends the requests to the API server without the pod's token,
	// which a GKE cluster requires.
	Anonymous bool

	// Transport carries the requests to the API server; nil is a clone of
	// http.DefaultTransport, which trusts the system pool.
	Transport http.RoundTripper

	// Timeout bounds one request to the API server; zero is DefaultTimeout.
	Timeout time.Duration

	// Log receives a failed refresh of the key set, which runs in the
	// background after NewVerifier returns; nil discards it.
	Log func(format string, args ...any)
}

// NewVerifier builds a verifier of ServiceAccount tokens: the signature
// against the key set of the issuer's OIDC discovery, the issuer, the
// audience, the expiry, and the issue time, as the platform's own Kubernetes
// verifier checks them.
//
// It reads the discovery and the key set before it returns, and returns an
// error when either does not answer within the timeout, so a verifier it
// returns holds the cluster's keys, and a caller that retries always gets to
// retry. The key set is refreshed under ctx, which has to outlive the
// verifier: the refresh runs in the background until ctx ends.
func NewVerifier(ctx context.Context, cfg Config) (tokenverifier.Verifier, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Transport == nil {
		cfg.Transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	own, err := cfg.Token()
	if err != nil {
		return nil, fmt.Errorf("read the pod's ServiceAccount token: %w", err)
	}
	issuer, err := issuerOf(own)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: cfg.Timeout, Transport: bearer{base: cfg.Transport, cfg: cfg}}
	jwksURI, err := discover(ctx, client, issuer, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	failFirst := false
	keyFunc, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURI}, keyfunc.Override{
		Client:                    client,
		HTTPTimeout:               cfg.Timeout,
		NoErrorReturnFirstHTTPReq: &failFirst,
		RateLimitWaitMax:          unknownKeyWait,
		RefreshInterval:           keySetRefresh,
		RefreshUnknownKID:         rate.NewLimiter(rate.Every(unknownKeyRefresh), 1),
		RefreshErrorHandlerFunc: func(u string) func(context.Context, error) {
			return func(_ context.Context, err error) {
				if cfg.Log != nil {
					cfg.Log("refresh the key set at %s: %s", u, strings.Join(strings.Fields(err.Error()), " "))
				}
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("fetch the key set at %s: %w", jwksURI, err)
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingMethods),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(cfg.Audience),
	)
	return tokenverifier.NewVerifier(parser, heldKeys{keySource: keyFunc}, tokenverifier.ValidateIssuedAt)
}

// heldKeys is the key function the verifier looks keys up through. A token
// whose key id the cached key set does not hold is refused with
// [jwkset.ErrKeyNotFound] in its chain, whatever ended the lookup: past the
// first unknown key id in a refresh window the lookup waits on the refresh
// limiter, and the limiter's error does not wrap [jwkset.ErrKeyNotFound]. The
// verifier calls KeyfuncCtx alone; the other methods are the wrapped key
// function's.
type heldKeys struct {
	keySource
}

// keySource names the wrapped key function, so that heldKeys can embed it
// without a field that shadows its Keyfunc method.
type keySource = keyfunc.Keyfunc

// KeyfuncCtx implements [keyfunc.Keyfunc]; the verifier looks keys up through it.
func (k heldKeys) KeyfuncCtx(ctx context.Context) jwt.Keyfunc {
	lookup := k.keySource.KeyfuncCtx(ctx)
	return func(token *jwt.Token) (any, error) {
		key, err := lookup(token)
		return key, k.unknown(ctx, token, err)
	}
}

// unknown adds [jwkset.ErrKeyNotFound] to err when the token names a key id
// the cached key set does not hold. The set is read from memory; nothing is
// fetched.
func (k heldKeys) unknown(ctx context.Context, token *jwt.Token, err error) error {
	if err == nil || errors.Is(err, jwkset.ErrKeyNotFound) {
		return err
	}
	kid, ok := token.Header[jwkset.HeaderKID].(string)
	if !ok {
		return err
	}
	held, readErr := k.Storage().KeyReadAll(ctx)
	if readErr != nil {
		return err
	}
	for _, key := range held {
		if key.Marshal().KID == kid {
			return err
		}
	}
	return fmt.Errorf("%w: %w", jwkset.ErrKeyNotFound, err)
}

// signingMethods are the algorithms a caller's token may be signed with: the
// asymmetric ones an API server signs ServiceAccount tokens with, RSA or
// ECDSA. A token of any other, none or an HMAC among them, is refused before
// a key is looked up.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// issuerOf reads the iss claim of the pod's own token. The token is the
// kubelet's, read from the pod's volume, and only its issuer is taken: it
// names the discovery to read, and a caller's token is then checked against
// that issuer and the keys the discovery serves.
func issuerOf(own string) (string, error) {
	segments := strings.Split(own, ".")
	if len(segments) != 3 {
		return "", errors.New("the pod's ServiceAccount token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return "", fmt.Errorf("decode the pod's ServiceAccount token: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("read the claims of the pod's ServiceAccount token: %w", err)
	}
	if claims.Issuer == "" {
		return "", errors.New("the pod's ServiceAccount token carries no issuer")
	}
	return claims.Issuer, nil
}

// discover reads the URL of the key set from the issuer's OIDC discovery,
// with timeout on the request.
func discover(ctx context.Context, client *http.Client, issuer string, timeout time.Duration) (string, error) {
	discovery, err := oidc.GetProviderUrl(issuer)
	if err != nil {
		return "", fmt.Errorf("build the OIDC discovery URL of issuer %s: %w", issuer, err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	if err != nil {
		return "", fmt.Errorf("build the OIDC discovery request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery at %s: %w", discovery, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery at %s answered %s", discovery, response.Status)
	}
	var provider oidc.ProviderResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&provider); err != nil {
		return "", fmt.Errorf("decode the OIDC discovery at %s: %w", discovery, err)
	}
	if provider.JwksUri == "" {
		return "", fmt.Errorf("the OIDC discovery at %s names no jwks_uri", discovery)
	}
	return provider.JwksUri, nil
}

// bearer sends the pod's own token with every request to the API server, read
// afresh each time.
type bearer struct {
	base http.RoundTripper
	cfg  Config
}

// RoundTrip implements [http.RoundTripper].
func (b bearer) RoundTrip(request *http.Request) (*http.Response, error) {
	if !b.cfg.Anonymous {
		own, err := b.cfg.Token()
		if err != nil {
			return nil, fmt.Errorf("read the pod's ServiceAccount token: %w", err)
		}
		request = request.Clone(request.Context())
		request.Header.Set("Authorization", "Bearer "+own)
	}
	return b.base.RoundTrip(request)
}
