// Package m2m verifies the Kubernetes ServiceAccount tokens the platform's
// machine-to-machine clients send: it composes the platform's token verifier
// with a deadline on every request to the API server.
package m2m

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(own, &claims); err != nil {
		return nil, fmt.Errorf("read the issuer of the pod's ServiceAccount token: %w", err)
	}
	if claims.Issuer == "" {
		return nil, errors.New("the pod's ServiceAccount token carries no issuer")
	}

	client := &http.Client{Timeout: cfg.Timeout, Transport: bearer{base: cfg.Transport, cfg: cfg}}
	jwksURI, err := discover(ctx, client, claims.Issuer, cfg.Timeout)
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
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithIssuer(claims.Issuer),
		jwt.WithAudience(cfg.Audience),
	)
	return tokenverifier.NewVerifier(parser, keyFunc, tokenverifier.ValidateIssuedAt)
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
