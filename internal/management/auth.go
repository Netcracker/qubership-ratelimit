package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

// Subject is the authenticated caller, as the API server described it. It is
// what the audit records name, so an operator can answer "who reset that
// counter" from the log alone.
type Subject struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

// String renders the subject for a log line or an audit record.
func (s Subject) String() string {
	if s.Name == "" {
		return "unknown"
	}
	return s.Name
}

// Authenticator resolves a bearer token to the caller it belongs to. The bool
// separates a token the API server rejected, which is a 401, from an error
// reaching the API server at all, which is a 500 — answering 401 to an outage
// would tell an operator their credentials are wrong when they are not.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Subject, bool, error)
}

// Authorizer decides whether the caller may perform verb on path. The reason
// is the API server's explanation of a denial, for the log — a client is told
// that it was denied, never by which rule, since that describes the cluster's
// RBAC to someone who just failed to prove they may read it.
type Authorizer interface {
	Authorize(ctx context.Context, subject Subject, verb, path string) (bool, string, error)
}

// KubeAuth authenticates and authorizes against the Kubernetes API server:
// TokenReview to establish who the caller is, SubjectAccessReview to ask
// whether RBAC lets them do this.
//
// Delegating both is what keeps this API free of an account system of its own.
// A cluster already knows who its subjects are and already has a language for
// granting them things, so a UI, a pipeline, and an engineer at a terminal all
// present the same kind of credential and are granted access the same way.
//
// The operator needs create on tokenreviews and subjectaccessreviews, which is
// cluster-scoped; the chart's ClusterRole carries both.
type KubeAuth struct {
	tokens  authenticationclient.TokenReviewInterface
	access  authorizationclient.SubjectAccessReviewInterface
	subject *ttlCache[string, cachedSubject]
	verdict *ttlCache[string, cachedVerdict]
	ttl     AuthCacheTTL
}

// AuthCacheTTL bounds how long an authentication or authorization result is
// reused. The point is not throughput — this API is not on the data path — but
// a UI that polls: without a cache, one open dashboard turns every poll of
// every panel into two writes against the API server.
//
// A denial is cached far more briefly than an allow, so granting someone
// access takes effect while they are still watching. Revocation is the reverse
// and takes up to Subject to be felt, which is the price of the cache and the
// reason it is a minute rather than an hour.
type AuthCacheTTL struct {
	Subject time.Duration
	Allow   time.Duration
	Deny    time.Duration
}

// DefaultAuthCacheTTL matches the delegating authenticator the Kubernetes
// components use, with a shorter allow window: the calls cached here can lift
// a rate limit.
var DefaultAuthCacheTTL = AuthCacheTTL{
	Subject: time.Minute,
	Allow:   30 * time.Second,
	Deny:    10 * time.Second,
}

type cachedSubject struct {
	subject       Subject
	authenticated bool
}

type cachedVerdict struct {
	allowed bool
	reason  string
}

// NewKubeAuth builds the delegating authenticator and authorizer over the
// operator's own API server connection.
func NewKubeAuth(config *rest.Config, ttl AuthCacheTTL) (*KubeAuth, error) {
	authentication, err := authenticationclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create the authentication client: %w", err)
	}
	authorization, err := authorizationclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create the authorization client: %w", err)
	}
	if ttl.Subject <= 0 {
		ttl.Subject = DefaultAuthCacheTTL.Subject
	}
	if ttl.Allow <= 0 {
		ttl.Allow = DefaultAuthCacheTTL.Allow
	}
	if ttl.Deny <= 0 {
		ttl.Deny = DefaultAuthCacheTTL.Deny
	}
	return &KubeAuth{
		tokens:  authentication.TokenReviews(),
		access:  authorization.SubjectAccessReviews(),
		subject: newTTLCache[string, cachedSubject](maxAuthCacheEntries),
		verdict: newTTLCache[string, cachedVerdict](maxAuthCacheEntries),
		ttl:     ttl,
	}, nil
}

// Authenticate resolves the token through a TokenReview.
func (a *KubeAuth) Authenticate(ctx context.Context, token string) (Subject, bool, error) {
	// The cache is keyed by a digest, never by the token: this map outlives
	// the request, and a credential that need not be held in memory should not
	// be.
	digest := tokenDigest(token)
	if hit, ok := a.subject.get(digest); ok {
		return hit.subject, hit.authenticated, nil
	}

	review, err := a.tokens.Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil {
		return Subject{}, false, fmt.Errorf("create a token review: %w", err)
	}
	if review.Status.Error != "" && !review.Status.Authenticated {
		// A structured rejection, not a transport failure: the token is bad.
		a.subject.put(digest, cachedSubject{}, a.ttl.Deny)
		return Subject{}, false, nil
	}

	entry := cachedSubject{authenticated: review.Status.Authenticated}
	if entry.authenticated {
		user := review.Status.User
		entry.subject = Subject{
			Name:   user.Username,
			UID:    user.UID,
			Groups: user.Groups,
			Extra:  extraToMap(user.Extra),
		}
	}

	ttl := a.ttl.Subject
	if !entry.authenticated {
		ttl = a.ttl.Deny
	}
	a.subject.put(digest, entry, ttl)
	return entry.subject, entry.authenticated, nil
}

// Authorize asks RBAC through a SubjectAccessReview.
//
// The attributes are those of a non-resource URL, so access is granted with
// nonResourceURLs and an HTTP verb rather than by inventing a resource. That
// keeps a read-only grant expressible as get and a mutating one as post, which
// is the split this API already draws.
func (a *KubeAuth) Authorize(ctx context.Context, subject Subject, verb, path string) (bool, string, error) {
	cacheKey := subject.UID + "\x00" + subject.Name + "\x00" + verb + "\x00" + path
	if hit, ok := a.verdict.get(cacheKey); ok {
		return hit.allowed, hit.reason, nil
	}

	review, err := a.access.Create(ctx, &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   subject.Name,
			UID:    subject.UID,
			Groups: subject.Groups,
			Extra:  mapToExtra(subject.Extra),
			NonResourceAttributes: &authorizationv1.NonResourceAttributes{
				Path: path,
				Verb: verb,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, "", fmt.Errorf("create a subject access review: %w", err)
	}

	verdict := cachedVerdict{
		allowed: review.Status.Allowed && !review.Status.Denied,
		reason:  review.Status.Reason,
	}
	ttl := a.ttl.Deny
	if verdict.allowed {
		ttl = a.ttl.Allow
	}
	a.verdict.put(cacheKey, verdict, ttl)
	return verdict.allowed, verdict.reason, nil
}

// withAuth requires every request to carry a bearer token the cluster
// recognizes, and to be permitted by RBAC.
//
// There is no anonymous path through it and no unauthenticated endpoint beside
// it, health included: this listener exists only to serve calls that can
// change what is enforced, and the readiness probe answers on the probe port.
func withAuth(authn Authenticator, authz Authorizer, log logr.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			// The challenge tells a client what kind of credential to present,
			// which is the difference between a UI showing a login prompt and
			// one showing an opaque failure.
			w.Header().Set("WWW-Authenticate", `Bearer realm="ratelimit-management"`)
			writeProblem(w, r, http.StatusUnauthorized, CodeUnauthorized,
				"Send a Kubernetes bearer token in the Authorization header.")
			return
		}

		ctx := r.Context()
		subject, authenticated, err := authn.Authenticate(ctx, token)
		if err != nil {
			log.Error(err, "management authentication failed", "requestId", requestIDOf(r))
			internalError(w, r, "verify the credentials with the API server")
			return
		}
		if !authenticated {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ratelimit-management"`)
			writeProblem(w, r, http.StatusUnauthorized, CodeUnauthorized,
				"The API server did not recognize the token.")
			return
		}

		verb := strings.ToLower(r.Method)
		allowed, reason, err := authz.Authorize(ctx, subject, verb, r.URL.Path)
		if err != nil {
			log.Error(err, "management authorization failed",
				"subject", subject.Name, "requestId", requestIDOf(r))
			internalError(w, r, "check the permissions with the API server")
			return
		}
		if !allowed {
			// The reason names cluster RBAC, so it goes to the log rather than
			// to a caller who has just failed to prove who they are.
			log.Info("management request denied",
				"subject", subject.Name, "verb", verb, "path", r.URL.Path,
				"reason", reason, "requestId", requestIDOf(r))
			writeProblem(w, r, http.StatusForbidden, CodeForbidden,
				fmt.Sprintf("User %q may not %s this endpoint.", subject.Name, verb))
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, contextKeyUser, subject)))
	})
}

// subjectOf returns the authenticated caller. Handlers run behind withAuth, so
// the value is always present; the zero Subject is what a test that bypasses
// the middleware sees.
func subjectOf(r *http.Request) Subject {
	subject, _ := r.Context().Value(contextKeyUser).(Subject)
	return subject
}

// bearerToken pulls the credential out of the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// tokenDigest hashes a token for use as a cache key.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func extraToMap(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string][]string, len(extra))
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func mapToExtra(extra map[string][]string) map[string]authorizationv1.ExtraValue {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string]authorizationv1.ExtraValue, len(extra))
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// maxAuthCacheEntries bounds each auth cache. The subjects calling a
// management API are few, so the bound is a backstop against an attacker
// filling memory with rejected tokens rather than a working limit.
const maxAuthCacheEntries = 1024

// ttlCache is a small expiring map.
//
// Entries expire lazily, on read, so a value never outlives its TTL even
// though nothing sweeps in the background. When the bound is reached the cache
// drops everything expired and, failing that, empties itself: at this
// cardinality an eviction policy would cost more to maintain than the misses
// it saves, and losing the cache costs one extra API server round trip per
// caller.
type ttlCache[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]ttlEntry[V]
	max     int
	now     func() time.Time
}

type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

func newTTLCache[K comparable, V any](max int) *ttlCache[K, V] {
	return &ttlCache[K, V]{entries: make(map[K]ttlEntry[V]), max: max, now: time.Now}
}

func (c *ttlCache[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[k]
	if !ok {
		var zero V
		return zero, false
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, k)
		var zero V
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[K, V]) put(k K, v V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		now := c.now()
		for key, entry := range c.entries {
			if !now.Before(entry.expires) {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= c.max {
			clear(c.entries)
		}
	}
	c.entries[k] = ttlEntry[V]{value: v, expires: c.now().Add(ttl)}
}
