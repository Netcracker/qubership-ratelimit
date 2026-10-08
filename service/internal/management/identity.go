package management

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"
)

// Roles this API knows. Every caller listed in [API.Callers] holds operator;
// viewer is the role the read-only endpoints require, held through operator.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
)

// Subject is who is calling: the Kubernetes ServiceAccount the bearer token
// was issued to, as the verified token names it.
//
// Identity is read from exactly one place, the bearer token in Authorization,
// verified in this service. No header that names a user is read, not
// X-Forwarded-User and not any other: the caller keeps the record of which
// user asked.
type Subject struct {
	// Name is the token's sub claim, system:serviceaccount:<namespace>:<name>.
	Name  string
	Roles []string
}

// Can reports whether the subject holds the role. Operator subsumes viewer:
// every mutation this API offers implies the right to read what it mutates.
func (s Subject) Can(role string) bool {
	for _, held := range s.Roles {
		if held == role || held == RoleOperator {
			return true
		}
	}
	return false
}

// Verifier checks a bearer token's signature, issuer, audience, expiry, and
// issue time, and returns the parsed token.
type Verifier = tokenverifier.Verifier

// verifierRetryFirst and verifierRetryMax bound the wait between two attempts
// to build the verifier. Tests shorten them.
var (
	verifierRetryFirst = time.Second
	verifierRetryMax   = time.Minute
)

// buildVerifier calls NewVerifier until it succeeds or ctx ends, waiting
// twice as long after each failure, up to verifierRetryMax, and installs the
// verifier it gets. A failure is logged with the builder's error, which names
// the discovery call that failed and never a token.
func (a *API) buildVerifier(ctx context.Context) {
	if a.NewVerifier == nil {
		return
	}
	delay := verifierRetryFirst
	for {
		verifier, err := a.NewVerifier(ctx)
		if err == nil {
			a.verifier.Store(&verifier)
			a.Log.InfoC(ctx, "management API token verifier is ready")
			return
		}
		a.Log.ErrorC(ctx, "management API token verifier unavailable, retrying in %v: %v", delay, oneLine(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, verifierRetryMax)
	}
}

// withIdentity verifies the bearer token and sets the caller it names.
//
// Until the verifier exists every request is refused with
// CodeVerifierUnavailable, so a client can tell an API that cannot check
// tokens yet from a counter store that is down. A request without a bearer
// token, with a token the verifier refuses, or with a verified token that is
// not a Kubernetes ServiceAccount token is refused with CodeUnauthorized; the
// detail names the class of the refusal and never quotes the token, which is a
// live credential. A verified caller in Callers holds operator, and any other
// holds no role, which requireRole answers with CodeForbidden.
func (a *API) withIdentity() fiber.Handler {
	listed := make(map[string]bool, len(a.Callers))
	for _, caller := range a.Callers {
		listed[caller] = true
	}
	return func(c *fiber.Ctx) error {
		verifier := a.verifier.Load()
		if verifier == nil {
			return verifierUnavailable()
		}
		raw, ok := bearerToken(c)
		if !ok {
			return errorf(CodeUnauthorized,
				"no bearer token on the request; send a Kubernetes ServiceAccount token")
		}
		verified, err := (*verifier).Verify(c.UserContext(), raw)
		if err != nil {
			// The key id tells a key of another issuer from a key set the
			// service never fetched; the token itself is a live credential
			// and stays out.
			var kid any
			if verified != nil {
				kid = verified.Header["kid"]
			}
			a.Log.DebugC(c.UserContext(), "management API refused a bearer token kid=%v error=%v",
				logSafe(fmt.Sprint(kid)), oneLine(err))
			return errorf(CodeUnauthorized, refusal(err))
		}
		name, err := token.GetSubject(verified)
		if err != nil || name == "" || !token.IsKubernetesToken(verified) {
			return errorf(CodeUnauthorized,
				"the bearer token is not a Kubernetes ServiceAccount token")
		}
		subject := Subject{Name: name}
		if listed[name] {
			subject.Roles = []string{RoleOperator}
		}
		c.Locals(localSubject, subject)
		return c.Next()
	}
}

// refusal names the class of a token the verifier refused, in the words the
// 401 detail carries. The verifier's own error is not quoted: its text is the
// parser's and changes with the library.
func refusal(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "the bearer token is not a well-formed JWT"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "the bearer token has expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet), errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "the bearer token is not valid yet"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "the bearer token is not issued for the audience of this API"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "the bearer token was not issued by this cluster"
	case errors.Is(err, jwkset.ErrKeyNotFound):
		return "the bearer token is signed with a key this cluster does not hold"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenUnverifiable):
		return "the signature of the bearer token could not be verified"
	default:
		return "the bearer token was not accepted"
	}
}

// oneLine is err's text on one line: an error that wraps a library's
// multi-line explanation would otherwise split one log record into several,
// the later ones without a timestamp.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// requireRole gates one handler on a role.
//
// Authorization is by path and verb, which is the split the API already draws:
// every GET and the one simulation POST need viewer, every mutation needs
// operator.
func requireRole(role string, next fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		subject := subjectOf(c)
		if !subject.Can(role) {
			return errorf(CodeForbidden,
				"subject "+logSafe(subject.Name)+" lacks the "+role+" role for "+
					c.Method()+" "+logSafe(c.Path()))
		}
		return next(c)
	}
}

// bearerToken pulls the credential out of the Authorization header.
func bearerToken(c *fiber.Ctx) (string, bool) {
	header := c.Get(fiber.HeaderAuthorization)
	if header == "" {
		return "", false
	}
	scheme, raw, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	return raw, raw != ""
}

// subjectOf returns the caller. Handlers run behind withIdentity, so the value
// is always present; the zero Subject is what a test bypassing the middleware
// sees, and it holds no role.
func subjectOf(c *fiber.Ctx) Subject {
	subject, _ := c.Locals(localSubject).(Subject)
	return subject
}
