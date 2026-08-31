package management

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Roles this API knows. They are canonical names: which IdP role maps onto
// which is deployment configuration, not a property of the service.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
)

// Subject is who is calling, as the bearer token describes them.
//
// The trust boundary is explicit and narrow: identity is read from exactly one
// place, the bearer token in Authorization, whose signature the gateway's auth
// extension has already checked. No auxiliary identity header is ever read, not
// X-Forwarded-User and not any other, because a header the service trusts is a
// header an attacker forges.
type Subject struct {
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

// ClaimNames says which claims carry the subject and its roles. IdPs disagree
// about both, so the names are configuration rather than a constant.
type ClaimNames struct {
	Subject string
	Roles   string
}

// DefaultClaimNames are the usual spellings.
var DefaultClaimNames = ClaimNames{Subject: "sub", Roles: "roles"}

// withIdentity reads the caller out of the bearer token and refuses the request
// without one.
//
// The signature is not checked here, deliberately: the gateway's auth extension
// has already validated it, and the mesh is required to keep this service's
// ingress to the gateway. That requirement is the security of the model: a
// deployment that cannot meet it has to validate signatures in the service
// instead. The 401 below is hygiene, not defense: it keeps an unauthenticated
// call from being processed, but it would not stop a forged token if the
// ingress requirement were broken.
func withIdentity(claims ClaimNames) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token, ok := bearerToken(c)
		if !ok {
			return errorf(CodeUnauthorized,
				"no bearer token on the request; call through the platform gateway")
		}
		subject, err := subjectFromToken(token, claims)
		if err != nil {
			// The token is unreadable rather than merely unsigned. The detail
			// never quotes the token: it is a live credential.
			return errorf(CodeUnauthorized,
				"the bearer token could not be read as a JWT payload")
		}
		if subject.Name == "" {
			return errorf(CodeUnauthorized,
				"the bearer token carries no "+claims.Subject+" claim to audit the call against")
		}
		c.Locals(localSubject, subject)
		return c.Next()
	}
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

// subjectFromToken decodes the JWT payload. The signature is the gateway's
// business; this only reads.
func subjectFromToken(token string, claims ClaimNames) (Subject, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Subject{}, errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Subject{}, errBadToken
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return Subject{}, errBadToken
	}

	subject := Subject{}
	if name, ok := body[claims.Subject].(string); ok {
		subject.Name = name
	}
	subject.Roles = stringsOf(body[claims.Roles])
	return subject, nil
}

// errBadToken is the one error subjectFromToken reports: what exactly was
// wrong with a credential is not something to tell the caller, and not
// something to log.
var errBadToken = errorf(CodeUnauthorized, "unreadable bearer token")

// stringsOf reads a claim that may be a single string or a list of them.
func stringsOf(claim any) []string {
	switch value := claim.(type) {
	case string:
		return []string{value}
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// bearerToken pulls the credential out of the Authorization header.
func bearerToken(c *fiber.Ctx) (string, bool) {
	header := c.Get(fiber.HeaderAuthorization)
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

// subjectOf returns the caller. Handlers run behind withIdentity, so the value
// is always present; the zero Subject is what a test bypassing the middleware
// sees, and it holds no role.
func subjectOf(c *fiber.Ctx) Subject {
	subject, _ := c.Locals(localSubject).(Subject)
	return subject
}
