package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_refusesACallWithoutABearerToken(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]string{
		"no header at all":    "",
		"another scheme":      "Basic YWxpY2U6c2VjcmV0",
		"an empty credential": "Bearer ",
		"not a JWT at all":    "Bearer opaque-token",
		"a token with no sub": "Bearer " + tokenWithClaims(map[string]any{"roles": []string{"viewer"}}),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
			if header != "" {
				request.Header.Set("Authorization", header)
			}
			recorder := h.send(t, request)

			requireError(t, recorder, http.StatusUnauthorized, CodeUnauthorized)
			assert.Equal(t, "Bearer", recorder.Header().Get("WWW-Authenticate"),
				"a 401 says what credential to present")
		})
	}
}

// Identity comes from exactly one place. A header the service trusted would be
// a header an attacker forges.
func TestIdentity_readsNoAuxiliaryIdentityHeader(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("X-Forwarded-User", "admin@example.com")
	request.Header.Set("X-Remote-Group", "operator")

	requireError(t, h.send(t, request), http.StatusUnauthorized, CodeUnauthorized)
}

// A mutation needs the operator role: the same reset a viewer is refused runs
// for an operator.
func TestAuthorization_gatesTheResetOnTheOperatorRole(t *testing.T) {
	h := newTestAPI(t)

	operator := h.reset(t, addressAlice, "key-operator", operatorRoles())
	require.Equal(t, http.StatusOK, operator.Code, "the reset as an operator: %s", operator.Body.String())

	requireError(t, h.reset(t, addressAlice, "key-viewer", viewerRoles()), http.StatusForbidden, CodeForbidden)
}

// An operator holds both roles: every mutation implies the right to read what
// it mutates.
func TestAuthorization_letsTheOperatorRoleRead(t *testing.T) {
	h := newTestAPI(t)

	response := h.call(t, http.MethodGet, BasePath+"/domains", operatorRoles(), nil)
	assert.Equal(t, http.StatusOK, response.Code, "body: %s", response.Body.String())
}

func TestAuthorization_refusesATokenWithoutRoles(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", nil, nil),
		http.StatusForbidden, CodeForbidden)
}

func TestSubjectFromToken_readsARoleClaimGivenAsOneString(t *testing.T) {
	subject, err := subjectFromToken(tokenWithClaims(map[string]any{"sub": "alice", "roles": "operator"}),
		DefaultClaimNames, RoleMapping{})

	require.NoError(t, err)
	assert.Equal(t, "alice", subject.Name)
	assert.Equal(t, []string{"operator"}, subject.Roles)
	assert.True(t, subject.Can(RoleViewer), "Can(%q) of an operator", RoleViewer)
}

func TestSubjectFromToken_readsTheConfiguredClaimNames(t *testing.T) {
	token := tokenWithClaims(map[string]any{"preferred_username": "alice", "groups": []string{"rl-operator"}})

	subject, err := subjectFromToken(token, ClaimNames{Subject: "preferred_username", Roles: "groups"}, RoleMapping{})

	require.NoError(t, err)
	assert.Equal(t, "alice", subject.Name)
	assert.Equal(t, []string{"rl-operator"}, subject.Roles)
}

// The id lands in the log and the audit journal verbatim, so a value that
// could forge a record is refused, never sanitized, and the refusal is
// reported under a generated id rather than the offending one.
// TestApp_answersWithExactlyOneRequestID holds the log-safe value that
// round-trips.
func TestRequestID_refusesAValueThatCouldForgeALogRecord(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil, func(request *http.Request) {
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, logSafe(tc.raw), "logSafe(%q)", tc.raw)
		})
	}
}

// An IdP rarely issues "viewer" and "operator" verbatim. Without the mapping a
// deployment whose realm calls them ratelimit-operator gets 403 on every call,
// and nothing in the service can change that.
func TestRoleMapping_translatesTheRolesAnIdPIssues(t *testing.T) {
	mapping := RoleMapping{
		Viewer:   []string{"ratelimit-viewer", "sre"},
		Operator: []string{"ratelimit-operator"},
	}

	cases := []struct {
		name   string
		issued []string
		want   []string
	}{
		{name: "an operator role", issued: []string{"ratelimit-operator"}, want: []string{RoleOperator}},
		{name: "a viewer role", issued: []string{"sre"}, want: []string{RoleViewer}},
		{name: "both roles", issued: []string{"sre", "ratelimit-operator"}, want: []string{RoleViewer, RoleOperator}},
		// A role on neither list is dropped rather than passed through:
		// authorizing against a name nobody configured is how a role from
		// another system becomes a grant here. The canonical names are no
		// exception once a mapping exists.
		{name: "roles on neither list", issued: []string{"operator", "admin"}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.want, mapping.canonical(tc.issued), "canonical(%q)", tc.issued)
		})
	}
}

// A deployment whose IdP already issues the canonical names configures nothing.
func TestRoleMapping_withoutListsKeepsTheTokensRoles(t *testing.T) {
	assert.Equal(t, []string{RoleOperator, "unrelated"},
		RoleMapping{}.canonical([]string{RoleOperator, "unrelated"}))
}

// Keycloak issues realm roles under realm_access.roles. Reading only top-level
// claims would leave that deployment with no roles at all.
func TestSubjectFromToken_readsANestedRolesClaim(t *testing.T) {
	token := tokenWithClaims(map[string]any{
		"sub": "alice@example.com",
		"realm_access": map[string]any{
			"roles": []any{"ratelimit-operator", "offline_access"},
		},
	})

	subject, err := subjectFromToken(token,
		ClaimNames{Subject: "sub", Roles: "realm_access.roles"},
		RoleMapping{Operator: []string{"ratelimit-operator"}})

	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", subject.Name)
	assert.True(t, subject.Can(RoleOperator), "Can(%q) with roles %q", RoleOperator, subject.Roles)
}

// A dotted path that walks into something that is not an object yields no
// roles, rather than reaching for a claim of the same name one level up.
func TestSubjectFromToken_aPathThatDoesNotResolveGrantsNothing(t *testing.T) {
	token := tokenWithClaims(map[string]any{"sub": "alice", "roles": []any{"operator"}})

	subject, err := subjectFromToken(token,
		ClaimNames{Subject: "sub", Roles: "realm_access.roles"}, RoleMapping{})

	require.NoError(t, err)
	assert.Empty(t, subject.Roles)
	assert.False(t, subject.Can(RoleViewer), "Can(%q) with roles %q", RoleViewer, subject.Roles)
}

// An explicit mapping maps only the roles its lists name: the deployment chose
// to map no IdP role onto a role whose list is empty, which is not the same as
// leaving the mapping unset.
func TestRoleMapping_anExplicitMappingGrantsNothingThroughAnEmptyList(t *testing.T) {
	issued := []string{RoleOperator, RoleViewer}
	cases := []struct {
		name    string
		mapping RoleMapping
		want    []string
	}{
		{name: "both lists empty", mapping: RoleMapping{Explicit: true}, want: nil},
		{
			name:    "the operator list empty",
			mapping: RoleMapping{Viewer: []string{RoleViewer}, Explicit: true},
			want:    []string{RoleViewer},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.want, tc.mapping.canonical(issued), "canonical(%q)", issued)
		})
	}
}
