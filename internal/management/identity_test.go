package management

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentity_refusesACallWithoutABearerToken(t *testing.T) {
	h := newTestAPI(t)

	cases := map[string]string{
		"no header at all":    "",
		"another scheme":      "Basic YWxpY2U6c2VjcmV0",
		"an empty credential": "Bearer ",
		"not a JWT at all":    "Bearer opaque-token",
		"a token with no sub": "Bearer header." + encodePayload(map[string]any{"roles": []string{"viewer"}}) + ".sig",
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

// Identity comes from exactly one place. A header the service trusted would be
// a header an attacker forges.
func TestIdentity_readsNoAuxiliaryIdentityHeader(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("X-Forwarded-User", "admin@example.com")
	request.Header.Set("X-Remote-Group", "operator")

	recorder := h.send(t, request)
	requireError(t, recorder, http.StatusUnauthorized, CodeUnauthorized)
}

func TestAuthorization_gatesMutationsOnTheOperatorRole(t *testing.T) {
	h := newTestAPI(t)

	// A viewer reads.
	require.Equal(t, http.StatusOK, h.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil).Code)

	// And is refused the mutation.
	requireError(t, h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-1", viewerRoles()),
		http.StatusForbidden, CodeForbidden)

	// An operator holds both: every mutation implies the right to read what it
	// mutates.
	require.Equal(t, http.StatusOK,
		h.call(t, http.MethodGet, BasePath+"/domains", operatorRoles(), nil).Code)
	require.Equal(t, http.StatusOK,
		h.reset(t, "ruleId=api/orders/per-client&axis.client=alice", "key-2", operatorRoles()).Code)
}

func TestAuthorization_refusesATokenWithoutRoles(t *testing.T) {
	h := newTestAPI(t)
	requireError(t, h.call(t, http.MethodGet, BasePath+"/domains", nil, nil),
		http.StatusForbidden, CodeForbidden)
}

func TestSubject_readsASingleRoleClaimAsWellAsAList(t *testing.T) {
	subject, err := subjectFromToken(
		"header."+encodePayload(map[string]any{"sub": "alice", "roles": "operator"})+".sig",
		DefaultClaimNames)
	require.NoError(t, err)
	require.Equal(t, "alice", subject.Name)
	require.Equal(t, []string{"operator"}, subject.Roles)
	require.True(t, subject.Can(RoleViewer))
}

func TestSubject_takesTheClaimNamesFromConfiguration(t *testing.T) {
	payload := encodePayload(map[string]any{
		"preferred_username": "alice", "groups": []string{"rl-operator"},
	})

	subject, err := subjectFromToken("header."+payload+".sig",
		ClaimNames{Subject: "preferred_username", Roles: "groups"})
	require.NoError(t, err)
	require.Equal(t, "alice", subject.Name)
	require.Equal(t, []string{"rl-operator"}, subject.Roles)
}

func TestRequestID_roundTripsALogSafeValueAndRefusesTheRest(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", viewerRoles()))
	request.Header.Set(RequestIDHeader, "trace-42")
	recorder := h.send(t, request)
	require.Equal(t, "trace-42", recorder.Header().Get(RequestIDHeader))

	// The id lands in the log and the audit journal verbatim, so a value that
	// could forge a record is refused, never sanitized — and the refusal is
	// reported under a generated id rather than the offending one.
	forged := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	forged.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", viewerRoles()))
	forged.Header.Set(RequestIDHeader, "id\nlevel=error msg=\"forged\"")
	forgedRecorder := h.send(t, forged)

	requireError(t, forgedRecorder, http.StatusBadRequest, CodeInvalidRequest)
	require.NotContains(t, forgedRecorder.Header().Get(RequestIDHeader), "\n")
	require.NotContains(t, forgedRecorder.Body.String(), "forged")
}

func TestRequestID_isGeneratedWhenTheCallerSendsNone(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil)
	require.NotEmpty(t, recorder.Header().Get(RequestIDHeader))
	require.Regexp(t, requestIDPattern, recorder.Header().Get(RequestIDHeader))
}

func TestLogSafe_dropsWhatCouldForgeARecord(t *testing.T) {
	require.Equal(t, "alicelevel=info", logSafe("alice\nlevel=info"))
	require.Equal(t, "alice", logSafe("alice\r\t\x00"))
	require.Len(t, logSafe(strings.Repeat("x", 1000)), maxLoggedValueLength)
}

func encodePayload(claims map[string]any) string {
	buf, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
