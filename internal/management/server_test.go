package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The app is the platform's, and the platform brings middleware of its own —
// context propagation that already puts an X-Request-Id on the response, a
// security middleware, and an error handler for whatever a route did not
// answer. These tests pin what that adds up to at the edge.

// Propagation adds the header, this API has the last word on it. Two values
// would leave a client and an operator quoting different ids for one call.
func TestApp_answersWithExactlyOneRequestID(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, BasePath+"/domains", strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+testToken("alice@example.com", viewerRoles()))
	request.Header.Set(RequestIDHeader, "trace-42")

	recorder := h.send(t, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, []string{"trace-42"}, recorder.Header().Values(RequestIDHeader))
}

func TestApp_generatesOneRequestIDWhenTheCallerSendsNone(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil)

	values := recorder.Header().Values(RequestIDHeader)
	require.Len(t, values, 1)
	require.Regexp(t, requestIDPattern, values[0])
}

// A path outside the API is answered in the same envelope as everything else,
// not with the router's plain-text default.
func TestApp_answersAnUnknownPathInTheSameShape(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, "/nothing-here", strings.NewReader(""))
	body := requireError(t, h.send(t, request), http.StatusNotFound, CodeNotFound)
	require.NotEmpty(t, body.Meta.RequestID)
	require.Equal(t, "NC.TMFErrorResponse.v1.0", body.Type)
}

// The error catalog reaches the wire through the platform's TMF envelope, so a
// client parses the same body here as from any other service of the platform.
func TestApp_answersInTheTmfEnvelope(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/gateway.typo/rules",
		viewerRoles(), nil), http.StatusNotFound, CodeNotFound)

	require.Equal(t, "NC.TMFErrorResponse.v1.0", body.Type)
	require.Equal(t, "404", body.Status)
	require.NotEmpty(t, body.ID, "every instance carries its own id")
	require.Contains(t, body.Message, "gateway.typo")
}

func TestNewApp_isBuildableTwiceInOneProcess(t *testing.T) {
	// The security middleware is registered globally, once; a second app must
	// not trip over the registration the first one made.
	first := newTestAPI(t)
	second := newTestAPI(t)

	require.Equal(t, http.StatusOK,
		first.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil).Code)
	require.Equal(t, http.StatusOK,
		second.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil).Code)
}
