package management

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
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

// fasthttp cuts an oversized body before any handler runs, so this is two
// facts: the limit is the one this package documents rather than fiber's 4 MiB
// default, and what the cut produces is answered as a bad request. Under the
// platform's default handler it would be RLS-0500, telling a client branching
// on codes that the server broke when its request was simply too large.
func TestApp_boundsTheRequestBodyAtItsOwnLimit(t *testing.T) {
	h := newTestAPI(t)
	require.Equal(t, maxRequestBody, h.app.Config().BodyLimit,
		"the guard in decodeJSON runs after the body is in memory; this is the limit")
}

func TestErrorHandler_answersAnOversizedBodyAsABadRequest(t *testing.T) {
	app := fiber.New(fiber.Config{ErrorHandler: managementErrorHandler()})
	app.Get("/", func(*fiber.Ctx) error { return fiber.ErrRequestEntityTooLarge })

	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()

	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), CodeInvalidRequest.Code)
	require.Contains(t, string(body), "larger than")
}

// The only acceptable end of a body is the end of the stream. Checking for a
// second well-formed JSON value catches {}{} alone: {}garbage ends in a syntax
// error and {}[] in a type error, and reading either as "nothing follows"
// accepts trailing data and runs the command. It matters most for the bulk
// reset, where the command is destructive.
func TestDecodeJSON_refusesAnythingAfterTheValue(t *testing.T) {
	h := newTestAPI(t)

	target := BasePath + "/domains/" + testDomain + "/counter-resets"
	post := func(t *testing.T, body, key string) *testResponse {
		t.Helper()
		return h.callWith(t, http.MethodPost, target, operatorRoles(), nil,
			func(request *http.Request) {
				request.Header.Set("Idempotency-Key", key)
				request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
				request.Body = io.NopCloser(strings.NewReader(body))
				request.ContentLength = int64(len(body))
			})
	}

	valid := `{"selector":{"ruleIds":["orders"]},"dryRun":true}`
	for name, body := range map[string]string{
		"trailing garbage":    valid + "garbage",
		"a trailing array":    valid + "[]",
		"a second object":     valid + valid,
		"a trailing NUL byte": valid + "\x00",
	} {
		t.Run(name, func(t *testing.T) {
			requireError(t, post(t, body, "key-"+strings.ReplaceAll(name, " ", "-")),
				http.StatusBadRequest, CodeInvalidRequest)
		})
	}

	// Whitespace is not data: a body written by a shell ends in a newline.
	require.Equal(t, http.StatusOK, post(t, valid+"\n", "key-newline").Code)
}
