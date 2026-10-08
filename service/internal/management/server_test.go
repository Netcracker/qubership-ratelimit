package management

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The app is the platform's, and the platform brings middleware of its own:
// context propagation that already puts an X-Request-Id on the response, a
// security middleware, and an error handler for whatever a route did not
// answer. These tests pin what that adds up to at the edge.

// Propagation adds the header, this API has the last word on it. Two values
// would leave a client and an operator quoting different ids for one call.
func TestApp_answersWithExactlyOneRequestID(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil, func(request *http.Request) {
		request.Header.Set(RequestIDHeader, "trace-42")
	})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	assert.Equal(t, []string{"trace-42"}, recorder.Header().Values(RequestIDHeader))
}

func TestApp_generatesOneRequestIDWhenTheCallerSendsNone(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil)

	values := recorder.Header().Values(RequestIDHeader)
	require.Len(t, values, 1)
	assert.Regexp(t, requestIDPattern, values[0])
}

// A path outside the API is answered in the same envelope as everything else,
// not with the router's plain-text default.
func TestApp_answersAnUnknownPathInTheSameShape(t *testing.T) {
	h := newTestAPI(t)

	request := httptest.NewRequest(http.MethodGet, "/nothing-here", strings.NewReader(""))
	body := requireError(t, h.send(t, request), http.StatusNotFound, CodeNotFound)

	assert.Equal(t, "NC.TMFErrorResponse.v1.0", body.Type)
}

// The error catalog reaches the wire through the platform's TMF envelope, so a
// client parses the same body here as from any other service of the platform.
func TestApp_answersInTheTmfEnvelope(t *testing.T) {
	h := newTestAPI(t)

	body := requireError(t, h.call(t, http.MethodGet, BasePath+"/domains/gateway.typo/rules",
		viewerRoles(), nil), http.StatusNotFound, CodeNotFound)

	assert.Equal(t, "NC.TMFErrorResponse.v1.0", body.Type)
	assert.Equal(t, "404", body.Status)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, body.ID,
		"every instance carries its own id, a UUID")
	assert.Contains(t, body.Message, "gateway.typo")
}

// The security middleware is registered globally, once; a second app must not
// trip over the registration the first one made.
func TestNewApp_isBuildableTwiceInOneProcess(t *testing.T) {
	first := newTestAPI(t)
	second := newTestAPI(t)

	assert.Equal(t, http.StatusOK,
		first.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil).Code, "the app built first")
	assert.Equal(t, http.StatusOK,
		second.call(t, http.MethodGet, BasePath+"/domains", viewerRoles(), nil).Code, "the app built second")
}

// fasthttp cuts an oversized body before any handler runs, so this is two
// facts: the limit is the one this package documents rather than fiber's 4 MiB
// default, and what the cut produces is answered as a bad request, which
// TestErrorHandler_answersAnOversizedBodyAsABadRequest holds. Under the
// platform's default handler it would be RLS-0500, telling a client branching
// on codes that the server broke when its request was simply too large.
func TestApp_boundsTheRequestBodyAtItsOwnLimit(t *testing.T) {
	h := newTestAPI(t)
	assert.Equal(t, maxRequestBody, h.app.Config().BodyLimit,
		"the guard in decodeJSON runs after the body is in memory; this is the limit")
}

func TestErrorHandler_answersAnOversizedBodyAsABadRequest(t *testing.T) {
	app := fiber.New(fiber.Config{ErrorHandler: managementErrorHandler()})
	app.Get("/", func(*fiber.Ctx) error { return fiber.ErrRequestEntityTooLarge })

	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()

	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode, "body: %s", raw)
	var body errorBody
	require.NoError(t, json.Unmarshal(raw, &body), "body: %s", raw)
	assert.Equal(t, CodeInvalidRequest.Code, body.Code, "body: %s", raw)
}

// The only acceptable end of a body is the end of the stream. Checking for a
// second well-formed JSON value catches {}{} alone: {}garbage ends in a syntax
// error and {}[] in a type error, and reading either as "nothing follows"
// accepts trailing data and runs the command. It matters most for the bulk
// reset, where the command is destructive. Whitespace is not data: a body
// written by a shell ends in a newline.
func TestDecodeJSON_refusesAnythingAfterTheValue(t *testing.T) {
	const valid = `{"selector":{"ruleIds":["orders"]},"dryRun":true}`
	cases := []struct{ name, body string }{
		{name: "trailing garbage", body: valid + "garbage"},
		{name: "a trailing array", body: valid + "[]"},
		{name: "a second object", body: valid + valid},
		{name: "a trailing NUL byte", body: valid + "\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			requireError(t, h.bulk(t, rawJSON(tc.body), "key-1", operatorRoles()),
				http.StatusBadRequest, CodeInvalidRequest)
		})
	}

	t.Run("a trailing newline is accepted", func(t *testing.T) {
		h := newTestAPI(t)
		response := h.bulk(t, rawJSON(valid+"\n"), "key-1", operatorRoles())
		assert.Equal(t, http.StatusOK, response.Code, "body: %s", response.Body.String())
	})
}
