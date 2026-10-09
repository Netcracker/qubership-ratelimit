package management

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

	recorder := h.callWith(t, http.MethodGet, BasePath+"/domains", listedCaller, nil, func(request *http.Request) {
		request.Header.Set(RequestIDHeader, "trace-42")
	})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	assert.Equal(t, []string{"trace-42"}, recorder.Header().Values(RequestIDHeader))
}

func TestApp_generatesOneRequestIDWhenTheCallerSendsNone(t *testing.T) {
	h := newTestAPI(t)
	recorder := h.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil)

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
		listedCaller, nil), http.StatusNotFound, CodeNotFound)

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
		first.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code, "the app built first")
	assert.Equal(t, http.StatusOK,
		second.call(t, http.MethodGet, BasePath+"/domains", listedCaller, nil).Code, "the app built second")
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

// The refusal of an oversized body carries a request id like every other
// answer, in the header and in meta.requestId: the caller's own when it sent
// one, a fresh one otherwise. fasthttp refuses such a body while it reads it,
// before the middleware that sets the id runs, and the refusal used to carry
// none. The app serves a real listener here, since app.Test fails on such a
// request in the client half.
func TestApp_answersAnOversizedBodyWithARequestID(t *testing.T) {
	h := newTestAPI(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = h.app.Listener(listener) }()
	t.Cleanup(func() { _ = h.app.Shutdown() })
	path := BasePath + "/domains/" + testDomain + "/counter-resets"

	for name, sent := range map[string]string{"without an id": "", "with an id": "e2e-oversized-1"} {
		t.Run(name, func(t *testing.T) {
			// The headers alone: fasthttp refuses on the declared length, and
			// a client still writing the body would see the connection close
			// under it instead of the answer.
			conn, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			head := "POST " + path + " HTTP/1.1\r\nHost: management\r\n" +
				"Content-Type: application/json\r\n" +
				"Authorization: Bearer " + testToken(listedCaller) + "\r\n" +
				"Content-Length: " + strconv.Itoa(maxRequestBody+1) + "\r\n"
			if sent != "" {
				head += RequestIDHeader + ": " + sent + "\r\n"
			}
			_, err = conn.Write([]byte(head + "\r\n"))
			require.NoError(t, err)

			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			defer func() { _ = response.Body.Close() }()
			raw, err := io.ReadAll(response.Body)
			require.NoError(t, err)

			require.Equal(t, http.StatusBadRequest, response.StatusCode, "body: %s", raw)
			var body errorBody
			require.NoError(t, json.Unmarshal(raw, &body), "body: %s", raw)
			id := response.Header.Get(RequestIDHeader)
			assert.NotEmpty(t, id, "the %s header", RequestIDHeader)
			assert.Equal(t, id, body.Meta.RequestID, "meta.requestId")
			if sent != "" {
				assert.Equal(t, sent, id, "the id the caller sent")
			}
		})
	}
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
			requireError(t, h.bulk(t, rawJSON(tc.body), "key-1", listedCaller),
				http.StatusBadRequest, CodeInvalidRequest)
		})
	}

	t.Run("a trailing newline is accepted", func(t *testing.T) {
		h := newTestAPI(t)
		response := h.bulk(t, rawJSON(valid+"\n"), "key-1", listedCaller)
		assert.Equal(t, http.StatusOK, response.Code, "body: %s", response.Body.String())
	})
}
