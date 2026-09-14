package management

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/stretchr/testify/require"
)

// The embedded document is the canonical specification, and a client is
// generated from it. Nothing in the service reads it at runtime, so a field
// renamed in Go and left alone here is invisible until a generated client
// fails to decode a response.
//
// Every answer of every test in this package goes through validateAgainstSpec,
// which is the cheapest place to catch that: the drift round 3 fixed by hand
// (`policies` still required, `NotExists` against a `DoesNotExist` payload, the
// old key tag) would have failed here.
//
// Route existence is not this validator's job — an unrouted path is skipped,
// because the tests deliberately call unknown paths to exercise the catch-all
// 404, and meta_test.go already holds route parity in both directions.
var specRouter = sync.OnceValues(func() (routers.Router, error) {
	loader := &openapi3.Loader{IsExternalRefsAllowed: false}
	document, err := loader.LoadFromData(specification)
	if err != nil {
		return nil, err
	}
	if err := document.Validate(context.Background()); err != nil {
		return nil, err
	}
	return gorillamux.NewRouter(document)
})

// validateAgainstSpec checks one answer against the document's schema for its
// route, status, and media type.
func validateAgainstSpec(t *testing.T, request *http.Request, code int, header http.Header, body []byte) {
	t.Helper()

	router, err := specRouter()
	require.NoError(t, err, "the embedded openapi.yaml does not load")

	route, pathParams, err := router.FindRoute(request)
	if err != nil {
		// An unrouted path, which the catch-all tests reach on purpose.
		return
	}

	// IncludeResponseStatus makes an undeclared status an error rather than a
	// pass: a handler that starts answering 409 where the document lists only
	// 200 and 404 is exactly the drift a generated client trips over.
	//
	// The body is checked only where it is JSON. The one endpoint that answers
	// something else serves this document itself, declared as a string; the
	// validator parses a YAML body into a value before it compares, so it reads
	// that as an object against `type: string`. There is no schema there to
	// drift from, and the status and the headers are still checked.
	options := &openapi3filter.Options{IncludeResponseStatus: true}
	if media, _, _ := strings.Cut(header.Get("Content-Type"), ";"); strings.TrimSpace(media) != "application/json" {
		options.ExcludeResponseBody = true
	}

	err = openapi3filter.ValidateResponse(request.Context(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    request,
			PathParams: pathParams,
			Route:      route,
		},
		Status:  code,
		Header:  header,
		Body:    io.NopCloser(bytes.NewReader(body)),
		Options: options,
	})
	require.NoError(t, err, "%s %s answered %d in a shape the document does not describe",
		request.Method, request.URL.Path, code)
}

// The document has to be loadable and internally consistent before it can judge
// anything, and a suite that never happened to call an endpoint would otherwise
// leave that unchecked.
func TestSpecification_loadsAndValidates(t *testing.T) {
	_, err := specRouter()
	require.NoError(t, err)
}
