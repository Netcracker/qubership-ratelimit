package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatch_exactComparesTheWholePath(t *testing.T) {
	matcher, err := Compile(Exact, "/api/v1/orders")
	require.NoError(t, err)

	_, ok := matcher.Match("/api/v1/orders")
	assert.True(t, ok)

	_, ok = matcher.Match("/api/v1/orders/1")
	assert.False(t, ok, "an exact match must not accept a longer path")
}

func TestMatch_prefixComparesTheLeadingBytes(t *testing.T) {
	matcher, err := Compile(Prefix, "/api/v1/order-management/")
	require.NoError(t, err)

	_, ok := matcher.Match("/api/v1/order-management/orders/1")
	assert.True(t, ok)

	_, ok = matcher.Match("/api/v1/other")
	assert.False(t, ok)
}

func TestMatch_templateCapturesOneSegmentPerPlaceholder(t *testing.T) {
	matcher, err := Compile(Template, "/api/v1/orders/{order_id}/items")
	require.NoError(t, err)
	assert.Equal(t, []string{"order_id"}, matcher.Names())

	captures, ok := matcher.Match("/api/v1/orders/42/items")
	require.True(t, ok)
	assert.Equal(t, map[string]string{"order_id": "42"}, captures)
}

func TestMatch_templateCoversThePathWhole(t *testing.T) {
	matcher, err := Compile(Template, "/api/v1/orders/{order_id}")
	require.NoError(t, err)

	_, ok := matcher.Match("/api/v1/orders/42/items")
	assert.False(t, ok, "a template must not accept a path with extra segments")

	_, ok = matcher.Match("/api/v1/orders")
	assert.False(t, ok, "a template must not accept a path with missing segments")
}

func TestMatch_templatePlaceholderRejectsAnEmptySegment(t *testing.T) {
	// A placeholder matches one non-empty segment, so //items must not capture an
	// empty order id and count it as a bucket of its own.
	matcher, err := Compile(Template, "/api/v1/orders/{order_id}/items")
	require.NoError(t, err)

	_, ok := matcher.Match("/api/v1/orders//items")
	assert.False(t, ok)
}

func TestMatch_templateLiteralsAreCaseSensitive(t *testing.T) {
	matcher, err := Compile(Template, "/api/v1/Orders/{order_id}")
	require.NoError(t, err)

	_, ok := matcher.Match("/api/v1/orders/42")
	assert.False(t, ok)
}

func TestCompile_templateRejectsARepeatedPlaceholder(t *testing.T) {
	// Two placeholders of one name would capture into one descriptor key, and the
	// second capture would silently win.
	_, err := Compile(Template, "/api/{id}/sub/{id}")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "repeats placeholder")
}

func TestCompile_rejectsAnEmptyValue(t *testing.T) {
	_, err := Compile(Prefix, "")

	require.Error(t, err)
}

func TestPathAxis_templateYieldsTheTemplate(t *testing.T) {
	// The axis is the template rather than the request path, which is what caps
	// the cardinality of a path axis at one bucket per route.
	matcher, err := Compile(Template, "/api/v1/orders/{order_id}")
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/orders/{order_id}", matcher.PathAxis("/api/v1/orders/42"))
}

func TestPathAxis_prefixYieldsTheRequestPath(t *testing.T) {
	matcher, err := Compile(Prefix, "/api/")
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/orders/42", matcher.PathAxis("/api/v1/orders/42"))
}
