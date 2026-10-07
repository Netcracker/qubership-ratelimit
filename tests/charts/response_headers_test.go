package charts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The service reads whether to send ratelimit-policy and ratelimit from
// RESPONSE_HEADERS_IETF, and an unset variable means on, so a misspelled name
// or a value path that does not resolve would leave responseHeaders.ietf:
// false without effect and every other test green. The chart renders the
// variable under that name, with the value it was given.
func TestServiceChart_handsTheIETFHeaderSwitchToTheService(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"the default is on", nil, "true"},
		{"false is handed over", []string{"--set", "responseHeaders.ietf=false"}, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := envOf(t, render(t, serviceChart, "biz", tc.args...), "RESPONSE_HEADERS_IETF")
			require.True(t, ok, "RESPONSE_HEADERS_IETF is not rendered")
			assert.Equal(t, tc.want, value)
		})
	}
}
