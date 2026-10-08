package rls

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// parseSFItem parses value as an RFC 9651 Item whose bare item is a String
// and whose parameters are all Integers, the one shape ratelimit-policy and
// ratelimit take here, and refuses anything else: a missing quote, a separator
// other than ";" and "=", a key outside the grammar, a value that is not an
// Integer, a repeated key, or trailing characters.
func parseSFItem(value string) (string, map[string]int64, error) {
	name, rest, err := parseSFString(value)
	if err != nil {
		return "", nil, err
	}
	params := map[string]int64{}
	for rest != "" {
		var key string
		var n int64
		if key, n, rest, err = parseSFIntegerParam(rest); err != nil {
			return "", nil, err
		}
		if _, repeated := params[key]; repeated {
			return "", nil, fmt.Errorf("parameter %s twice", key)
		}
		params[key] = n
	}
	return name, params, nil
}

// parseSFString reads the sf-string at the start of value and returns its
// content and what follows it.
func parseSFString(value string) (string, string, error) {
	if !strings.HasPrefix(value, `"`) {
		return "", "", errors.New("the item is not a String")
	}
	var name []byte
	for i := 1; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '"':
			return string(name), value[i+1:], nil
		case c == '\\':
			i++
			if i >= len(value) || value[i] != '"' && value[i] != '\\' {
				return "", "", errors.New("not a String escape")
			}
			c = value[i]
		case c < 0x20 || c > 0x7e:
			return "", "", fmt.Errorf("%q is not allowed in a String", c)
		}
		name = append(name, c)
	}
	return "", "", errors.New("the String is not closed")
}

// parseSFIntegerParam reads one parameter, ";" OWS key "=" sf-integer, at the
// start of value and returns it and what follows it.
func parseSFIntegerParam(value string) (string, int64, string, error) {
	rest, ok := strings.CutPrefix(value, ";")
	if !ok {
		return "", 0, "", fmt.Errorf("%q where a parameter's ; belongs", value[0])
	}
	rest = strings.TrimLeft(rest, " ")
	key, rest, ok := strings.Cut(rest, "=")
	if !ok || !sfKey.MatchString(key) {
		return "", 0, "", fmt.Errorf("%q is not a key with a value", key)
	}
	number := rest
	if end := strings.IndexByte(rest, ';'); end >= 0 {
		number, rest = rest[:end], rest[end:]
	} else {
		rest = ""
	}
	if !sfInteger.MatchString(number) {
		return "", 0, "", fmt.Errorf("the value of %s is not an Integer", key)
	}
	n, err := strconv.ParseInt(number, 10, 64)
	return key, n, rest, err
}

// sfKey and sfInteger are the RFC 9651 grammar of a parameter key and of an
// Integer.
var (
	sfKey     = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*$`)
	sfInteger = regexp.MustCompile(`^-?[0-9]{1,15}$`)
)

// sfField is a parsed structured-field Item of the shape parseSFItem reads.
type sfField struct {
	Name   string
	Params map[string]int64
}

// sfItem is parseSFItem for a value the test expects to be well formed. A
// value that is not reports the parse error and returns the zero sfField, so
// the comparison after it fails too.
func sfItem(t *testing.T, value string) sfField {
	t.Helper()
	name, params, err := parseSFItem(value)
	assert.NoError(t, err, "parseSFItem(%q)", value)
	return sfField{Name: name, Params: params}
}

// The parser refuses the slips it is there to catch in the headers.
func TestParseSFItem_refusesAValueOutsideTheGrammar(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a bare token", `api/exports;q=10;w=60`},
		{"an unclosed String", `"api/exports;q=10;w=60`},
		{"a comma before the parameters", `"api/exports",q=10`},
		{"a comma between the parameters", `"api/exports";q=10,w=60`},
		{"an uppercase key", `"api/exports";Q=10`},
		{"a decimal value", `"api/exports";q=1.5`},
		{"a String value", `"api/exports";q="10"`},
		{"a repeated key", `"api/exports";q=10;q=11`},
		{"an Integer of 16 digits", `"api/exports";q=1234567890123456`},
		{"a trailing space", `"api/exports";q=10 `},
		{"a trailing semicolon", `"api/exports";q=10;`},
		{"characters after the String", `"api/exports"x`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseSFItem(tc.value)

			assert.Error(t, err, "parseSFItem(%q)", tc.value)
		})
	}
}

// A space after a parameter's ";" is allowed, and an Integer may be negative.
func TestParseSFItem_readsAStringWithIntegerParameters(t *testing.T) {
	name, params, err := parseSFItem(`"api/exports";q=10; w=-60`)

	require.NoError(t, err)
	assert.Equal(t, "api/exports", name, "name")
	assert.Equal(t, map[string]int64{"q": 10, "w": -60}, params, "parameters")
}

// exportsPerHourServer returns a Server for gateway.public with one rule,
// api/exports-per-hour, that admits two requests per hour under GCRA on the
// paths under /api/.
func exportsPerHourServer(t *testing.T) *Server {
	t.Helper()
	server, _ := newServerOver(ruleSetWith(t, model.Policy{Blocks: []model.Block{{
		Name:   "api",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
		Rules: []model.Rule{{Name: "exports-per-hour",
			Rates: []model.Rate{{Requests: 2, Period: time.Hour}}}},
	}}}))
	return server
}

// checkExports runs a check of /api/exports with the request cost cost, where
// zero is the protocol default of one.
func checkExports(t *testing.T, server *Server, cost uint32) *envoyratelimit.RateLimitResponse {
	t.Helper()
	req := request("gateway.public", map[string]string{"path": "/api/exports"})
	req.HitsAddend = cost
	return shouldRateLimit(t, server, req)
}

// A response carries ratelimit-policy and ratelimit beside x-ratelimit-*,
// naming the strictest rule as block/rule: q and w are its window, r is
// x-ratelimit-remaining, and t the effective window, the time until one more
// request is admitted. Under GCRA at two per hour a request returns every
// 1800 s.
func TestShouldRateLimit_anAdmissionCarriesTheIETFFields(t *testing.T) {
	server := exportsPerHourServer(t)

	headers := headerMap(checkExports(t, server, 0))

	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"q": 2, "w": 3600}},
		sfItem(t, headers["ratelimit-policy"]), "ratelimit-policy")
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"r": 1, "t": 1800}},
		sfItem(t, headers["ratelimit"]), "ratelimit")
	assert.Equal(t, "2", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "1", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.NotContains(t, headers, "retry-after", "an admission carries no retry hint")
}

// The admission that spends two per hour carries a t of 1800 s, the time until
// one request returns, while x-ratelimit-reset counts to the empty bucket,
// 3600 s.
func TestShouldRateLimit_theLastAdmissionCarriesAnEffectiveWindowShorterThanTheReset(t *testing.T) {
	server := exportsPerHourServer(t)
	checkExports(t, server, 0)

	headers := headerMap(checkExports(t, server, 0))

	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"q": 2, "w": 3600}},
		sfItem(t, headers["ratelimit-policy"]), "ratelimit-policy")
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"r": 0, "t": 1800}},
		sfItem(t, headers["ratelimit"]), "ratelimit")
	assert.Equal(t, "2", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "0", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.Equal(t, "3600", headers["x-ratelimit-reset"], "x-ratelimit-reset")
}

// On a refusal of cost one, t is the 1800 s retry-after waits, no longer than
// it, while x-ratelimit-reset still counts to the empty bucket.
func TestShouldRateLimit_aRefusalCarriesAnEffectiveWindowOfItsRetryHint(t *testing.T) {
	server := exportsPerHourServer(t)
	checkExports(t, server, 0)
	checkExports(t, server, 0)

	resp := checkExports(t, server, 0)

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	headers := headerMap(resp)
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"q": 2, "w": 3600}},
		sfItem(t, headers["ratelimit-policy"]), "ratelimit-policy")
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"r": 0, "t": 1800}},
		sfItem(t, headers["ratelimit"]), "ratelimit")
	assert.Equal(t, "2", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "0", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.Equal(t, "3600", headers["x-ratelimit-reset"], "x-ratelimit-reset")
	assert.Equal(t, "1800", headers["retry-after"], "retry-after")
}

// A cost of three never fits two per hour, so no waiting cures the refusal: it
// carries no retry hint, and the window, which holds its whole capacity, sends
// no t.
func TestShouldRateLimit_aRefusalNoWaitingCuresCarriesNoEffectiveWindow(t *testing.T) {
	server := exportsPerHourServer(t)

	resp := checkExports(t, server, 3)

	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	headers := headerMap(resp)
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"q": 2, "w": 3600}},
		sfItem(t, headers["ratelimit-policy"]), "ratelimit-policy")
	assert.Equal(t, sfField{"api/exports-per-hour", map[string]int64{"r": 2}},
		sfItem(t, headers["ratelimit"]), "ratelimit")
	assert.Equal(t, "2", headers["x-ratelimit-limit"], "x-ratelimit-limit")
	assert.Equal(t, "2", headers["x-ratelimit-remaining"], "x-ratelimit-remaining")
	assert.NotContains(t, headers, "retry-after", "a refusal no waiting cures carries no retry hint")
}

func TestShouldRateLimit_aRequestOutsideEveryRuleCarriesNoRateLimitHeader(t *testing.T) {
	server := exportsPerHourServer(t)

	resp := shouldRateLimit(t, server, request("gateway.public", map[string]string{"path": "/other"}))

	assert.Empty(t, resp.GetResponseHeadersToAdd())
}

// headerKeys returns the names of the headers resp adds, sorted, one per
// header, so that a repeated header shows twice.
func headerKeys(resp *envoyratelimit.RateLimitResponse) []string {
	keys := make([]string, 0, len(resp.GetResponseHeadersToAdd()))
	for _, h := range resp.GetResponseHeadersToAdd() {
		keys = append(keys, h.GetKey())
	}
	slices.Sort(keys)
	return keys
}

// WithIETFHeaders(false) leaves the two structured fields out and keeps the
// rest: an admission carries x-ratelimit-*, and a refusal x-ratelimit-* and
// retry-after.
func TestShouldRateLimit_withoutTheIETFFieldsSendsTheXRateLimitHeaders(t *testing.T) {
	for _, tc := range []struct {
		name        string
		checkBefore int
		code        envoyratelimit.RateLimitResponse_Code
		headers     []string
	}{
		{"an admission", 0, envoyratelimit.RateLimitResponse_OK,
			[]string{"x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"}},
		{"a refusal", 1, envoyratelimit.RateLimitResponse_OVER_LIMIT,
			[]string{"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)), WithIETFHeaders(false))
			for range tc.checkBefore {
				shouldRateLimit(t, server, request("gateway.public", nil))
			}

			resp := shouldRateLimit(t, server, request("gateway.public", nil))

			require.Equal(t, tc.code, resp.GetOverallCode(), "check %d of one per hour", tc.checkBefore+1)
			assert.Equal(t, tc.headers, headerKeys(resp))
		})
	}
}
