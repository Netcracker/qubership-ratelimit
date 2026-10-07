package rls

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
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

// sfItem is parseSFItem for a value the test expects to be well formed.
func sfItem(t *testing.T, value string) (string, map[string]int64) {
	t.Helper()
	name, params, err := parseSFItem(value)
	require.NoError(t, err, "%q is not a structured-field Item", value)
	return name, params
}

// The parser itself refuses the slips it is there to catch.
func TestParseSFItem_refusesWhatIsNotAStringWithIntegerParameters(t *testing.T) {
	for _, value := range []string{
		`api/exports;q=10;w=60`,
		`"api/exports;q=10;w=60`,
		`"api/exports",q=10`,
		`"api/exports";q=10,w=60`,
		`"api/exports";Q=10`,
		`"api/exports";q=1.5`,
		`"api/exports";q="10"`,
		`"api/exports";q=10;q=11`,
		`"api/exports";q=1234567890123456`,
		`"api/exports";q=10 `,
		`"api/exports";q=10;`,
		`"api/exports"x`,
	} {
		_, _, err := parseSFItem(value)
		assert.Error(t, err, "the parser accepted %s", value)
	}
	name, params := sfItem(t, `"api/exports";q=10; w=-60`)
	assert.Equal(t, "api/exports", name)
	assert.Equal(t, map[string]int64{"q": 10, "w": -60}, params)
}

// Every response that carries x-ratelimit-* also carries ratelimit-policy and
// ratelimit, naming the strictest rule as block/rule: q and w are its window,
// r is x-ratelimit-remaining, and t the effective window, the time until one
// more request is admitted. Under GCRA at two per hour that is 1800 s while
// x-ratelimit-reset counts to the empty bucket, 3600 s; on a refusal t is no
// longer than retry-after, and a window at its full capacity sends no t. A
// request outside every rule carries none of the six headers.
func TestShouldRateLimit_sendsTheIETFRateLimitFields(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name:   "api",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"}}}},
		Rules: []model.Rule{{Name: "exports-per-hour",
			Rates: []model.Rate{{Requests: 2, Period: time.Hour}}}},
	}}}
	newServer := func() *Server {
		ruleStore := store.New()
		ruleStore.Replace(ruleSetWith(t, p))
		log, _ := recordingLogger()
		return NewServer(ruleStore, log)
	}
	check := func(server *Server, path string, cost uint32) *envoyratelimit.RateLimitResponse {
		req := request(domain, map[string]string{"path": path})
		req.HitsAddend = cost
		resp, err := server.ShouldRateLimit(context.Background(), req)
		require.NoError(t, err)
		return resp
	}
	agrees := func(step string, resp *envoyratelimit.RateLimitResponse, window string) map[string]string {
		headers := headerMap(resp)
		name, policy := sfItem(t, headers["ratelimit-policy"])
		assert.Equal(t, "api/exports-per-hour", name, step)
		assert.Equal(t, map[string]int64{"q": 2, "w": 3600}, policy, step)
		name, quota := sfItem(t, headers["ratelimit"])
		assert.Equal(t, "api/exports-per-hour", name, step)
		assert.Equal(t, headers["x-ratelimit-limit"], fmt.Sprint(policy["q"]), step)
		assert.Equal(t, headers["x-ratelimit-remaining"], fmt.Sprint(quota["r"]), step)
		if window == "" {
			assert.Equal(t, map[string]int64{"r": quota["r"]}, quota, "%s: ratelimit carries r alone", step)
		} else {
			assert.Equal(t, window, fmt.Sprint(quota["t"]), step)
			assert.Len(t, quota, 2, "%s: ratelimit carries r and t alone", step)
		}
		return headers
	}

	server := newServer()
	admitted := agrees("admission", check(server, "/api/exports", 0), "1800")
	assert.NotContains(t, admitted, "retry-after", "an admission carries no retry hint")
	second := agrees("second admission", check(server, "/api/exports", 0), "1800")
	assert.Equal(t, "0", second["x-ratelimit-remaining"])
	assert.Equal(t, "3600", second["x-ratelimit-reset"], "x-ratelimit-reset counts to the empty bucket")
	refused := check(server, "/api/exports", 0)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, refused.GetOverallCode())
	headers := agrees("refusal", refused, "1800")
	assert.Equal(t, "3600", headers["x-ratelimit-reset"], "x-ratelimit-reset counts to the empty bucket")
	assert.Equal(t, "1800", headers["retry-after"], "the effective window is longer than the retry hint")

	never := check(newServer(), "/api/exports", 3)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, never.GetOverallCode())
	assert.NotContains(t, agrees("refusal no waiting cures", never, ""), "retry-after")

	assert.Empty(t, check(server, "/other", 0).GetResponseHeadersToAdd(),
		"a request outside every rule carries no rate limit header")
}

// WithIETFHeaders(false) leaves the two structured fields out and keeps the
// rest: an admission still carries x-ratelimit-*, and a refusal x-ratelimit-*
// and retry-after.
func TestShouldRateLimit_withoutTheIETFFieldsSendsTheRest(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log, WithIETFHeaders(false))

	for step, want := range []envoyratelimit.RateLimitResponse_Code{
		envoyratelimit.RateLimitResponse_OK, envoyratelimit.RateLimitResponse_OVER_LIMIT,
	} {
		resp, err := server.ShouldRateLimit(context.Background(), request(domain, nil))
		require.NoError(t, err)
		require.Equal(t, want, resp.GetOverallCode())
		headers := headerMap(resp)
		assert.Contains(t, headers, "x-ratelimit-limit", "check %d", step)
		assert.NotContains(t, headers, "ratelimit-policy", "check %d", step)
		assert.NotContains(t, headers, "ratelimit", "check %d", step)
		if want == envoyratelimit.RateLimitResponse_OVER_LIMIT {
			assert.Contains(t, headers, "retry-after", "the refusal lost its retry hint")
		}
	}
}
