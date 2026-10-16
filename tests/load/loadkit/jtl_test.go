package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The columns are found by their names in the header, whatever their order,
// a row without kind, from a sampler outside the two thread groups, is
// skipped, and each row gets the outcome its response code and
// x-ratelimit-remaining value give it.
func TestReadJTL_classifiesTheRowsOfBothThreadGroups(t *testing.T) {
	jtl := strings.Join([]string{
		`label,timeStamp,responseCode,responseMessage,elapsed,user,group,kind,remaining,lag`,
		`debug sampler,1800057600000,200,OK,3,,,,-,`,
		`READ,1800057601000,200,OK,4,a,orders,background,49,0`,
		`LIST,1800057602000,429,Too Many Requests,5,b,billing,hot,0,12`,
		`SEARCH,1800057603000,200,OK,6,c,orders,background,-,0`,
		`READ,1800057604000,"Non HTTP response code: java.net.SocketTimeoutException",` +
			`"Read timed out, after 10000 ms",10000,d,orders,background,-,0`,
	}, "\n") + "\n"

	type row struct {
		user, group, kind string
		outcome           outcome
		lag               int64
	}
	var got []row
	require.NoError(t, readJTL(strings.NewReader(jtl), func(s sample) {
		got = append(got, row{s.user, s.group, s.kind, s.outcome, s.lag})
	}))
	assert.Equal(t, []row{
		{"a", "orders", "background", admitted, 0},
		{"b", "billing", "hot", refused, 12},
		{"c", "orders", "background", undecided, 0},
		{"d", "orders", "background", failed, 0},
	}, got)
}

func TestReadJTL_refusesResultsWithoutTheSampleVariables(t *testing.T) {
	jtl := "timeStamp,elapsed,label,responseCode,user,group,kind,remaining\n"
	err := readJTL(strings.NewReader(jtl), func(sample) {})
	assert.ErrorContains(t, err, "no lag column")
}
