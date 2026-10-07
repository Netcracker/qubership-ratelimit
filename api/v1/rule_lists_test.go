package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A list a rule writes empty is a value under presets, so it has to leave a
// Go client as [] and come back as an empty list, while a list left out
// leaves no field. The four lists of Rule are omitzero for that reason;
// omitempty would drop the empty list and the rule would take the preset's.
func TestRule_aListWrittenEmptyIsSerializedAndOneLeftOutIsNot(t *testing.T) {
	written, err := json.Marshal(Rule{
		Name: "r", Matches: []Predicate{}, Counters: []string{}, Rates: []Rate{}, ReplacedRules: []string{},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name": "r", "matches": [], "counters": [], "rates": [], "replacedRules": []}`, string(written))

	leftOut, err := json.Marshal(Rule{Name: "r"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name": "r"}`, string(leftOut))

	var back Rule
	require.NoError(t, json.Unmarshal(written, &back))
	assert.Equal(t, []string{}, back.Counters, "an empty list comes back as an empty list, not nil")
}
