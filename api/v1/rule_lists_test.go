package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A list a rule writes empty is a value under presets: it replaces the
// preset's list, where a list left out takes it. A Go client therefore sends
// the empty list as [] and leaves a list it left out off the wire. The four
// lists of Rule are omitzero for that reason, where omitempty would drop the
// empty list and the rule would take the preset's.
func TestRule_serializesAListWhenItIsWrittenEvenEmpty(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "lists written empty are serialized as empty lists",
			rule: Rule{
				Name: "r", Matches: []Predicate{}, Counters: []string{}, Rates: []Rate{}, ReplacedRules: []string{},
			},
			want: `{"name": "r", "matches": [], "counters": [], "rates": [], "replacedRules": []}`,
		},
		{
			name: "lists left out are not serialized",
			rule: Rule{Name: "r"},
			want: `{"name": "r"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			written, err := json.Marshal(tc.rule)

			require.NoError(t, err, "json.Marshal(Rule)")
			assert.JSONEq(t, tc.want, string(written), "json.Marshal(Rule)")
		})
	}
}
