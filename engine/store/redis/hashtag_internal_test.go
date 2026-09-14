package redis

import "testing"

// hasHashTag follows the Cluster rule to the letter: the first "{" and the
// first "}" after it, with at least one character between them. An empty
// pair is hashed as a whole key, so a detector that took "{}" for a tag
// would scan one master for keys that live on all of them.
func TestHasHashTag_followsTheClusterRule(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"a tag", "rl:v1:{ns/domain}:", true},
		{"an empty pair is no tag", "rl:{}:", false},
		{"an empty pair before a tag is no tag", "{}{a}", false},
		{"an unclosed brace", "rl:{a", false},
		{"a closing brace alone", "rl:a}", false},
		{"no braces", "rl:v1:", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasHashTag(tc.in); got != tc.want {
				t.Errorf("hasHashTag(%q) = %t, want %t", tc.in, got, tc.want)
			}
		})
	}
}
