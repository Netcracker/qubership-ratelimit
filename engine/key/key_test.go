package key

import (
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
)

var id = Ident{Namespace: "core-1-core", Domain: "gateway.public", Block: "api", Rule: "per-user"}

func mustAlgo(t *testing.T, name string) algo.Algorithm {
	t.Helper()
	a, ok := algo.ByName(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	return a
}

func TestBucketMatchesTheGoldenKey(t *testing.T) {
	ident := Ident{Namespace: "core-1-core", Domain: "gateway.public", Block: "api", Rule: "per-user"}
	gcra := mustAlgo(t, "GCRA")
	fixed := mustAlgo(t, "FixedWindow")

	cases := []struct {
		name string
		algo algo.Algorithm
		w    algo.Window
		axes []string
		want string
	}{
		{
			"a GCRA minute window by client",
			gcra, algo.Window{Requests: 100, Period: time.Minute}, []string{"alice"},
			"rl:v1:{core-1-core/gateway.public}:api/per-user:gcra:60:alice:",
		},
		{
			"a fixed day window by client and path, the path escaped",
			fixed, algo.Window{Requests: 10000, Period: 24 * time.Hour}, []string{"alice", "/api/v1/orders"},
			"rl:v1:{core-1-core/gateway.public}:api/per-user:fixedwindow:86400:alice:%2Fapi%2Fv1%2Forders:",
		},
		{
			"a window without axes, its key terminated as the prefix of its own subtree",
			gcra, algo.Window{Requests: 5000, Period: time.Minute}, nil,
			"rl:v1:{core-1-core/gateway.public}:api/per-user:gcra:60:",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bucketOf(ident, c.algo, c.w, c.axes); got != c.want {
				t.Errorf("Bucket(RatePrefix(%+v, %s, %+v), %q) = %q, want %q",
					ident, c.algo.Name(), c.w, c.axes, got, c.want)
			}
		})
	}
}

// An axis value comes from a token claim, so it is attacker-shaped: key syntax
// in it must create no segment boundary and no hash tag beyond the domain's own.
func TestBucketEscapesKeySyntaxInAnAxisValue(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	axes := []string{"evil}:{spoof", "b:c"}
	forged := bucketOf(id, gcra, w, axes)
	if got := strings.Count(forged, "{"); got != 1 {
		t.Errorf("Bucket(%q) = %q holds %d opening braces, want the domain's 1", axes, forged, got)
	}
	if got := strings.Count(forged, "}"); got != 1 {
		t.Errorf("Bucket(%q) = %q holds %d closing braces, want the domain's 1", axes, forged, got)
	}
	plain := bucketOf(id, gcra, w, []string{"a", "b"})
	if got, want := strings.Count(forged, ":"), strings.Count(plain, ":"); got != want {
		t.Errorf("Bucket(%q) = %q holds %d separators, want %d as in %q", axes, forged, got, want, plain)
	}
}

// A value that already reads like an escape sequence escapes again, so it never
// lands on the key of the value it spells.
func TestBucketKeepsAColonApartFromItsEscapeSequence(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	colon := bucketOf(id, gcra, w, []string{"a:b"})
	if spelled := bucketOf(id, gcra, w, []string{"a%3Ab"}); spelled == colon {
		t.Errorf(`Bucket(["a:b"]) and Bucket(["a%%3Ab"]) are both %q, want two keys`, colon)
	}
}

func TestDomainPrefixPanicsOnAnEmptyHashTagPart(t *testing.T) {
	for _, c := range []struct{ name, namespace, domain string }{
		{"an empty domain", "core-1-core", ""},
		{"an empty namespace", "", "gateway.public"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("DomainPrefix(%q, %q) returned, want a panic", c.namespace, c.domain)
				}
			}()
			DomainPrefix(c.namespace, c.domain)
		})
	}
}

// The namespace is inside the hash tag, so two installations that reach one
// store by mistake count in separate keys.
func TestRulePrefixSeparatesTwoNamespaces(t *testing.T) {
	first := Ident{Namespace: "core-1-core", Domain: "gateway.public", Block: "api", Rule: "r"}
	second := first
	second.Namespace = "core-2-core"

	if a, b := RulePrefix(first), RulePrefix(second); a == b {
		t.Errorf("RulePrefix in namespaces %q and %q is %q for both, want two prefixes",
			first.Namespace, second.Namespace, a)
	}
}

// Every segment of a bucket key is terminated, so one string addresses the
// exact bucket and scopes its subtree, and a client's key never prefixes the
// key of a longer client name that starts with it.
func TestBucketKeyPrefixesOnlyItsOwnSubtree(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	window := bucketOf(id, gcra, w, nil)
	alice := bucketOf(id, gcra, w, []string{"alice"})
	aliceByPath := bucketOf(id, gcra, w, []string{"alice", "/p"})
	alice2ByPath := bucketOf(id, gcra, w, []string{"alice2", "/p"})

	if !strings.HasPrefix(alice, window) {
		t.Errorf("the key of alice %q lacks the window prefix %q", alice, window)
	}
	if !strings.HasPrefix(aliceByPath, alice) {
		t.Errorf("the key of alice by path %q lacks the prefix of alice %q", aliceByPath, alice)
	}
	if strings.HasPrefix(alice2ByPath, alice) {
		t.Errorf("the key of alice2 by path %q starts with the key of alice %q", alice2ByPath, alice)
	}
}

func TestRulePrefixStartsWithTheDomainPrefix(t *testing.T) {
	if got, want := RulePrefix(id), DomainPrefix(id.Namespace, id.Domain); !strings.HasPrefix(got, want) {
		t.Errorf("RulePrefix(%+v) = %q lacks domain prefix %q", id, got, want)
	}
}

func TestEveryBucketSharesTheRulePrefix(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	prefix := RulePrefix(id)

	for _, axes := range [][]string{nil, {"alice"}, {"alice", "acme"}} {
		k := bucketOf(id, gcra, algo.Window{Requests: 1, Period: time.Second}, axes)
		if !strings.HasPrefix(k, prefix) {
			t.Errorf("Bucket(%q) = %q lacks prefix %q", axes, k, prefix)
		}
	}
}

// A block or rule name shaped like key syntax cannot forge the block/rule pair
// or a hash tag.
func TestBucketEscapesKeySyntaxInTheBlockAndRuleNames(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 1, Period: time.Second, Burst: 1}
	evil := Ident{Namespace: "core-1-core", Domain: "gateway.public", Block: "api/x", Rule: "r:{a}"}

	k := bucketOf(evil, gcra, w, []string{"alice"})
	// One separator inside the hash tag, one between block and rule.
	if got := strings.Count(k, "/"); got != 2 {
		t.Errorf("the key of block %q is %q and holds %d slashes, want 2", evil.Block, k, got)
	}
	if got := strings.Count(k, "{"); got != 1 {
		t.Errorf("the key of rule %q is %q and holds %d opening braces, want the domain's 1", evil.Rule, k, got)
	}
	if got := strings.Count(k, "}"); got != 1 {
		t.Errorf("the key of rule %q is %q and holds %d closing braces, want the domain's 1", evil.Rule, k, got)
	}
}

func TestBucketKeysDifferWhenTheAxesSwap(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 1, Period: time.Second}

	if ab, ba := bucketOf(id, gcra, w, []string{"a", "b"}), bucketOf(id, gcra, w, []string{"b", "a"}); ab == ba {
		t.Errorf(`Bucket(["a", "b"]) and Bucket(["b", "a"]) are both %q, want two keys`, ab)
	}
}

// bucketOf composes the two halves of key building the way the request path
// does: the compiled rate prefix plus the runtime axes.
func bucketOf(id Ident, a algo.Algorithm, w algo.Window, axes []string) string {
	return Bucket(RatePrefix(id, a, w), axes)
}
