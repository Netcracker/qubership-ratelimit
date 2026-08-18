package key

import (
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
)

var id = Ident{Domain: "gateway.public", Policy: "orders", Block: "api", Rule: "per-user"}

func mustAlgo(t *testing.T, name string) algo.Algorithm {
	t.Helper()
	a, ok := algo.ByName(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	return a
}

func TestBucketGoldenKeys(t *testing.T) {
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
			"gcra minute by client",
			gcra, algo.Window{Requests: 100, Period: time.Minute}, []string{"alice"},
			"rl:v1:{gateway.public}:orders/api/per-user:gcra:60:alice",
		},
		{
			"fixed day by client and path",
			fixed, algo.Window{Requests: 10000, Period: 24 * time.Hour}, []string{"alice", "/api/v1/orders"},
			"rl:v1:{gateway.public}:orders/api/per-user:fixedwindow:86400:alice:%2Fapi%2Fv1%2Forders",
		},
		{
			"no axes, no axis segments",
			gcra, algo.Window{Requests: 5000, Period: time.Minute}, nil,
			"rl:v1:{gateway.public}:orders/api/per-user:gcra:60",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Bucket(id, c.algo, c.w, c.axes); got != c.want {
				t.Errorf("Bucket() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEscapingStopsForgery pins the security property: an axis value shaped
// like key syntax must not create segment boundaries or a hash tag beyond the
// domain's own.
func TestEscapingStopsForgery(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 100, Period: time.Minute, Burst: 100}

	forged := Bucket(id, gcra, w, []string{"evil}:{spoof", "b:c"})
	if strings.Count(forged, "{") != 1 || strings.Count(forged, "}") != 1 {
		t.Errorf("axis value forged a hash tag: %q", forged)
	}
	if got, want := strings.Count(forged, ":"), strings.Count(Bucket(id, gcra, w, []string{"a", "b"}), ":"); got != want {
		t.Errorf("axis value forged a segment: %q", forged)
	}

	// Escaping must keep distinct values distinct.
	if Bucket(id, gcra, w, []string{"a:b"}) == Bucket(id, gcra, w, []string{"a%3Ab"}) {
		t.Error("escaping collapsed two distinct axis values into one key")
	}
}

func TestEmptyDomainPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("DomainPrefix accepted an empty domain; its keys would carry an empty hash tag")
		}
	}()
	DomainPrefix("")
}

func TestPrefixHierarchy(t *testing.T) {
	if got, want := RulePrefix(id), DomainPrefix(id.Domain); !strings.HasPrefix(got, want) {
		t.Errorf("RulePrefix(%v) = %q lacks domain prefix %q", id, got, want)
	}
}

func TestEveryBucketSharesTheRulePrefix(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	prefix := RulePrefix(id)

	for _, axes := range [][]string{nil, {"alice"}, {"alice", "acme"}} {
		k := Bucket(id, gcra, algo.Window{Requests: 1, Period: time.Second}, axes)
		if !strings.HasPrefix(k, prefix) {
			t.Errorf("Bucket(%v) = %q lacks prefix %q", axes, k, prefix)
		}
	}
}

// TestIdentPartsAreEscaped pins that a block or rule name shaped like key
// syntax cannot forge the triple or a hash tag.
func TestIdentPartsAreEscaped(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 1, Period: time.Second, Burst: 1}
	evil := Ident{Domain: "gateway.public", Policy: "orders", Block: "api/x", Rule: "r:{a}"}

	k := Bucket(evil, gcra, w, []string{"alice"})
	if strings.Count(k, "/") != 2 {
		t.Errorf("block name forged a triple separator: %q", k)
	}
	if strings.Count(k, "{") != 1 || strings.Count(k, "}") != 1 {
		t.Errorf("rule name forged a hash tag: %q", k)
	}
}

func TestAxisOrderIsSignificant(t *testing.T) {
	gcra := mustAlgo(t, "GCRA")
	w := algo.Window{Requests: 1, Period: time.Second}

	if Bucket(id, gcra, w, []string{"a", "b"}) == Bucket(id, gcra, w, []string{"b", "a"}) {
		t.Error("axis order does not reach the key")
	}
}
