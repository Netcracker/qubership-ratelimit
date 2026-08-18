// Package storetest exercises the Store contract against any implementation.
//
// The Store interface promises behavior the type system cannot see: a refused
// request leaves no trace, an admitted one charges every enforcing bucket,
// Peek never charges, shadow buckets count without vetoing. An implementation that gets
// these wrong still compiles and passes its own tests while production counts
// differently. Every implementation therefore runs this one suite, and
// "swappable stores" becomes a claim about behavior, not about types.
//
// The suite never fakes time: a Redis-backed store takes its clock from the
// server, so properties are asserted over long windows with small tolerances,
// and the same code runs against the in-memory fixture and a live store.
package storetest

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// tolerance absorbs the real time passing between two calls in one subtest.
const tolerance = 10 * time.Second

const hour = time.Hour

// Run exercises the contract against one implementation. newStore is called
// once per subtest and must return a ready store, registering cleanup on t.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	subtests := []struct {
		name string
		fn   func(t *testing.T, f *fixture)
	}{
		{"ChargesAllOrNothing", chargesAllOrNothing},
		{"PeekDoesNotCharge", peekDoesNotCharge},
		{"RefusalSpendsNothing", refusalSpendsNothing},
		{"ShadowCountsWithoutVeto", shadowCountsWithoutVeto},
		{"ShadowRefusalSpendsNothing", shadowRefusalSpendsNothing},
		{"CostThatCanNeverFit", costThatCanNeverFit},
		{"RejectsNonPositiveCost", rejectsNonPositiveCost},
		{"DuplicateKeysRejected", duplicateKeysRejected},
		{"ResetClearsState", resetClearsState},
		{"VerdictPerBucketInOrder", verdictPerBucketInOrder},
		{"FixedWindowCounts", fixedWindowCounts},
		{"KeysListsUnderPrefix", keysListsUnderPrefix},
	}
	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, newFixture(t, newStore))
		})
	}
}

func chargesAllOrNothing(t *testing.T, f *fixture) {
	tight := f.bucket("tight", "GCRA", algo.Window{Requests: 1, Period: hour, Burst: 1}, false)
	roomy := f.bucket("roomy", "GCRA", algo.Window{Requests: 1000, Period: hour, Burst: 1000}, false)
	both := []store.Bucket{tight, roomy}

	if !f.decideAdmitted(both) {
		t.Fatal("first request refused by fresh buckets")
	}
	if f.decideAdmitted(both) {
		t.Fatal("second request admitted past a one-request bucket")
	}
	if got := f.peekOne(roomy).Remaining; got < 999 {
		t.Errorf("roomy Remaining = %d after one admitted and one refused request: the refusal charged it", got)
	}
}

func peekDoesNotCharge(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false)

	for i := range 3 {
		if got := f.peekOne(b).Remaining; got != 10 {
			t.Fatalf("Peek #%d: Remaining = %d on an untouched bucket, want 10", i+1, got)
		}
	}
	if !f.decideAdmitted([]store.Bucket{b}) {
		t.Fatal("request refused by a fresh bucket")
	}
	if got := f.peekOne(b).Remaining; got != 9 {
		t.Errorf("Remaining = %d after one admitted request, want 9", got)
	}
}

// refusalSpendsNothing observes the invariant through GCRA, where a charged
// refusal moves RetryAfter. Under FixedWindow a spurious increment is
// invisible until the window boundary — and harmless past it — so the
// property stays GCRA-only here.
func refusalSpendsNothing(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 1, Period: hour, Burst: 1}, false)
	one := []store.Bucket{b}

	if !f.decideAdmitted(one) {
		t.Fatal("first request refused by a fresh bucket")
	}
	first := f.decideOne(one)
	if first.Allowed {
		t.Fatal("second request admitted past a one-request bucket")
	}
	f.decideOne(one)
	last := f.decideOne(one)
	if last.RetryAfter > first.RetryAfter+tolerance {
		t.Errorf("RetryAfter grew from %s to %s across refusals: refusals advanced counter state",
			first.RetryAfter, last.RetryAfter)
	}
}

func shadowCountsWithoutVeto(t *testing.T, f *fixture) {
	shadow := f.bucket("shadow", "GCRA", algo.Window{Requests: 1, Period: hour, Burst: 1}, true)
	roomy := f.bucket("roomy", "GCRA", algo.Window{Requests: 1000, Period: hour, Burst: 1000}, false)
	both := []store.Bucket{shadow, roomy}

	if !f.decideAdmitted(both) {
		t.Fatal("first request refused by fresh buckets")
	}
	verdicts := f.decide(both, 1)
	if !store.Admitted(both, verdicts) {
		t.Fatal("an exhausted shadow bucket vetoed the request")
	}
	if verdicts[0].Allowed {
		t.Error("shadow verdict reports allowed on an exhausted bucket: shadow was not charged")
	}
}

func shadowRefusalSpendsNothing(t *testing.T, f *fixture) {
	shadow := f.bucket("shadow", "GCRA", algo.Window{Requests: 1, Period: hour, Burst: 1}, true)
	roomy := f.bucket("roomy", "GCRA", algo.Window{Requests: 1000, Period: hour, Burst: 1000}, false)
	both := []store.Bucket{shadow, roomy}

	if !f.decideAdmitted(both) {
		t.Fatal("first request refused by fresh buckets")
	}
	first := f.decide(both, 1)[0]
	if first.Allowed {
		t.Fatal("shadow verdict reports allowed on an exhausted bucket")
	}
	f.decide(both, 1)
	last := f.decide(both, 1)[0]
	if last.RetryAfter > first.RetryAfter+tolerance {
		t.Errorf("shadow RetryAfter grew from %s to %s: refused shadow buckets are being charged",
			first.RetryAfter, last.RetryAfter)
	}
}

func costThatCanNeverFit(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 100, Period: hour, Burst: 5}, false)
	one := []store.Bucket{b}

	v := f.decide(one, 10)[0]
	if v.Allowed {
		t.Fatal("cost 10 admitted into burst capacity 5")
	}
	if !v.CostExceedsCapacity {
		t.Error("refusal of an impossible cost is not marked CostExceedsCapacity")
	}
	after := f.decide(one, 1)[0]
	if !after.Allowed {
		t.Fatal("normal request refused after an impossible-cost refusal")
	}
	if after.Remaining != 4 {
		t.Errorf("Remaining = %d, want 4: the impossible cost charged the bucket", after.Remaining)
	}
}

func rejectsNonPositiveCost(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false)
	one := []store.Bucket{b}

	// Charge one unit first: on a full bucket Remaining is capped at
	// capacity, so an executed refund would be invisible.
	if !f.decideAdmitted(one) {
		t.Fatal("request refused by a fresh bucket")
	}
	for _, cost := range []int64{0, -1} {
		if _, err := f.s.Decide(f.t.Context(), one, cost); err == nil {
			t.Errorf("Decide accepted cost %d; a negative cost would refund counter state", cost)
		}
	}
	if got := f.peekOne(b).Remaining; got != 9 {
		t.Errorf("Remaining = %d after rejected costs, want untouched 9", got)
	}
}

func duplicateKeysRejected(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false)

	if _, err := f.s.Decide(f.t.Context(), []store.Bucket{b, b}, 1); err == nil {
		t.Error("Decide accepted duplicate bucket keys; one of the two charges would be lost")
	}
	if got := f.peekOne(b).Remaining; got != 10 {
		t.Errorf("Remaining = %d after rejected duplicates, want untouched 10", got)
	}
}

func resetClearsState(t *testing.T, f *fixture) {
	b := f.bucket("b", "GCRA", algo.Window{Requests: 1, Period: hour, Burst: 1}, false)
	one := []store.Bucket{b}

	if !f.decideAdmitted(one) {
		t.Fatal("first request refused by a fresh bucket")
	}
	if f.decideAdmitted(one) {
		t.Fatal("second request admitted past a one-request bucket")
	}
	if err := f.s.Reset(f.t.Context(), []string{b.Key}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := f.s.Reset(f.t.Context(), []string{b.Key}); err != nil {
		t.Errorf("Reset over absent state: %v; management retries must be a no-op", err)
	}
	if !f.decideAdmitted(one) {
		t.Error("request refused after Reset")
	}
}

func verdictPerBucketInOrder(t *testing.T, f *fixture) {
	buckets := []store.Bucket{
		f.bucket("b5", "GCRA", algo.Window{Requests: 5, Period: hour, Burst: 5}, false),
		f.bucket("b50", "GCRA", algo.Window{Requests: 50, Period: hour, Burst: 50}, false),
		f.bucket("b500", "GCRA", algo.Window{Requests: 500, Period: hour, Burst: 500}, false),
	}

	verdicts := f.decide(buckets, 1)
	for i, want := range []int64{4, 49, 499} {
		if got := verdicts[i].Remaining; got < want || got > want+1 {
			t.Errorf("verdicts[%d].Remaining = %d, want %d or %d: order or count broken", i, got, want, want+1)
		}
	}
}

func fixedWindowCounts(t *testing.T, f *fixture) {
	waitOutWindowBoundary(hour)
	b := f.bucket("b", "FixedWindow", algo.Window{Requests: 3, Period: hour}, false)
	one := []store.Bucket{b}

	for i := range 3 {
		if !f.decideAdmitted(one) {
			t.Fatalf("request %d refused under a limit of 3", i+1)
		}
	}
	if f.decideAdmitted(one) {
		t.Error("fourth request admitted under a limit of 3")
	}
}

func keysListsUnderPrefix(t *testing.T, f *fixture) {
	insp, ok := f.s.(store.Inspector)
	if !ok {
		t.Skip("store does not implement Inspector")
	}
	a := f.bucket("a", "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false)
	b := f.bucket("b", "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false)
	f.decide([]store.Bucket{a, b}, 1)

	keys, err := insp.Keys(f.t.Context(), f.uniq)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	for _, want := range []string{a.Key, b.Key} {
		if !slices.Contains(keys, want) {
			t.Errorf("Keys(%q) = %v, missing %q", f.uniq, keys, want)
		}
	}
}

// fixture holds one store and the run-unique key prefix that keeps reruns
// against a shared live store from tripping over a previous run's TTLs. The
// hash tag mirrors production keys: every bucket of one fixture shares a
// Redis Cluster slot, the way a domain's buckets do, so the suite runs
// against a cluster too.
type fixture struct {
	t    *testing.T
	s    store.Store
	uniq string
}

func newFixture(t *testing.T, newStore func(t *testing.T) store.Store) *fixture {
	return &fixture{
		t:    t,
		s:    newStore(t),
		uniq: fmt.Sprintf("storetest:{%d:%s}", time.Now().UnixNano(), t.Name()),
	}
}

func (f *fixture) bucket(name, algoName string, w algo.Window, shadow bool) store.Bucket {
	f.t.Helper()
	a, ok := algo.ByName(algoName)
	if !ok {
		f.t.Fatalf("%s is not registered", algoName)
	}
	return store.Bucket{
		Key:       f.uniq + ":" + name,
		Algorithm: a.ID(),
		Window:    w,
		Shadow:    shadow,
	}
}

func (f *fixture) decide(buckets []store.Bucket, cost int64) []store.Verdict {
	f.t.Helper()
	verdicts, err := f.s.Decide(f.t.Context(), buckets, cost)
	if err != nil {
		f.t.Fatalf("Decide: %v", err)
	}
	if len(verdicts) != len(buckets) {
		f.t.Fatalf("Decide returned %d verdicts for %d buckets", len(verdicts), len(buckets))
	}
	return verdicts
}

func (f *fixture) decideAdmitted(buckets []store.Bucket) bool {
	f.t.Helper()
	return store.Admitted(buckets, f.decide(buckets, 1))
}

func (f *fixture) decideOne(buckets []store.Bucket) store.Verdict {
	f.t.Helper()
	return f.decide(buckets, 1)[0]
}

func (f *fixture) peekOne(b store.Bucket) store.Verdict {
	f.t.Helper()
	verdicts, err := f.s.Peek(f.t.Context(), []store.Bucket{b}, 1)
	if err != nil {
		f.t.Fatalf("Peek: %v", err)
	}
	if len(verdicts) != 1 {
		f.t.Fatalf("Peek returned %d verdicts for 1 bucket", len(verdicts))
	}
	return verdicts[0]
}

// waitOutWindowBoundary sleeps briefly when a calendar window is about to roll
// over, so a fixed-window subtest never spans the boundary and flakes. Fixed
// windows are epoch-aligned (see the FixedWindow passport); the boundary is
// computed from the local clock as best effort, so a store skewed beyond the
// tolerance can still straddle it.
func waitOutWindowBoundary(period time.Duration) {
	now := time.Now()
	boundary := now.Truncate(period).Add(period)
	if wait := boundary.Sub(now); wait < tolerance {
		time.Sleep(wait + time.Second)
	}
}
