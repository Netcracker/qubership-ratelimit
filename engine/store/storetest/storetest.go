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
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// tolerance absorbs the real time passing between two calls in one subtest.
const tolerance = 10 * time.Second

const hour = time.Hour

// Shared precondition messages: several subtests open with the same two
// checks, and a repeated literal is a lint finding, not a style choice.
const (
	msgFreshRefused = "precondition failed: a fresh bucket refused the first request"
	msgSpentNotHeld = "precondition failed: a one-request bucket admitted the second request"
)

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
		{"ScanListsEveryKeyUnderThePrefix", scanListsEveryKeyUnderThePrefix},
		{"ScanOfAnEmptyPrefixEndsWithNoKeys", scanOfAnEmptyPrefixEndsWithNoKeys},
		{"ScanRejectsANonPositiveLimit", scanRejectsANonPositiveLimit},
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
		t.Fatal(msgFreshRefused)
	}
	if f.decideAdmitted(both) {
		t.Fatal(msgSpentNotHeld)
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
		t.Fatal(msgFreshRefused)
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
		t.Fatal(msgFreshRefused)
	}
	first := f.decideOne(one)
	if first.Allowed {
		t.Fatal(msgSpentNotHeld)
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
		t.Fatal(msgFreshRefused)
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
		t.Fatal(msgFreshRefused)
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
		t.Fatal(msgFreshRefused)
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
		t.Fatal(msgFreshRefused)
	}
	if f.decideAdmitted(one) {
		t.Fatal(msgSpentNotHeld)
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

// maxScanSteps caps a walk of the conformance suite. A live store shared with
// other tests holds keys outside the prefix, and a step of a few keys over
// such a keyspace is mostly empty; the cap is far above what that takes, so
// that a walk which never ends fails instead of hanging.
const maxScanSteps = 100000

// Seven keys walked three at a time, and then one at a time, the smallest
// step there is: every key comes back, and nothing outside the prefix does.
// On the in-process store the first walk crosses two step boundaries and
// the second six.
func scanListsEveryKeyUnderThePrefix(t *testing.T, f *fixture) {
	insp := f.inspector()
	buckets := make([]store.Bucket, 0, 7)
	for i := range 7 {
		buckets = append(buckets,
			f.bucket(fmt.Sprintf("k%d", i), "GCRA", algo.Window{Requests: 10, Period: hour, Burst: 10}, false))
	}
	f.decide(buckets, 1)

	for _, limit := range []int{3, 1} {
		seen := scanWalk(t, insp, f.uniq, limit)
		for _, b := range buckets {
			if !slices.Contains(seen, b.Key) {
				t.Errorf("Scan(%q) walk with limit %d = %v, missing %q", f.uniq, limit, seen, b.Key)
			}
		}
		for _, k := range seen {
			if !strings.HasPrefix(k, f.uniq) {
				t.Errorf("Scan(%q) walk with limit %d returned %q, a key outside the prefix", f.uniq, limit, k)
			}
		}
	}
}

func scanOfAnEmptyPrefixEndsWithNoKeys(t *testing.T, f *fixture) {
	prefix := f.uniq + ":nothing:"
	if seen := scanWalk(t, f.inspector(), prefix, 3); len(seen) != 0 {
		t.Errorf("Scan(%q) walk = %v, want no keys", prefix, seen)
	}
}

func scanRejectsANonPositiveLimit(t *testing.T, f *fixture) {
	insp := f.inspector()
	for _, limit := range []int{0, -1} {
		if _, _, err := insp.Scan(f.t.Context(), f.uniq, "", limit); err == nil {
			t.Errorf("Scan(%q, \"\", %d) = no error, want one", f.uniq, limit)
		}
	}
}

// scanWalk follows Scan from an empty cursor to the end and returns every key
// the steps returned, in step order, failing on a step that is not sorted or
// a walk that outruns maxScanSteps.
func scanWalk(t *testing.T, insp store.Inspector, prefix string, limit int) []string {
	t.Helper()
	var seen []string
	cursor := ""
	for step := 1; ; step++ {
		keys, next, err := insp.Scan(t.Context(), prefix, cursor, limit)
		if err != nil {
			t.Fatalf("Scan(%q, %q, %d) at step %d: %v", prefix, cursor, limit, step, err)
		}
		if !slices.IsSorted(keys) {
			t.Errorf("Scan(%q, %q, %d) at step %d = %v, want the step sorted", prefix, cursor, limit, step, keys)
		}
		seen = append(seen, keys...)
		if next == "" {
			return seen
		}
		if step >= maxScanSteps {
			t.Fatalf("Scan(%q) walk did not end within %d steps; the last cursor is %q", prefix, step, next)
		}
		cursor = next
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

// inspector returns the store's Inspector, skipping the subtest of a store
// that has none.
func (f *fixture) inspector() store.Inspector {
	f.t.Helper()
	insp, ok := f.s.(store.Inspector)
	if !ok {
		f.t.Skip("store does not implement Inspector")
	}
	return insp
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
