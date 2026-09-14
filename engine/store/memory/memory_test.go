package memory_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/engine/store/storetest"
)

// TestContract is the point of the package: the first implementation to run
// the conformance suite.
func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return memory.New()
	})
}

// TestRejectsBrokenBuckets covers the cheap guards behind the "windows passed
// validation" contract: the fixture answers with an error, never a panic.
func TestRejectsBrokenBuckets(t *testing.T) {
	s := memory.New()
	valid := algo.Window{Requests: 10, Period: time.Hour, Burst: 10}

	cases := []struct {
		name   string
		bucket store.Bucket
	}{
		{"unknown algorithm", store.Bucket{Key: "g:{d}:a", Algorithm: 99, Window: valid}},
		{"requests below one", store.Bucket{Key: "g:{d}:b", Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 0, Period: time.Hour}}},
		{"period below a microsecond", store.Bucket{Key: "g:{d}:c", Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 1, Period: 0}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.Decide(t.Context(), []store.Bucket{c.bucket}, 1); err == nil {
				t.Error("Decide accepted a bucket that never passed validation")
			}
		})
	}
}

// TestPeekCostRules pins that Peek shares Decide's cost contract.
func TestPeekCostRules(t *testing.T) {
	s := memory.New()
	b := store.Bucket{
		Key:       "p:{d}:k",
		Algorithm: algo.GCRAID,
		Window:    algo.Window{Requests: 10, Period: time.Hour, Burst: 10},
	}
	if _, err := s.Peek(t.Context(), []store.Bucket{b}, 0); err == nil {
		t.Error("Peek accepted cost 0")
	}
}

// TestStateExpires covers the one property the suite cannot check quickly:
// state of both algorithms is gone once its window has fully drained.
func TestStateExpires(t *testing.T) {
	s := memory.New()
	buckets := []store.Bucket{
		{
			Key:       "exp:{d}:gcra",
			Algorithm: algo.GCRAID,
			Window:    algo.Window{Requests: 1, Period: time.Second, Burst: 1},
		},
		{
			Key:       "exp:{d}:fixed",
			Algorithm: algo.FixedWindowID,
			Window:    algo.Window{Requests: 1, Period: time.Second},
		},
	}

	if _, err := s.Decide(t.Context(), buckets, 1); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	keys, _, err := s.Scan(t.Context(), "exp:", "", 10)
	if err != nil || len(keys) != 2 {
		t.Fatalf("Scan(\"exp:\") = %v, %v; want both live keys", keys, err)
	}

	time.Sleep(1200 * time.Millisecond)

	keys, _, err = s.Scan(t.Context(), "exp:", "", 10)
	if err != nil || len(keys) != 0 {
		t.Fatalf("Scan(\"exp:\") = %v, %v after the windows drained; want none", keys, err)
	}
}

// The fixture walks in key order and each step ends on its last key, so a
// walk of five keys two at a time is three steps that repeat nothing, and a
// step with room to spare is the last one.
func TestScan_walksInKeyOrderWithoutARepeat(t *testing.T) {
	s := memory.New()
	want := []string{"walk:{d}:a", "walk:{d}:b", "walk:{d}:c", "walk:{d}:d", "walk:{d}:e"}
	for _, k := range want {
		bucket := store.Bucket{Key: k, Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 10, Period: time.Hour, Burst: 10}}
		if _, err := s.Decide(t.Context(), []store.Bucket{bucket}, 1); err != nil {
			t.Fatalf("Decide(%q): %v", k, err)
		}
	}

	var steps [][]string
	cursor := ""
	for {
		keys, next, err := s.Scan(t.Context(), "walk:", cursor, 2)
		if err != nil {
			t.Fatalf("Scan(\"walk:\", %q, 2): %v", cursor, err)
		}
		steps = append(steps, keys)
		if next == "" {
			break
		}
		cursor = next
	}

	wantSteps := [][]string{
		{"walk:{d}:a", "walk:{d}:b"},
		{"walk:{d}:c", "walk:{d}:d"},
		{"walk:{d}:e"},
	}
	if !reflect.DeepEqual(steps, wantSteps) {
		t.Errorf("Scan(\"walk:\") steps = %v, want %v", steps, wantSteps)
	}

	// Any string is a cursor: the walk resumes after it in key order, whether
	// or not it is a key of the store.
	keys, _, err := s.Scan(t.Context(), "walk:", "walk:{d}:bb", 2)
	if err != nil {
		t.Fatalf("Scan(\"walk:\", \"walk:{d}:bb\", 2): %v", err)
	}
	if want := []string{"walk:{d}:c", "walk:{d}:d"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("Scan(\"walk:\", \"walk:{d}:bb\", 2) = %v, want %v", keys, want)
	}
}
