package memory_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/engine/store/storetest"
)

// The in-memory store is the first implementation to run the conformance
// suite, and the reference the Redis store is compared with.
func TestConformsToTheStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		return memory.New()
	})
}

// The fixture runs the cheap guards behind the contract that windows passed
// validation, and answers a broken bucket with an error, never a panic.
func TestDecideRefusesABucketThatSkippedValidation(t *testing.T) {
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
			s := memory.New()

			if _, err := s.Decide(t.Context(), []store.Bucket{c.bucket}, 1); err == nil {
				t.Errorf("Decide(%+v) = no error, want one", c.bucket)
			}
		})
	}
}

// Peek shares the cost rule of Decide: a cost below 1 is refused.
func TestPeekRefusesACostOfZero(t *testing.T) {
	s := memory.New()
	b := store.Bucket{
		Key:       "p:{d}:k",
		Algorithm: algo.GCRAID,
		Window:    algo.Window{Requests: 10, Period: time.Hour, Burst: 10},
	}

	if _, err := s.Peek(t.Context(), []store.Bucket{b}, 0); err == nil {
		t.Errorf("Peek(%q, cost 0) = no error, want one", b.Key)
	}
}

// The conformance suite cannot check expiry without waiting a window out. Both
// windows here last one second, so the state of both algorithms is gone a
// second after the decision; the poll allows 200 ms more for the scheduler.
func TestStateIsGoneOnceItsWindowDrains(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Scan(\"exp:\"): %v", err)
	}
	if want := []string{"exp:{d}:fixed", "exp:{d}:gcra"}; !slices.Equal(keys, want) {
		t.Fatalf("Scan(\"exp:\") = %v right after the decision, want %v", keys, want)
	}

	deadline := time.Now().Add(1200 * time.Millisecond)
	for {
		keys, _, err = s.Scan(t.Context(), "exp:", "", 10)
		if err == nil && len(keys) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Scan(\"exp:\") = %v, %v 1.2 s after the decision, want no keys once both windows drained",
				keys, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// storeWithKeys returns a store that holds one live bucket under each key.
func storeWithKeys(t *testing.T, keys ...string) *memory.Store {
	t.Helper()
	s := memory.New()
	for _, k := range keys {
		bucket := store.Bucket{Key: k, Algorithm: algo.GCRAID,
			Window: algo.Window{Requests: 10, Period: time.Hour, Burst: 10}}
		if _, err := s.Decide(t.Context(), []store.Bucket{bucket}, 1); err != nil {
			t.Fatalf("Decide(%q): %v", k, err)
		}
	}
	return s
}

// The fixture walks in key order and each step ends on its last key, so a
// walk of five keys two at a time is three steps that repeat nothing, and a
// step with room to spare is the last one. The walk stops after ten steps, so
// a cursor that never ends it shows up as extra steps in the report.
func TestScan_walksInKeyOrderWithoutARepeat(t *testing.T) {
	s := storeWithKeys(t, "walk:{d}:a", "walk:{d}:b", "walk:{d}:c", "walk:{d}:d", "walk:{d}:e")

	var steps [][]string
	cursor := ""
	for range 10 {
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
}

// Any string is a cursor: the walk resumes after it in key order, whether or
// not it is a key of the store.
func TestScan_resumesAfterACursorThatIsNotAKey(t *testing.T) {
	s := storeWithKeys(t, "walk:{d}:a", "walk:{d}:b", "walk:{d}:c", "walk:{d}:d", "walk:{d}:e")

	keys, _, err := s.Scan(t.Context(), "walk:", "walk:{d}:bb", 2)

	if err != nil {
		t.Fatalf("Scan(\"walk:\", \"walk:{d}:bb\", 2): %v", err)
	}
	if want := []string{"walk:{d}:c", "walk:{d}:d"}; !slices.Equal(keys, want) {
		t.Errorf("Scan(\"walk:\", \"walk:{d}:bb\", 2) = %v, want %v", keys, want)
	}
}
