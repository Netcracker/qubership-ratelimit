package memory_test

import (
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
	keys, err := s.Keys(t.Context(), "exp:")
	if err != nil || len(keys) != 2 {
		t.Fatalf("Keys = %v, %v; want both live keys", keys, err)
	}

	time.Sleep(1200 * time.Millisecond)

	keys, err = s.Keys(t.Context(), "exp:")
	if err != nil || len(keys) != 0 {
		t.Fatalf("Keys = %v, %v after the windows drained; want none", keys, err)
	}
}
