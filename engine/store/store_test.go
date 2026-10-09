package store

import (
	"testing"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
)

// A verdict count that differs from the bucket count is a broken Store
// implementation, not data, and the one function deciding admission fails
// loudly rather than guessing.
func TestAdmittedPanicsWhenTheVerdictCountDiffersFromTheBucketCount(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Admitted(2 buckets, 1 verdict) returned, want a panic")
		}
	}()
	Admitted(make([]Bucket, 2), make([]Verdict, 1))
}

// The counter math runs in whole microseconds, where a period under one
// microsecond is zero. The guard refuses such a period and passes a period of
// exactly one microsecond.
func TestGuardBuckets_refusesAPeriodUnderOneMicrosecond(t *testing.T) {
	withPeriod := func(period time.Duration) []Bucket {
		return []Bucket{{Key: "k", Algorithm: algo.GCRAID, Cost: 1,
			Window: algo.Window{Requests: 1, Period: period, Burst: 1}}}
	}

	t.Run("a period of one microsecond", func(t *testing.T) {
		if err := GuardBuckets(withPeriod(time.Microsecond)); err != nil {
			t.Errorf("GuardBuckets(a window of period %v) = %v, want nil", time.Microsecond, err)
		}
	})
	t.Run("a period of 999 nanoseconds", func(t *testing.T) {
		if err := GuardBuckets(withPeriod(999 * time.Nanosecond)); err == nil {
			t.Errorf("GuardBuckets(a window of period %v) = nil, want an error", 999*time.Nanosecond)
		}
	})
}
