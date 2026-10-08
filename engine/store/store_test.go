package store

import "testing"

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
