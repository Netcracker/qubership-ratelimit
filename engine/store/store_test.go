package store

import "testing"

// TestAdmittedPanicsOnMismatch pins the contract that a verdict-count mismatch
// is a broken Store implementation, not data: the one function deciding
// admission must fail loudly rather than guess.
func TestAdmittedPanicsOnMismatch(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Admitted accepted 2 buckets with 1 verdict")
		}
	}()
	Admitted(make([]Bucket, 2), make([]Verdict, 1))
}
