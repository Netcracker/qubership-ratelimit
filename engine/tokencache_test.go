package engine

import (
	"crypto/sha256"
	"testing"
)

// TestTokenCacheNeverExceedsCapacity pins the retention contract for every
// capacity shape: two even generations, an odd capacity rounding down, and
// the single-generation degenerate case of capacity one.
func TestTokenCacheNeverExceedsCapacity(t *testing.T) {
	for _, capacity := range []int{1, 2, 3, 10} {
		c := newTokenCache(capacity)
		for i := range 100 {
			var h [sha256.Size]byte
			h[0], h[1] = byte(i), byte(i>>8)
			c.store(h, cacheEntry{})
			if got := len(c.cur) + len(c.prev); got > capacity {
				t.Fatalf("capacity %d: %d entries retained after %d inserts", capacity, got, i+1)
			}
		}
	}
}
