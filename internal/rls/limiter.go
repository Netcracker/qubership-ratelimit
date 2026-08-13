package rls

import (
	"sync"
	"time"
)

// One request per second per domain.
const (
	defaultLimit  = 1
	defaultWindow = time.Second
)

// fixedWindow counts requests per key in wall-clock windows and denies once the
// limit is reached.
type fixedWindow struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count      int
	windowEnds time.Time
}

func newFixedWindow(limit int, window time.Duration) *fixedWindow {
	return &fixedWindow{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
	}
}

// allow counts the request and reports whether it fits under the limit, along
// with the count the decision was made from.
func (f *fixedWindow) allow(key string) (bool, int) {
	if f.limit <= 0 {
		return true, 0
	}

	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	b, ok := f.buckets[key]
	if !ok || now.After(b.windowEnds) {
		b = &bucket{windowEnds: now.Add(f.window)}
		f.buckets[key] = b
	}

	b.count++
	return b.count <= f.limit, b.count
}
