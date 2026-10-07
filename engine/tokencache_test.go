package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/identity"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// TestTokenCacheNeverExceedsCapacity pins the retention contract for every
// capacity shape: two even generations, an odd capacity rounding down, and
// the single-generation degenerate case of capacity one.
func TestTokenCacheNeverExceedsCapacity(t *testing.T) {
	for _, capacity := range []int{1, 2, 3, 10} {
		c := newTokenCache(capacity, tokenCacheBytes)
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

// TestTokenCache_neverExceedsItsByteBudget fills the cache with entries
// whose bytes, not their count, reach the bound first: the two generations
// together never hold more than the budget.
func TestTokenCache_neverExceedsItsByteBudget(t *testing.T) {
	const budget, size = 10_000, 900
	for _, capacity := range []int{1, 1000} {
		c := newTokenCache(capacity, budget)
		for i := range 100 {
			var h [sha256.Size]byte
			h[0] = byte(i)
			c.store(h, cacheEntry{size: size})
			held := 0
			for _, e := range c.cur {
				held += e.size
			}
			for _, e := range c.prev {
				held += e.size
			}
			if held > budget {
				t.Fatalf("capacity %d: %d bytes retained after %d inserts, budget %d", capacity, held, i+1, budget)
			}
		}
		if capacity > 1 && len(c.prev) == 0 {
			t.Fatalf("capacity %d: the byte bound never rotated a generation", capacity)
		}
	}
}

// rolesEngine is an engine with the token cache and one extracted key, read
// from the roles claim, for the tests that size an extraction exactly.
func rolesEngine(key string) *Engine {
	return &Engine{
		snap: &compile.Snapshot{Extraction: []compile.KeyExtraction{
			{Key: key, Path: []string{"roles"}, Type: model.ValueStringArray}}},
		cache: newTokenCache(DefaultTokenCacheSize, tokenCacheBytes),
		stats: &CacheStats{},
	}
}

// rolesToken is an engine and a token whose roles claim extracts to an entry
// of exactly size bytes, as entrySize counts it: sixteen values whose lengths
// are multiples of valueAlign, and a key whose length takes up the rest.
func rolesToken(t *testing.T, size int) (*Engine, string) {
	t.Helper()
	const values = 16
	fixed := entrySize(map[string][]string{"": make([]string, values)}, nil)
	keyLen := (size - fixed) % valueAlign
	if keyLen == 0 {
		keyLen = valueAlign
	}
	units := (size - fixed - keyLen) / valueAlign
	roles := make([]string, values)
	for i := range roles {
		n := units / (values - i)
		roles[i] = strings.Repeat(string(rune('a'+i)), n*valueAlign)
		units -= n
	}
	raw, err := json.Marshal(map[string]any{"roles": roles})
	if err != nil {
		t.Fatal(err)
	}
	e := rolesEngine("r" + strings.Repeat("x", keyLen-1))
	tok := "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
	keys, _ := identity.Extract(e.snap.Extraction, tok)
	if got := entrySize(keys, nil); got != size {
		t.Fatalf("the token extracts to %d bytes, want %d", got, size)
	}
	return e, tok
}

// TestTokenCache_theEntryBoundIsInclusive pins both sides of the entry
// bound: an extraction of exactly maxCachedEntryBytes is cached, one byte
// more is extracted on every request.
func TestTokenCache_theEntryBoundIsInclusive(t *testing.T) {
	for _, tc := range []struct {
		size int
		hits uint64
	}{{maxCachedEntryBytes, 1}, {maxCachedEntryBytes + 1, 0}} {
		e, tok := rolesToken(t, tc.size)
		e.cachedExtract(tok)
		e.cachedExtract(tok)
		if got := e.stats.Hits(); got != tc.hits {
			t.Errorf("an extraction of %d bytes: %d hits, want %d", tc.size, got, tc.hits)
		}
	}
}

// TestTokenCache_skipsCountAgainstTheEntryBound covers the extraction that
// finds nothing under a policy of many mappings: it carries a skip per
// mapping, and an entry of a few hundred skips is not cached.
func TestTokenCache_skipsCountAgainstTheEntryBound(t *testing.T) {
	plan := make([]compile.KeyExtraction, 400)
	for i := range plan {
		plan[i] = compile.KeyExtraction{Key: "k" + strings.Repeat("x", i%8), Path: []string{"bad"},
			Type: model.ValueStringArray}
	}
	e := &Engine{snap: &compile.Snapshot{Extraction: plan},
		cache: newTokenCache(DefaultTokenCacheSize, tokenCacheBytes), stats: &CacheStats{}}
	tok := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"bad":0}`)) + ".s"
	if _, skips := e.cachedExtract(tok); len(skips) != len(plan) {
		t.Fatalf("%d skips, want one per mapping, %d", len(skips), len(plan))
	}
	e.cachedExtract(tok)
	if hits := e.stats.Hits(); hits != 0 {
		t.Errorf("an extraction of %d skips was cached: %d hits", len(plan), hits)
	}
}

// TestNewCacheEntry_holdsOnlyWhatWasExtracted checks that an entry does not
// share the extraction's map or slices, and that an empty extraction keeps
// no map at all, whatever capacity identity.Extract gave its own.
func TestNewCacheEntry_holdsOnlyWhatWasExtracted(t *testing.T) {
	empty := make(map[string][]string, 400)
	if e := newCacheEntry(empty, nil, 0); e.keys != nil || e.skips != nil {
		t.Errorf("an empty extraction kept %v and %v", e.keys, e.skips)
	}
	keys := map[string][]string{"roles": {"a", "b"}}
	e := newCacheEntry(keys, nil, 0)
	keys["roles"][0] = "mutated"
	if e.keys["roles"][0] != "a" {
		t.Errorf("the entry shares the extraction's values: %v", e.keys)
	}
}

// TestEntrySize_isNeverUnderTheHeap fills a cache with entries of each shape,
// from an empty one to the array bound, and compares the estimate the byte
// budget counts with the heap they retain after the garbage collector. Each
// value is its own allocation, as a decoded claim is. The estimate may run
// over the heap, never under it, and not by more than half.
func TestEntrySize_isNeverUnderTheHeap(t *testing.T) {
	value := func(i, n int) string { return strings.Clone(fmt.Sprintf("%0*d", n, i)) }
	roles := func(i, count, n int) []string {
		out := make([]string, count)
		for j := range out {
			out[j] = value(i*100+j, n)
		}
		return out
	}
	for _, shape := range []struct {
		name string
		make func(i int) (map[string][]string, []identity.Skip)
	}{
		{"empty", func(int) (map[string][]string, []identity.Skip) { return nil, nil }},
		{"five skips", func(int) (map[string][]string, []identity.Skip) {
			return nil, []identity.Skip{{Key: "a"}, {Key: "b"}, {Key: "c"}, {Key: "d"}, {Key: "e"}}
		}},
		{"a subject", func(i int) (map[string][]string, []identity.Skip) {
			return map[string][]string{"sub": {value(i, 36)}}, nil
		}},
		{"a subject, a plan, 20 roles", func(i int) (map[string][]string, []identity.Skip) {
			return map[string][]string{"sub": {value(i, 36)}, "plan": {value(i, 6)}, "roles": roles(i, 20, 15)}, nil
		}},
		{"a subject, a plan, 40 long roles", func(i int) (map[string][]string, []identity.Skip) {
			return map[string][]string{"sub": {value(i, 36)}, "plan": {value(i, 6)}, "roles": roles(i, 40, 24)}, nil
		}},
		{"a subject, a plan, 64 short roles", func(i int) (map[string][]string, []identity.Skip) {
			return map[string][]string{"sub": {value(i, 36)}, "plan": {value(i, 6)}, "roles": roles(i, 64, 8)}, nil
		}},
		{"nine keys", func(i int) (map[string][]string, []identity.Skip) {
			keys := map[string][]string{}
			for k := range 9 {
				keys[fmt.Sprintf("k%d", k)] = []string{value(i, 10)}
			}
			return keys, nil
		}},
	} {
		const entries = 5000
		before := heapAlloc()
		c := newTokenCache(2*entries, 1<<40)
		estimate := 0
		for i := range entries {
			keys, skips := shape.make(i)
			size := entrySize(keys, skips)
			estimate += size
			var h [sha256.Size]byte
			h[0], h[1] = byte(i), byte(i>>8)
			c.store(h, newCacheEntry(keys, skips, size))
		}
		heap := int(heapAlloc() - before)
		runtime.KeepAlive(c)
		t.Logf("%s: estimate %d bytes per entry, heap %d", shape.name, estimate/entries, heap/entries)
		if estimate < heap || estimate > heap*3/2 {
			t.Errorf("%s: the estimate is %d bytes per entry, the heap %d", shape.name, estimate/entries, heap/entries)
		}
	}
}

// heapAlloc is the heap in use after two collections, the second of which
// frees what the first one's finalizers released.
func heapAlloc() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
