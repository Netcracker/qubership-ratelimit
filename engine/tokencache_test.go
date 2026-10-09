package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
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
	for _, c := range []struct {
		name     string
		capacity int
	}{
		{"capacity 1, a single generation", 1},
		{"capacity 2", 2},
		{"capacity 3, rounding the generations down", 3},
		{"capacity 10", 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			cache := newTokenCache(c.capacity, tokenCacheBytes)
			for i := range 100 {
				cache.store(hashOf(i), cacheEntry{})
				if got := len(cache.cur) + len(cache.prev); got > c.capacity {
					t.Fatalf("after %d inserts the cache retains %d entries, want at most %d", i+1, got, c.capacity)
				}
			}
		})
	}
}

// A token found in the previous generation is promoted into the current one,
// so a token in active use survives the next rotation, while the token stored
// beside it and never read again is dropped by it.
func TestTokenCache_aHitInThePreviousGenerationSurvivesTheNextRotation(t *testing.T) {
	c := newTokenCache(4, tokenCacheBytes) // two entries a generation
	c.store(hashOf(0), cacheEntry{})
	c.store(hashOf(1), cacheEntry{})
	c.store(hashOf(2), cacheEntry{}) // rotates 0 and 1 into the previous generation
	if _, ok := c.lookup(hashOf(0)); !ok {
		t.Fatal("precondition: lookup(0) after the first rotation missed, want a hit in the previous generation")
	}

	// Two more tokens rotate the generations again.
	c.store(hashOf(3), cacheEntry{})
	c.store(hashOf(4), cacheEntry{})

	if _, ok := c.lookup(hashOf(0)); !ok {
		t.Error("after the next rotation, lookup(0) of the token read in between missed, want a hit")
	}
	if _, ok := c.lookup(hashOf(1)); ok {
		t.Error("after the next rotation, lookup(1) of the token never read again hit, want a miss")
	}
}

// hashOf is a distinct token hash for each i below 65536.
func hashOf(i int) [sha256.Size]byte {
	var h [sha256.Size]byte
	h[0], h[1] = byte(i), byte(i>>8)
	return h
}

// storeWithinBudget stores 100 entries of size bytes and fails the test as
// soon as the two generations together hold more than budget.
func storeWithinBudget(t *testing.T, c *tokenCache, budget, size int) {
	t.Helper()
	for i := range 100 {
		c.store(hashOf(i), cacheEntry{size: size})
		held := 0
		for _, e := range c.cur {
			held += e.size
		}
		for _, e := range c.prev {
			held += e.size
		}
		if held > budget {
			t.Fatalf("after %d inserts of %d bytes the cache retains %d bytes, want at most %d", i+1, size, held, budget)
		}
	}
}

// TestTokenCache_neverExceedsItsByteBudget fills the cache with entries
// whose bytes, not their count, reach the bound first: the two generations
// together never hold more than the budget.
func TestTokenCache_neverExceedsItsByteBudget(t *testing.T) {
	const budget, size = 10_000, 900
	t.Run("a single generation", func(t *testing.T) {
		storeWithinBudget(t, newTokenCache(1, budget), budget, size)
	})
	t.Run("two generations rotated by their bytes", func(t *testing.T) {
		c := newTokenCache(1000, budget)
		storeWithinBudget(t, c, budget, size)
		if len(c.prev) == 0 {
			t.Errorf("100 entries of %d bytes in a cache of 1000 entries and %d bytes: no generation rotated, "+
				"want the byte bound to rotate one", size, budget)
		}
	})
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
	for _, c := range []struct {
		name string
		size int
		hits uint64
	}{
		{"an extraction of exactly maxCachedEntryBytes", maxCachedEntryBytes, 1},
		{"an extraction one byte past maxCachedEntryBytes", maxCachedEntryBytes + 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, tok := rolesToken(t, c.size)
			e.cachedExtract(tok)
			e.cachedExtract(tok)
			if got := e.stats.Hits(); got != c.hits {
				t.Errorf("an extraction of %d bytes, made twice: %d hits, want %d", c.size, got, c.hits)
			}
		})
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

// An empty extraction keeps no map at all, whatever capacity identity.Extract
// gave its own.
func TestNewCacheEntry_keepsNoMapForAnEmptyExtraction(t *testing.T) {
	if e := newCacheEntry(make(map[string][]string, 400), nil, 0); e.keys != nil || e.skips != nil {
		t.Errorf("newCacheEntry(an empty map of capacity 400, no skips) holds %#v and %#v, want nil and nil",
			e.keys, e.skips)
	}
}

func TestNewCacheEntry_sharesNoValuesWithTheExtraction(t *testing.T) {
	keys := map[string][]string{"roles": {"a", "b"}}
	e := newCacheEntry(keys, nil, 0)
	keys["roles"][0] = "mutated"

	if got, want := e.keys["roles"], []string{"a", "b"}; !slices.Equal(got, want) {
		t.Errorf("after the extraction's roles changed, the entry holds roles %q, want %q", got, want)
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
		t.Run(shape.name, func(t *testing.T) {
			const entries = 5000
			before := heapAlloc()
			c := newTokenCache(2*entries, 1<<40)
			estimate := 0
			for i := range entries {
				keys, skips := shape.make(i)
				size := entrySize(keys, skips)
				estimate += size
				c.store(hashOf(i), newCacheEntry(keys, skips, size))
			}
			heap := int(heapAlloc() - before)
			runtime.KeepAlive(c)
			t.Logf("estimate %d bytes per entry, heap %d", estimate/entries, heap/entries)
			if estimate < heap || estimate > heap*3/2 {
				t.Errorf("entrySize estimates %d bytes per entry, the heap holds %d; want from the heap to 1.5 times it",
					estimate/entries, heap/entries)
			}
		})
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
