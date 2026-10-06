package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// rolesEngine is an engine with the token cache and one extracted key,
// roles, for the tests that size an extraction exactly.
func rolesEngine() *Engine {
	return &Engine{
		snap: &compile.Snapshot{Extraction: []compile.KeyExtraction{
			{Key: "roles", Path: []string{"roles"}, Type: model.ValueStringArray}}},
		cache: newTokenCache(DefaultTokenCacheSize, tokenCacheBytes),
		stats: &CacheStats{},
	}
}

// rolesToken is a token whose roles claim extracts to an entry of exactly
// size bytes, as entrySize counts it, spread over four values.
func rolesToken(t *testing.T, size int) string {
	t.Helper()
	const values = 4
	rest := size - entrySize(map[string][]string{"roles": {}}, nil) - values*valueOverhead
	roles := make([]string, values)
	for i := range roles {
		n := rest / (values - i)
		roles[i] = strings.Repeat(string(rune('a'+i)), n)
		rest -= n
	}
	raw, err := json.Marshal(map[string]any{"roles": roles})
	if err != nil {
		t.Fatal(err)
	}
	tok := "h." + base64.RawURLEncoding.EncodeToString(raw) + ".s"
	keys, _ := identity.Extract(rolesEngine().snap.Extraction, tok)
	if got := entrySize(keys, nil); got != size {
		t.Fatalf("the token extracts to %d bytes, want %d", got, size)
	}
	return tok
}

// TestTokenCache_theEntryBoundIsInclusive pins both sides of the entry
// bound: an extraction of exactly maxCachedEntryBytes is cached, one byte
// more is extracted on every request.
func TestTokenCache_theEntryBoundIsInclusive(t *testing.T) {
	for _, tc := range []struct {
		size int
		hits uint64
	}{{maxCachedEntryBytes, 1}, {maxCachedEntryBytes + 1, 0}} {
		e := rolesEngine()
		tok := rolesToken(t, tc.size)
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
