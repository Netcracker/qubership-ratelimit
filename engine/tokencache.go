package engine

import (
	"crypto/sha256"
	"maps"
	"slices"
	"sync"

	"github.com/netcracker/qubership-ratelimit/engine/identity"
)

// tokenCache memoizes identity extraction per token. Extraction is a pure
// function of the token bytes and the snapshot's plan, and the cache lives
// inside one Engine, so a snapshot swap retires it with the engine value —
// no epochs, and no TTL: an entry can lose relevance, never validity.
//
// Tokens are keyed by their SHA-256; the cache must not retain raw token
// bytes. Eviction is generational: when the current generation fills, it
// becomes the previous one and the oldest generation drops, so the cache
// never holds more than its capacity, and a token in active use survives
// rotation through promotion on hit. Distinct tokens minted freely by an
// attacker churn the generations; the worst case that buys is the uncached
// extraction cost per request, never an error.
type tokenCache struct {
	mu     sync.RWMutex
	half   int  // per-generation bound: half of the configured capacity
	single bool // capacity 1: one generation, rotation drops instead of aging
	cur    map[[sha256.Size]byte]cacheEntry
	prev   map[[sha256.Size]byte]cacheEntry
}

// cacheEntry is one extraction result. The map inside is owned by the cache
// and never handed out: lookups clone.
type cacheEntry struct {
	keys  map[string][]string
	skips []identity.Skip
}

func newTokenCache(capacity int) *tokenCache {
	c := &tokenCache{half: capacity / 2}
	if capacity < 2 {
		c.half, c.single = 1, true
	}
	c.cur = make(map[[sha256.Size]byte]cacheEntry, c.half)
	return c
}

// lookup returns the entry for h. A previous-generation hit is promoted into
// the current one, so tokens in active use survive rotation.
func (c *tokenCache) lookup(h [sha256.Size]byte) (cacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.cur[h]
	if ok {
		c.mu.RUnlock()
		return e, true
	}
	e, ok = c.prev[h]
	c.mu.RUnlock()
	if !ok {
		return cacheEntry{}, false
	}
	c.store(h, e)
	return e, true
}

// store inserts an entry, rotating generations when the current one is full.
func (c *tokenCache) store(h [sha256.Size]byte, e cacheEntry) {
	c.mu.Lock()
	if _, exists := c.cur[h]; !exists && len(c.cur) >= c.half {
		if !c.single {
			c.prev = c.cur
		}
		c.cur = make(map[[sha256.Size]byte]cacheEntry, c.half)
	}
	c.cur[h] = e
	c.mu.Unlock()
}

// cachedExtract is identity.Extract behind the token cache. Results cross
// the cache boundary as clones in both directions: the facade overlays
// explicit request keys onto the map it gets back, and a shared map would
// let one request's overlay poison every later hit.
//
// The size bound comes before the hash: an oversized token is undecodable by
// contract, and hashing attacker-sized input — or spending cache slots on it
// — would cost more than the extraction the cache is there to avoid.
func (e *Engine) cachedExtract(token string) (map[string][]string, []identity.Skip) {
	if e.cache == nil || len(e.snap.Extraction) == 0 ||
		token == "" || len(token) > identity.MaxTokenBytes {
		return identity.Extract(e.snap.Extraction, token)
	}
	h := sha256.Sum256([]byte(token))
	if entry, ok := e.cache.lookup(h); ok {
		return maps.Clone(entry.keys), slices.Clone(entry.skips)
	}
	keys, skips := identity.Extract(e.snap.Extraction, token)
	e.cache.store(h, cacheEntry{keys: maps.Clone(keys), skips: slices.Clone(skips)})
	return keys, skips
}
