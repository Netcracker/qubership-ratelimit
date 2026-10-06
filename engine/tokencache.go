package engine

import (
	"crypto/sha256"
	"maps"
	"slices"
	"sync"
	"unsafe"

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
//
// The capacity bounds the entries and tokenCacheBytes bounds their size, so
// neither a stream of distinct tokens with large claims nor a policy with
// many mappings can hold the cache past a replica's memory limit.
type tokenCache struct {
	mu        sync.RWMutex
	half      int  // per-generation bound: half of the configured capacity
	halfBytes int  // per-generation bound: half of tokenCacheBytes
	single    bool // capacity 1: one generation, rotation drops instead of aging
	cur       map[[sha256.Size]byte]cacheEntry
	prev      map[[sha256.Size]byte]cacheEntry
	curBytes  int // the size of the entries in cur
}

// cacheEntry is one extraction result. The map inside is owned by the cache
// and never handed out: lookups clone.
type cacheEntry struct {
	keys  map[string][]string
	skips []identity.Skip
	size  int // the estimate of entrySize, counted against the byte bounds
}

// tokenCacheBytes bounds the heap one domain's cache retains, by the estimate
// of entrySize. A realistic extraction, a subject, a plan, and twenty roles,
// retains about 1.3 KiB, so the budget holds about 5 600 of them.
const tokenCacheBytes = 8 << 20

// maxCachedEntryBytes bounds one entry. It admits a realistic extraction with
// room to spare, forty roles of 24 bytes estimate to about 2.8 KiB; a larger
// one is extracted every time instead of being cached, which costs only the
// work the identity layer's shape bounds already cap, and leaves the budget
// to the tokens that repeat.
const maxCachedEntryBytes = 4 << 10

// The overheads entrySize adds to the bytes of the keys and values, fitted to
// the heap an entry retains on a 64-bit platform: the entry's slot in a
// generation with its hash, the keys map, which costs about 400 bytes as soon
// as it holds one key, a key's slot with its slice of values, a value's string
// header, and one skip. A value's bytes are rounded up to valueAlign, the
// allocator's smallest size-class step. Measured against the heap after the
// garbage collector, the estimate is 3 to 22 percent over it for every shape
// from an empty entry to 64 values; see TestEntrySize_isNeverUnderTheHeap.
const (
	entryOverhead = 160
	mapOverhead   = 384
	keyOverhead   = 64
	valueOverhead = 16
	valueAlign    = 16
	skipOverhead  = int(unsafe.Sizeof(identity.Skip{}))
)

// entrySize estimates the heap an entry holding keys and skips retains, the
// map and the skips included: an extraction that found nothing for a policy
// of many mappings still carries a skip per mapping.
func entrySize(keys map[string][]string, skips []identity.Skip) int {
	n := entryOverhead + len(skips)*skipOverhead
	if len(keys) > 0 {
		n += mapOverhead
	}
	for key, values := range keys {
		n += keyOverhead + len(key)
		for _, v := range values {
			n += valueOverhead + (len(v)+valueAlign-1)/valueAlign*valueAlign
		}
	}
	return n
}

// newCacheEntry copies an extraction into an entry sized for what it holds,
// and shares no map or slice with it. maps.Clone would keep the capacity the
// extraction's map grew to, which entrySize does not see.
func newCacheEntry(keys map[string][]string, skips []identity.Skip, size int) cacheEntry {
	e := cacheEntry{size: size}
	if len(keys) > 0 {
		e.keys = make(map[string][]string, len(keys))
		for key, values := range keys {
			e.keys[key] = slices.Clone(values)
		}
	}
	if len(skips) > 0 {
		e.skips = slices.Clone(skips)
	}
	return e
}

func newTokenCache(capacity, budget int) *tokenCache {
	c := &tokenCache{half: capacity / 2, halfBytes: budget / 2}
	if capacity < 2 {
		c.half, c.halfBytes, c.single = 1, budget, true
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

// store inserts an entry, rotating generations when the current one is full
// by its entries or by its bytes.
func (c *tokenCache) store(h [sha256.Size]byte, e cacheEntry) {
	c.mu.Lock()
	if _, exists := c.cur[h]; !exists {
		if len(c.cur) >= c.half || c.curBytes+e.size > c.halfBytes {
			if !c.single {
				c.prev = c.cur
			}
			c.cur = make(map[[sha256.Size]byte]cacheEntry, c.half)
			c.curBytes = 0
		}
		c.curBytes += e.size
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
		if e.stats != nil {
			e.stats.hits.Add(1)
		}
		return maps.Clone(entry.keys), slices.Clone(entry.skips)
	}
	if e.stats != nil {
		e.stats.misses.Add(1)
	}
	keys, skips := identity.Extract(e.snap.Extraction, token)
	if size := entrySize(keys, skips); size <= maxCachedEntryBytes {
		e.cache.store(h, newCacheEntry(keys, skips, size))
	}
	return keys, skips
}
