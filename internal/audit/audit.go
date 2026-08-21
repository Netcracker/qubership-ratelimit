// Package audit carries the decision audit stream: a per-rule record of what
// the engine decided and why, for the rules an operator has asked about.
//
// It sits between the decision path, which produces records, and the
// management API, which selects the rules and serves the stream. Both import
// this package so neither has to import the other.
//
// The stream is off for every rule until someone turns it on. At gateway
// speed a record per decision is a firehose — one per request per matching
// rule, on every replica — so enabling it is a deliberate act against a named
// rule, and nothing here starts emitting on its own.
package audit

import (
	"sync"
	"sync/atomic"
	"time"
)

// Verdicts a record can carry.
const (
	VerdictAllowed = "allowed"
	VerdictRefused = "refused"
)

// Record is one rule's decision about one request.
//
// It deliberately carries no token and no raw path: the path is sanitized by
// the caller before it arrives, and the token never leaves the identity layer.
// What it does carry is the rule, the verdict, and the budget left, which is
// what someone debugging "why was this refused" is looking for.
type Record struct {
	Time time.Time `json:"time"`

	Domain string `json:"domain"`
	RuleID string `json:"ruleId"`

	Verdict string `json:"verdict"`
	Shadow  bool   `json:"shadow"`

	Limit     int64 `json:"limit"`
	Remaining int64 `json:"remaining"`

	RetryAfterSeconds float64 `json:"retryAfterSeconds,omitempty"`

	// Path and Method describe the request. Path arrives with its query string
	// already redacted.
	Path   string `json:"path,omitempty"`
	Method string `json:"method,omitempty"`

	// RequestID ties the record to the gateway's access log for the same
	// request.
	RequestID string `json:"requestId,omitempty"`

	// Replica names the pod that decided. Each replica streams only its own
	// decisions, so a reader watching one connection sees a share of the
	// traffic, not all of it — the field is what makes that legible.
	Replica string `json:"replica,omitempty"`
}

// Selector decides which rules are streamed. The decision path asks before
// building a record, so a rule nobody selected costs one map lookup.
type Selector interface {
	Enabled(domain, policy, block, rule string) bool
}

// subscriberBuffer is how many records a slow reader may fall behind before
// its records start being dropped. A browser on a good connection keeps up
// with a busy rule; one on a bad connection must not be able to slow the
// decision path down, so the buffer is where the backpressure stops.
const subscriberBuffer = 256

// Hub fans records out to whoever is watching.
//
// Publishing never blocks and never fails. The decision path calls it while
// answering a rate limit check, so a subscriber that cannot keep up loses
// records rather than delaying a gateway — the subscription reports how many,
// so a reader is told its view has gaps instead of quietly seeing a filtered
// stream.
type Hub struct {
	mu   sync.Mutex
	next uint64
	subs map[uint64]*Subscription
}

// Subscription is one reader's view of the stream.
type Subscription struct {
	records chan Record
	dropped atomic.Uint64
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[uint64]*Subscription)}
}

// Publish offers a record to every subscriber, dropping it for those that are
// behind.
func (h *Hub) Publish(record Record) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sub := range h.subs {
		select {
		case sub.records <- record:
		default:
			sub.dropped.Add(1)
		}
	}
}

// Subscribers reports how many readers are attached, which is what lets the
// decision path skip building records nobody will read.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Subscribe attaches a reader. The returned function detaches it and must be
// called, or the hub keeps publishing into a channel nobody reads.
func (h *Hub) Subscribe() (*Subscription, func()) {
	sub := &Subscription{records: make(chan Record, subscriberBuffer)}

	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = sub
	h.mu.Unlock()

	return sub, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs, id)
	}
}

// Records is the channel to read from. It is never closed: the reader stops
// when its own context ends, which is the only thing that ends an HTTP stream.
func (s *Subscription) Records() <-chan Record { return s.records }

// Dropped reports how many records this subscriber missed because it was
// behind.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }
