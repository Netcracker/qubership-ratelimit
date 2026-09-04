// Package key builds counter keys. It is the only place that knows their
// shape: matching builds keys to decide, management builds them to reset and
// inspect, and the two must agree to the byte or resets silently miss live
// counters.
package key

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
)

// schemaVersion names the key layout. It changes when the layout does, so two
// layouts never collide in one store: old keys expire on their own TTL.
const schemaVersion = "v1"

// Ident names one rule's bucket space within a domain. The parts are escaped
// like axis values: the resource schema constrains them too, but a key must
// not depend on a validation layer the library cannot see.
//
// There is no policy part: a domain has exactly one policy and its name is the
// domain, so block and rule already name a bucket space uniquely.
type Ident struct {
	Namespace string
	Domain    string
	Block     string
	Rule      string
}

// RatePrefix returns the constant prefix of every bucket key of one rate:
// domain, rule identity, algorithm, and window. Compilation builds it once;
// the request path only appends axis values through Bucket.
//
// The window must have passed algo.Check: an unvalidated sub-second period
// would truncate into a colliding prefix.
func RatePrefix(id Ident, a algo.Algorithm, w algo.Window) string {
	return RulePrefix(id) + strings.ToLower(a.Name()) + ":" +
		strconv.FormatInt(int64(w.Period/time.Second), 10) + ":"
}

// Bucket completes a rate prefix with axis values in axis order. The hash
// tag lives in the domain prefix, so every bucket of a decision shares one
// Redis Cluster slot and the store can commit the whole decision as one
// atomic script; other stores see the braces as opaque bytes.
//
// Every segment is terminated, the last one included, so a bucket key is also
// the prefix of its own subtree: the same string addresses the exact bucket
// and safely scopes scans and partial resets — leading axes cover the buckets
// sharing them, and "alice" never matches "alice2", because the terminator is
// part of the string.
//
// Axis values are non-empty by construction: an absent axis means the rule
// did not match and no bucket was built.
func Bucket(prefix string, axes []string) string {
	if len(axes) == 0 {
		return prefix
	}
	var b strings.Builder
	b.Grow(len(prefix) + 16*len(axes))
	b.WriteString(prefix)
	for _, v := range axes {
		b.WriteString(escape(v))
		b.WriteByte(':')
	}
	return b.String()
}

// RulePrefix returns the prefix shared by every bucket of a rule — every
// algorithm, window, and axis combination — for enumeration and whole-rule
// reset.
func RulePrefix(id Ident) string {
	return DomainPrefix(id.Namespace, id.Domain) +
		escape(id.Block) + "/" + escape(id.Rule) + ":"
}

// DomainPrefix returns the prefix shared by every counter key of a domain, for
// management-side enumeration: usage per domain and the list of currently
// limited keys. Hand-building this prefix is what this package exists to
// prevent.
//
// The namespace and the domain are wrapped in one hash tag: a decision spans
// several buckets, and pinning them to one Redis Cluster slot is what lets the
// store commit them in one atomic script. The price, accepted deliberately, is
// that one domain's throughput is bounded by one shard; domains spread across
// shards freely.
//
// The namespace is the component's own, taken from the Downward API. A Redis
// is dedicated to one installation, and this segment is the insurance against
// two installations reaching the same store by mistake: the "/" separator is
// unambiguous, being forbidden in a domain and in a namespace name alike.
//
// An empty namespace or domain panics: Redis treats an empty "{}" as no hash
// tag at all, the decision's buckets would scatter across slots, and the atomic
// script would fail. Neither is ever empty in a running component, so this is a
// caller bug, not data.
func DomainPrefix(namespace, domain string) string {
	if namespace == "" || domain == "" {
		panic("key: an empty namespace or domain would produce an empty hash tag" +
			" and scatter a decision across cluster slots")
	}
	return "rl:" + schemaVersion + ":{" + escape(namespace) + "/" + escape(domain) + "}:"
}

// escape percent-encodes the characters the key schema reserves, for axis
// values and identifier parts alike. Axis values come from token claims, so an
// attacker-shaped value must not be able to forge segment boundaries or a hash
// tag; identifier parts are schema-constrained, but the key does not lean on a
// validation layer it cannot see.
func escape(v string) string {
	if !strings.ContainsAny(v, "%:/{}") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '%', ':', '/', '{', '}':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
