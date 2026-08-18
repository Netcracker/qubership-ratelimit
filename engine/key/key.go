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
type Ident struct {
	Domain string
	Policy string
	Block  string
	Rule   string
}

// Bucket returns the key of one window of one rule, keyed by axis values in
// axis order. The hash tag lives in the domain prefix, so every bucket of a
// decision shares one Redis Cluster slot and the store can commit the whole
// decision as one atomic script; other stores see the braces as opaque bytes.
// A bucket with no axes has no axis segments. Windows must have passed
// algo.Check: building runs on the request path and does not revalidate, and
// an unvalidated sub-second period would truncate into a colliding key. Axis
// values are non-empty by construction: an absent axis means the rule did not
// match and no bucket was built.
func Bucket(id Ident, a algo.Algorithm, w algo.Window, axes []string) string {
	var b strings.Builder
	b.WriteString(RulePrefix(id))
	b.WriteString(strings.ToLower(a.Name()))
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(int64(w.Period/time.Second), 10))
	for _, v := range axes {
		b.WriteByte(':')
		b.WriteString(escape(v))
	}
	return b.String()
}

// RulePrefix returns the prefix shared by every bucket of a rule — every
// algorithm, window, and axis combination — for enumeration and whole-rule
// reset.
func RulePrefix(id Ident) string {
	return DomainPrefix(id.Domain) +
		escape(id.Policy) + "/" + escape(id.Block) + "/" + escape(id.Rule) + ":"
}

// DomainPrefix returns the prefix shared by every counter key of a domain, for
// management-side enumeration: usage per domain and the list of currently
// limited keys. Hand-building this prefix is what this package exists to
// prevent.
//
// The domain is wrapped in a hash tag: a decision spans several buckets, and
// pinning a domain's counters to one Redis Cluster slot is what lets the store
// commit them in one atomic script. The price, accepted deliberately, is that
// one domain's throughput is bounded by one shard; domains spread across
// shards freely.
//
// An empty domain panics: Redis treats an empty "{}" as no hash tag at all,
// the decision's buckets would scatter across slots, and the atomic script
// would fail. The schema never produces an empty domain, so this is a caller
// bug, not data.
func DomainPrefix(domain string) string {
	if domain == "" {
		panic("key: empty domain would produce an empty hash tag and scatter a decision across cluster slots")
	}
	return "rl:" + schemaVersion + ":{" + escape(domain) + "}:"
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
