# Counter store contract

A document for the developer of the engine and of store implementations. The canon of the contract is the code of the
`engine/` module (the `store`, `algo`, `key`, and `store/storetest` packages); this is a map of it that makes the code
faster to read. A rule author does not need this document; that layer is described in the
[resource specification](ratelimitpolicy-cr-spec.md).

## Interfaces

```go
type Store interface {
    Decide(ctx, buckets []Bucket, cost int64) ([]Verdict, error)  // decide and charge
    Peek(ctx, buckets []Bucket, cost int64) ([]Verdict, error)    // decide without charging
    Reset(ctx, keys []string) error                               // reset the state
}

type Inspector interface {                       // management overview, separate from the decision path
    Scan(ctx, prefix, cursor string, limit int) (keys []string, next string, err error)  // one step of a walk
}
```

`Inspector` is deliberately separated from `Store`: enumeration is an expensive management operation, and the types
make it impossible to call it from the decision path. An implementation is free to provide both interfaces with one
type.

`Scan` walks the keys under a prefix one step at a time, so a caller holds one step of keys at once however many the
prefix covers. A step returns about `limit` keys, sorted, and the opaque cursor of the next step; an empty `next` ends
the walk, and a cursor the store cannot resume, malformed or minted for a Cluster node that has since left, is
`ErrBadCursor`. A step may return no key before the walk ends, where the prefix's keys are sparse in a keyspace shared
with other data. The walk is live rather than a snapshot: a key that exists for the whole walk is returned at least
once along the chain of cursors the steps return, and a step resumed with an earlier cursor has no such promise. A
limit below 1 is an error.

## Contract rules

| Rule | Reason |
| --- | --- |
| A decision is atomic: a refusal leaves no trace, an allowed request charges all enforcing buckets | charging one by one burns the daily quota with requests rejected by the per-minute limit |
| A shadow bucket is charged only on its own verdict | unconditional charging accumulates infinite debt, and the "would have rejected" metric lies |
| `cost < 1` is an error, nothing executes | a negative cost is a quota "refund" |
| A duplicate key in one decision is an error | two evaluations of one state in one commit lose one charge |
| An empty bucket list is not passed | a request outside the rules is allowed without a trip to the store |
| Time is taken from the store, not from the caller | engine replicas drift apart in their clocks; a shared bucket must not |
| State expires on its own (a TTL derived from the window) | there is no separate cleaner |
| `Reset` of missing keys is a successful no-op | management operations are retried |
| Windows arrive resolved and having passed `algo.Check` | the store does not re-validate; an unchecked window is undefined behavior |
| `Remaining` is non-negative; `CostExceedsCapacity` tells "will never fit" from "wait" | for a cost that can never fit, retry headers would be a lie |

A mismatch between the bucket and verdict lengths is a panic (`store.Admitted`): that is a broken implementation, not
the data.

## Math: integer microseconds

All arithmetic is in integer microseconds of Unix time: exact in int64 and in Lua's double (integers are representable
up to about the year 2255), comparisons without epsilons. The GCRA emission interval is rounded up, so the enforced
rate errs only toward the strict side; validation requires the period to be divisible at the resolution boundary and
caps the bucket depth at `burst × emission ≤ 10¹⁵ µs`: integers stay exact in Lua doubles (2⁵³ ≈ 9 × 10¹⁵), and the
`time.Duration` nanoseconds (10¹⁸ ns) keep headroom below the int64 ceiling. Fixed window aligns to Unix epoch
boundaries: a day is midnight UTC, an hour is on the hour. The state is parameter-independent: GCRA stores a
timestamp, fixed window stores the window start and a counter; `requests` and `burst` are tuned without re-bucketing.

## Keys

Only the `key` package builds keys: matching for decisions, management for reset and statistics, and both must match
byte for byte, otherwise a reset silently misses the live counters.

```text
rl:v1:{<namespace>/<domain>}:<block>/<rule>:<algorithm>:<window>:<axes...>:
```

Every segment is terminated with `:`, the last one included: a bucket key is the prefix of its own subtree, so scans
and partial resets need no hand-built prefixes. `DomainPrefix` enumerates a domain, `RulePrefix` resets a whole
rule, `Bucket` is the window key. The `{ns/domain}` hash tag keeps all buckets of a decision in one Redis Cluster
slot, which is what makes the atomic script valid on any
topology; an empty namespace or domain is a panic (an empty `{}` is not a tag for Redis). The component substitutes the
namespace segment (its own, via the Downward API): Redis is dedicated to the installation, and the segment is insurance
against two installations connecting to one store by mistake; the `/` separator is unambiguous, since it is forbidden
both in a domain and in a namespace name. There is no policy segment: a domain has one policy, and its name is the
domain itself. Gateways and filters take no part in the key shape. Axis values and names are escaped; the algorithm
segment is the passport name in lowercase.

## Algorithm passports

The Go side of an algorithm is a passport in the `algo` package: a numeric dispatch code, a name, a declaration of the
window fields it consumes, and semantic validation. The methods are unexported: an algorithm is added by editing the
module, and `Check` remains the only door into validation. Two passport invariants:

- **the key carries the name, not the code**: the code dispatches the server-side math over state that survives a
  deploy, so retired codes are never reused;
- **the state does not encode `Requests`/`Burst`**; otherwise tuning without re-bucketing breaks.

## The storetest contract suite

Every implementation plugs the suite in with one line:

```go
func TestContract(t *testing.T) {
    storetest.Run(t, func(t *testing.T) store.Store { return myimpl.New() })
}
```

The suite checks the properties the type system cannot see: all-or-nothing, `Peek` does not spend, a refusal does not
move state (regular and shadow), an impossible cost is flagged and not charged, a non-positive cost and duplicates are
rejected, reset and its idempotence, verdict order, fixed window counting, enumeration by prefix (if there is an
`Inspector`). Fixture keys carry a hash tag, so the suite also runs through Cluster.

The suite's honest limitations: "a refusal does not spend" is observable only through GCRA (with fixed window, an extra
increment is invisible until the window boundary and harmless after it); TTL expiry is not checked quickly, it is a
line of the contract and a separate implementation test; the window-boundary guard is computed by the local clock, best
effort.

## Implementations

**In-memory** (`store/memory`) is the reference client of the suite and a dev-only backend, for the local stand and
tests: counters live in the replica's memory, N replicas give an N-fold limit, so the chart never renders it; a
service started without `--redis-dbaas-microservice` counts there. Its math mirrors the server-side script formula for
formula; expiry is lazy (stale state is discarded on touch and in `Scan`).

**Redis** (`store/redis`) is one Lua script per decision: evaluate all buckets, commit only if no enforcing bucket
refused. GCRA is ported from go-redis/redis_rate (BSD-2-Clause), and that library remains the
single-bucket oracle; differential tests stitch the Lua to the in-memory reference. `Scan` is one `SCAN` per step: on
a Cluster it reads the master that owns the prefix's hash tag, where every key of a domain lives, and every master in
address order for a prefix without one; the cursor names its node, so a cursor from before a slot moved is refused
rather than resumed on the wrong node. The suite runs against standalone and Cluster; Sentinel (`masterName` in the
chart) is best effort and is not covered by the suite.
