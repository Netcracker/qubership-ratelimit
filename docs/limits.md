# Limits and their origin

All numbers that constrain a policy, in one place, with a note on where each one comes from and who checks it. There
are three sources: **engine constants** (the decision budget, window math), which the operator's compiler holds and
reflects in the status; **the physical walls of Kubernetes** (the client-side apply annotation, the etcd object), which
the API server holds; and **value formats** (patterns, ranges, uniqueness), which the CRD schema holds. There are no
bounds for the validator's sake: the only CEL rule on the CRD is `metadata.name == spec.domain`, it walks no lists, and
no list needs `maxItems`.

## Summary table

| Level | What is bounded | Number | Where from | Who checks |
| --- | --- | --- | --- | --- |
| **Policy** | buckets of one decision, the decision of one descriptor (worst case) | ≤ 128 | depth of one atomic Lua call, `MaxDomainDecisionBuckets` | the compiler, `DomainBudgetExceeded`; runtime backstop |
| | object size | ~256 KiB under client-side `apply`, 1.5 MiB in etcd | the `last-applied-configuration` annotation, `--max-request-bytes` | the API server |
| | blocks, rules, groups, clients, mapping keys | unbounded | object size only; the number of blocks is an observed metric | — |
| **Namespace** | the compressed configuration of all domains, the ConfigMap `ratelimit-config` | ≤ 1 MiB compressed total | the Kubernetes object size limit of a ConfigMap | the operator before the write, `ConfigMapTooLarge`; last-good stays enforced |
| **Call** | descriptors of one gRPC check | ≤ 16 | every descriptor is its own decision and its own store trip; a gateway sends one | the adapter, `too_many_descriptors` → `OVER_LIMIT` |
| **Block** | rules, routes | unbounded | object size only | — |
| | route methods | enum: the 8 RFC 9110 methods + `PATCH` (RFC 5789) | closed set; a method outside the enum matches only routes without `methods` | enum, `listType: set` |
| | route path | ≤ 2048 characters | the conventional URL length limit | `maxLength` |
| **Rule** | windows (`rates`) | unbounded; periods are unique | per decision, the bucket budget cuts them | `listType: map` by `periodSeconds` |
| | axes, predicates, `In` values, `replacedRules` | unbounded | object size only; key length is the author's concern | — |
| **Window** | `periodSeconds` | 1..86400 | whole seconds per the API convention; a day is the ceiling for rate limiting, beyond that it is a quota | `minimum`/`maximum` |
| | `requests`, `burst` | 1..2 147 483 647 | int32 with explicit bounds | `minimum`/`maximum` |
| | GCRA: resolution | `requests ≤ periodSeconds × 10⁶` (≤ 1 million/s) | whole microseconds in Lua | the compiler, `algo.Check` |
| | GCRA: divisibility | with an emission interval < 100 µs, the period divides evenly by `requests` | emission rounding ≤ 1 % | the compiler, `algo.Check` |
| | GCRA: depth | `burst × emission ≤ 10¹⁵ µs` | int64 protection | the compiler, `algo.Check` |
| **Names** | domain, block, rule, group | ≤ 63, DNS-1123 pattern / `[a-z0-9._-]` | counter key segments without `:`/`{`/`}`/`/` | pattern, `maxLength` |
| | descriptor keys: `mappings[].key`, placeholders, `matches[].key`, `counters[]` | ≤ 63, one pattern `^[a-z][a-zA-Z0-9_]*$` (camelCase allowed) | one pattern wherever a key is mentioned; enters the counter key as a segment | pattern, `maxLength` |
| | predicate values, clients, claim paths | ≤ 256 | the engine's sanitary limit on an extracted value (`MaxValueBytes`): a longer literal can never match | `maxLength` |
| **Key** | axis values | escaped; token sanity limits | engine constants | the engine |

## Object size: the physical walls

The number of rules, groups, and clients is bounded by nothing except the object size, and there are two walls:

1. **Client-side `kubectl apply`** writes a full copy of the manifest into the
   `kubectl.kubernetes.io/last-applied-configuration` annotation, and the API server bounds the total annotation size
   at **256 KiB**: the `TotalAnnotationSizeLimitB` constant, not configurable. A larger object fails on `apply` with
   `metadata.annotations: Too long: must have at most 262144 bytes`. Projects place policies exactly this way.
2. **etcd** accepts an object of up to **1.5 MiB** (`--max-request-bytes`); the safe zone, with headroom for auxiliary
   fields, is ~700 KiB. This wall is reachable only through server-side apply (Helm, Argo CD with SSA,
   `kubectl apply --server-side`), where there is no annotation.

Rule weight was measured on the real types in JSON: **283 bytes** typical (a predicate, an axis, two windows),
**543 bytes** dense (three predicates with `values`, two axes, two windows with `burst`, `replacedRules`); a group of
1024 UUIDs is ~40 KiB. Hence the object capacity:

| Wall | Typical profile | Dense profile |
| --- | --- | --- |
| client-side apply, 256 KiB | ~900 rules | ~470 rules (minus groups: 1024 clients ≈ 75 dense rules) |
| etcd, safe ~700 KiB | ~2500 rules | ~1300 rules |

A policy that covers one API with a handful of rules and a couple of client groups weighs a few kilobytes, so these
walls are reached only by a domain that collects many APIs behind one gateway.

### The compressed configuration of a namespace

The operator writes the validated spec of every domain of the namespace into one ConfigMap, `ratelimit-config`, as a
gzip-compressed `<domain>.json.gz` key per domain next to a plain `manifest` key. A ConfigMap holds at most 1 MiB
(1048576 bytes) across its values, so the compressed total of all domains of the namespace, with the manifest, is
bounded by 1 MiB. The wall is per namespace, not per policy, and compression decides how far away it is. Rules compress
about 20 to 40 times, so a policy of rules reaches the walls above first. A client list of UUIDs compresses only about
1.8 times, and about 45000 UUIDs across the policies of a namespace fill the object. The operator checks the compressed
total before it writes. A generation that does not fit is reported with `Ready: False`, `Stalled: True`, and reason
`ConfigMapTooLarge`, distinct from `NotCompiled`, and the last-good generation of that domain stays enforced
([the resource specification](ratelimitpolicy-cr-spec.md)). On the reading side a replica decompresses each payload
through a bound of 8 MiB, eight times the whole object: a corrupt or hand-edited value that expands past it is refused,
with the reason on `/debug/applied`, instead of growing the heap until the process is killed.

## Decision budget: 128 buckets

A bucket is one counter that the engine must check and charge while deciding the fate of one request: a matched rule
contributes one bucket per window it has. A decision is the fate of one descriptor, and the buckets of one decision
are checked and charged in one atomic Lua call; 128 is the ceiling of that call. The budget binds the decision, not
the gRPC check: a gateway sends one descriptor per request, a direct consumer may send several, and each is decided
and stored on its own. The check is bounded on its own axis, by the adapter: at most 16 descriptors, refused past that
before any decision is made. The worst case of one check is therefore 16 scripts of 128 buckets, never one script of
2048; an unbounded worst case on either axis would let one check monopolize the domain's shard.

The compiler computes the worst case statically: an `All` block contributes the sum of windows across all its rules
(all may match at once), a `FirstMatch` block the maximum windows of one rule plus all `Shadow` rules; the sum over all
blocks of the object. A generation above 128 is invalid as a whole: `DomainBudgetExceeded`, and last-good stays in
effect. The formula also adds up blocks with non-overlapping targets, so it is pessimistic: a domain whose blocks
target different APIs is charged for all of them even though one request reaches only one. The runtime backstop counts
the decision's real buckets and is unreachable in normal operation.

The consequence for a domain built out of `All` blocks is that it hits 128 long before the object size. With eight
counting rules per API, that is roughly 16 APIs behind one gateway with minute windows, and 8 once every rule also
carries an hour window.

## Blocks, axes, windows: why no bounds

The only thing a bound on blocks would protect against is the linear scan of targets on every request (~20 ns per
target). But there are never more blocks than rules, and never more rules than the object holds: even 2 500 targets
under server-side apply take ~50 µs against a storeless decision budget of p99 ≤ 1 ms. The object size keeps the scan
cheap by itself; the number of blocks is an observed metric, `ratelimit_domain_blocks`, and a scan benchmark in CI,
not a validation rule. There is nothing to bound axes and windows with either: the bucket budget cuts the windows per
request, and a long key made of many axes is the author's cardinality problem, not the engine's.

## Window bounds

From the engine's `algo.Check`; the refusal arrives in the status as `InvalidWindow`:

- `periodSeconds` is an integer from 1 to 86 400 (a day), the only window bound the schema holds; in Lua the period is
  whole microseconds (`periodSeconds × 10⁶`);
- GCRA computes in whole microseconds: no more than one request per microsecond (`requests ≤ periodSeconds × 10⁶`);
- with an emission interval shorter than 100 µs (faster than 10 000/s per bucket) the period must divide evenly by
  `requests`: below this bound, rounding the emission to a microsecond distorts the rate by more than 1 %;
- the bucket depth `burst × (period / requests)` is ≤ 10¹⁵ µs (~31 years), so the depth arithmetic and the duration
  conversions stay far from int64 overflow;
- FixedWindow has no additional math.

## Why content is not checked by CEL at admission

Measured on envtest (k8s 1.36): a CRD with root-level CEL rules for references, types, groups, the bucket budget, and
GCRA math registers, but only with list bounds that exist solely for the cost estimator. The estimate of **any** rule
is multiplied by the cardinality of its ancestors, the product of `maxItems` along the path to it: a window-level rule
runs up to `blocks × rules × 4` times, a predicate-level rule up to `blocks × rules × 8` (4 windows and 8
predicates in the measured schema). The API server limits: 10 M per expression, 100 M per CRD.

| Bounds (blocks × rules) | Cardinality | Result |
| --- | --- | --- |
| 256 × 64 | 16 k | passes |
| 256 × 128 | 32 k | passes only after the quadratic uniqueness checks are replaced with list types |
| 512 × 128 | 64 k | rejected at 1.6× on the GCRA rule |
| ~87 k | — | the ceiling of the total CRD budget; beyond it nothing helps |

Without `maxItems` on every list the API server does not register such rules at all. So content validation at
admission would cost a bound for the estimator's sake on every list and a second copy of the compiler's rules in
another language, and would give one thing in return: a message on `apply` instead of a status. The compiler checks
the same things on every generation, identically on all replicas, and answers `Accepted: False` with the address of
the rule; last-good holds the traffic.

## Store and key capacity

- **Redis** does not bound the keys: their number is determined by the axes (`counters: [client]` gives one counter
  per client), and the TTL by the window period. All keys of a domain share one slot (hash tag `{ns/domain}`): the
  domain's throughput is bounded by one shard; the reference point is ~80 k decisions/s with one bucket, ~38 k/s with
  four.
- **Key** `rl:v1:{<namespace>/<domain>}:<block>/<rule>:<algorithm>:<window>:<axes…>:`: block and rule names are ≤ 63,
  the domain is ≤ 63, axis values are escaped; the raw token never enters the key.
- **Token sanitary limits** are engine constants, not configuration fields: an extracted value ≤ 256 bytes
  (`MaxValueBytes`; longer values are skipped with reason `too_long`), an array claim ≤ 64 items (`MaxArrayItems`),
  and the token size. The token is untrusted input; the limits protect key length and store memory.

## What is checked by what

| Mechanism | What it holds |
| --- | --- |
| CRD OpenAPI schema | patterns and lengths of names and values, enums, `minimum`/`maximum`, uniqueness through `listType: map`/`set` |
| CEL on the CRD | only `metadata.name == spec.domain` |
| API server | object size: the 256 KiB annotation, 1.5 MiB in etcd |
| the operator's compiler (`status.ruleProblems`, last-good) | references to keys, groups, and rules; types against operators and axes; predicate arity and other structure; window math; 128 buckets; schema version skew |
| the operator before the ConfigMap write (`ConfigMapTooLarge`, last-good) | the compressed total of the namespace's domains against the 1 MiB of a ConfigMap |
| the service before the JSON decode (a refusal on `/debug/applied`, the snapshot stays) | the decompressed size of a payload against 8 MiB |
| the engine on the decision | the 128-bucket backstop per decision, token sanity limits |
| the adapter on the check | at most 16 descriptors per gRPC check |

There is one rule: the narrowest binds, the bucket budget, the object size, or the compressed total of the namespace.
For `All` policies it is the buckets; for large `FirstMatch` domains it is the object size under client-side apply; for
a namespace whose policies carry long client lists it is the ConfigMap.
