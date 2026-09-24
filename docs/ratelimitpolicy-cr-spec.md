# RateLimitPolicy resource specification

`RateLimitPolicy` is a namespace-scoped custom resource in the `ratelimit.netcracker.com` group, version `v1`,
and the only resource of the service. **One object per domain**: it holds the rate-limiting rules, the extraction of
identity keys from the JWT, and the named client groups. The operator of the same namespace validates it and
writes it into the ConfigMap `ratelimit-config`; the service of the same namespace enforces it and serves the Istio
ambient gateways (and any other consumers) over the Envoy RLS protocol (`envoy.service.ratelimit.v3`).

## How the resource takes effect

1. The team puts the object into the namespace where the operator and the service run (the single namespace or the
   baseline of a composite). The API server checks the shape: patterns, enums, ranges, duplicate names,
   `metadata.name == spec.domain`. Everything that relates fields to each other (references, windows, budgets) is
   checked by the operator's compiler, which reports through the status.
2. The operator keeps an informer on the `RateLimitPolicy` of its own namespace: an event, a compilation, a write of
   the ConfigMap `ratelimit-config`. That ConfigMap is the one object of the namespace that holds the validated spec of
   every domain, gzip-compressed under `binaryData` as `<domain>.json.gz`. Its `manifest` key carries the generation,
   UID, and hash of each domain. The operator writes the object's status; the ConfigMap is the last-good state.
3. Every replica of the service mounts the ConfigMap as a directory and watches it. The kubelet projects a change
   within its sync period, one minute by default. On the swap the replica decodes the manifest, compiles every domain
   with the engine module, and swaps the in-memory rule snapshot atomically. A replica holds no Kubernetes credentials
   and reads nothing from the API server.
4. For every request, the gateway sends the service one flat descriptor: `path`, `method`, `token` (the value of the
   `authorization` header), and `request_id`. The gateway takes the request's domain from the configuration of its
   `envoy.filters.http.ratelimit` filter (the operator chart installs it).
5. The service decodes the JWT payload from `token`, **without verifying the signature**: the `jwt_authn` filter on
   the gateway has already verified it. Identity keys are assembled from the claims: the built-in `client` (the `sub`
   claim) and the keys declared in `spec.mappings` (for example `roles`, `tenant`).
6. The service finds the domain's rules, computes which ones matched, updates the counters in the shared store
   (Redis) with one atomic script, and returns `OK` or `OVER_LIMIT`; on a refusal the gateway returns `429` and the
   `x-ratelimit-*` headers to the client.

## Binding to the traffic source: spec.domain

The domain is a linking string; it is set on two sides and must match literally:

| Side | Who sets it | Where |
| --- | --- | --- |
| gateway | the platform | Helm chart values → EnvoyFilter → the `domain` field of the ratelimit filter |
| policy | the team | `spec.domain`, a verbatim copy of the value the platform published; it is also `metadata.name` |
| direct gRPC consumer | the service itself | the `domain` field of the `ShouldRateLimit` call + `spec.domain` of its policy |

Format (validated by the CRD): `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`, length 1..63. Forbidden: `:` (the separator of
counter key segments), `{` and `}` (Redis Cluster hash tags, which change slot routing), `/` (the separator between
namespace and domain inside the hash tag), spaces, and uppercase letters; domains are compared as strings,
case-sensitively. The naming convention is `<type>.<name>`: `gateway.public`, `gateway.private`, `service.billing`.

A request for a domain that has no rules **is allowed** and counted in the `unknown_domain` metric; this is not an
error. Consequence: a typo in the domain silently switches the limits off; the metric must stay at zero and sits under
an alert.

In a composite, the gateways of all namespaces send one domain and the policy lives in the baseline: requests from the
baseline and from the satellites are indistinguishable and are charged to the same buckets
([topology](deployment-topology.md)).

## One object per domain

- **A singleton by construction.** The `metadata.name == spec.domain` rule (CEL) plus the uniqueness of object names
  within a namespace make a second policy for a domain unrepresentable: the API server rejects the `create` with
  `AlreadyExists`. No "which of the two wins" arbitration is needed; the state is unreachable.
- **Everything in one object.** The claim mapping, the groups, and the rules change in one edit and apply atomically: a
  request never sees old extraction mixed with new rules. The compiler checks references from rules to keys and groups
  inside the one object; there is no cross-object arbitration.
- **A built-in default.** `client` from the `sub` claim (lowercased) is hardcoded in the service and works with an
  empty `mappings`; a `key: client` entry overrides it.
- **Object bounds**, per [the limits and their origin](limits.md): 128 buckets per decision, the decision of one
  descriptor, is an engine constant held by the compiler, and a gRPC check carries at most 16 descriptors; the number
  of blocks, rules, axes, and windows is unbounded, and the object size is bounded only by the API server.

## Spec structure

```yaml
apiVersion: ratelimit.netcracker.com/v1
kind: RateLimitPolicy
metadata:
  name: gateway.public                       # must equal spec.domain (CEL)
  namespace: core-1-core
spec:
  domain: gateway.public                     # binding to the gateway; convention <type>.<name>

  mappings:                                  # which token claims become descriptor keys
  - { key: roles,  claim: realm_access.roles, type: StringArray }
  - { key: plan,   claim: plan, normalization: Lowercase }
  - { key: tenant, claim: org_id, fallbacks: [sub], normalization: Lowercase }
  - { key: entitlements, claimPath: ["https://acme.com/entitlements"], type: StringArray }

  groups:                                    # named client lists; InGroup refers to them
  - name: mvno-group-1
    clients: [mvno_acc1, mvno_acc2]          # client values in its effective normalization (default Lowercase)

  limits:
  # ── Block 1: a cascade of plans ────────────────────────────────────
  - name: order-management                   # unique within the policy; part of the counter key
    target:                                  # optional; no target = all traffic of the domain
      routes:                                # the list is OR; the fields inside a route are AND
      - path: { type: Prefix, value: /api/v1/order-management/ }
        methods: [GET]                       # optional, OR over the list; absent = any method
      - path: { type: Template, value: "/api/v1/orders/{orderId}/items" }
    mode: FirstMatch                         # All (default) | FirstMatch
    rules:
    - name: internal-bypass                  # Bypass: matched -> the cascade ends with an allow,
      matches:                                  # no trip to the store. Bypasses only THIS block:
      - { key: client, operator: Equals, value: prometheus }  # block 2 still applies
      behavior: Bypass
    - name: mvno-group-1-trial               # Shadow in a cascade: counts and writes metrics,
      matches:                                  # but does NOT stop the cascade: trialing a tighter
      - { key: client, operator: InGroup, value: mvno-group-1 }  # limit on top of the live rule below
      counters: []
      behavior: Shadow
      rates:
      - { requests: 50, periodSeconds: 60 }
    - name: mvno-group-1                     # unique within the block
      matches:                                  # identity/claims only; AND
      - { key: client, operator: InGroup, value: mvno-group-1 }
      counters: []                           # bucket axes; empty = one shared bucket for the rule
      rates:                                 # the algorithm is a property of the entry (window); default GCRA
      - { requests: 100, periodSeconds: 60, algorithm: FixedWindow }
      - { requests: 10000, periodSeconds: 86400, algorithm: FixedWindow }
    - name: subscriber-per-user
      matches:
      - { key: roles, operator: Contains, value: subscriber }
      counters: [client]
      rates:
      - { requests: 1000, periodSeconds: 60, burst: 100 }
    - name: per-user                         # no matches: matches everyone who has client
      counters: [client]                     # (the missing-axis semantics cuts anonymous callers off)
      rates:
      - { requests: 100, periodSeconds: 60 }
    - name: anonymous
      matches:
      - { key: client, operator: DoesNotExist } # an explicit absence predicate
      counters: []
      rates:
      - { requests: 100, periodSeconds: 60 }

  # ── Block 2: additive ceilings ──────────────────────────────────────
  - name: api-defaults
    target:
      routes:
      - path: { type: Prefix, value: /api/ }
    rules:                                   # mode: All (default): the rules add up
    - name: per-user                         # axis: user; all paths share one bucket
      counters: [client]
      rates:                                 # rate + quota in one rule:
      - { requests: 300, periodSeconds: 60 }        # minute window: GCRA, smoothing
      - { requests: 20000, periodSeconds: 86400, algorithm: FixedWindow }  # daily quota with a reset
    - name: per-user-per-path                # axes: user + path; a bucket per pair
      counters: [client, path]               # under Prefix the path axis is the raw path: mind the
      rates:                                 # cardinality; under Template the path = the template itself
      - { requests: 60, periodSeconds: 60 }
```

## Field reference

### Top level

| Field | Type | Description |
| --- | --- | --- |
| `domain` | string, required | binding to the traffic source (see above); equals `metadata.name` |
| `mappings` | list | extraction of keys from token claims; empty = built-in keys only |
| `groups` | list | named client lists; the `InGroup` operator refers to a group; values are compared with the `client` key after its effective normalization |
| `limits` | list of blocks | block = `target` + `mode` + `rules`; blocks are always additive with each other |

### The mappings[] entry

| Field | Type | Description |
| --- | --- | --- |
| `key` | string, required | descriptor key name: the shared key pattern `^[a-z][a-zA-Z0-9_]*$`, at most 63 characters; `path`/`method`/`token` are forbidden; `client` is an allowed override |
| `claim` | string | dot-separated path in the token payload (`realm_access.roles`) |
| `claimPath` | list of strings | the same path segment by segment, for claim names with dots; exactly one of `claim`/`claimPath` |
| `type` | `String` (default) \| `StringArray` | shape of the value; an array key is a set of elements |
| `normalization` | `None` (default) \| `Lowercase` | value normalization |
| `fallbacks` | list of paths | tried in order when the primary path is empty; the first non-empty result wins |

Sanity limits (token size, axis value length, array size) are constants of the service, not fields; axis values are
escaped when counter keys are assembled. A semantically broken claim path cannot be caught by static checks at all; the
runtime detector "key declared, tokens arriving, zero extractions" catches it (extraction metrics, under an alert).

The values of `groups[].clients` are compared with the `client` key after its effective normalization: `Lowercase` by
default; when `client` is overridden by a `mappings` entry with `normalization: None`, group values are stored and
compared as written, and the exact case is the author's responsibility. The compiler adds no normalization of its own.

### The limits[] block

| Field | Type | Description |
| --- | --- | --- |
| `name` | string, required | unique within the policy; part of the counter key |
| `target.routes` | list of routes | an OR list; no `target` = the block sees all traffic of the domain |
| `target.routes[].path` | `{type, value}` | `type: Exact \| Prefix \| Template` |
| `target.routes[].methods` | list of enum values: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE` | OR over the values; absent = any method |
| `mode` | `All` (default) \| `FirstMatch` | how the block's rules combine |
| `rules` | list of rules | the block's counters |

### The rules[] rule

| Field | Type | Description |
| --- | --- | --- |
| `name` | string, required | unique within the block; part of the counter key |
| `matches` | list of predicates | a conjunction; the key is `client`, a `mappings` key, or a capture of its own block (`path`/`method`/`token` are forbidden: routes go in `target`); empty = everyone |
| `counters` | list of keys | bucket axes: `client`, `path`, `method`, a scalar `mappings` key, or a capture; empty = one shared bucket |
| `rates` | list of entries | counting windows; absent in a rule with `behavior: Bypass` |
| `behavior` | `Enforce` (default) \| `Shadow` \| `Bypass` | Shadow: count and write metrics, never refuse; Bypass: skip without going to the store |
| `replacedRules` | list of names | suppresses rules of its own block (only with `mode: All`) |

### The rates[] entry

| Field | Type | Description |
| --- | --- | --- |
| `requests` | int32, 1..2 147 483 647 | the window's quota |
| `periodSeconds` | int32 | window length in seconds, 1..86400 (one day); unique within the rule |
| `burst` | int32, 1..2 147 483 647 | only with the `GCRA` algorithm; defaults to `requests` (a full bucket) |
| `algorithm` | `GCRA` (default) \| `FixedWindow` | a property of the window; every entry is an independent bucket |

GCRA limits visible to the rule author: the service counts in whole microseconds, so the rate is capped at one
request per microsecond; at a rate above ~10 000/s per bucket the emission interval is rounded to a microsecond, and
the period must be divisible by `requests` without remainder (`500000/s` is valid, `500001/s` is `InvalidWindow` in
the status); the bucket depth `burst × (period/requests)` is bounded from above. Below these values the limits do not
manifest.

### The matches operators

A key is a set: a scalar key is a one-element set, an array key is the set of its elements, a missing key is the empty
set. Operators are predicates over sets, which is where their applicability to types comes from:

| Operator | Parameter | Meaning | Scalar | Array |
| --- | --- | --- | --- | --- |
| `Equals` | `value` | the set equals `{v}` | ✓ | rejected (`IncompatibleOperator`) |
| `In` | `values` | the intersection with the list is non-empty | ✓ | ✓ ("any element is in the list") |
| `InGroup` | `value` (group name) | the intersection with the group is non-empty | ✓ | ✓ ("any element is in the group") |
| `Contains` | `value` | the element belongs to the set; never a substring match | ≡ `Equals` | ✓ |
| `Exists` | none | the set is non-empty | ✓ | ✓ |
| `DoesNotExist` | none | the set is empty (anonymous traffic) | ✓ | ✓ |

An unknown key (one outside the effective key set of the domain) is rejected by the compiler; see "Validations".

### Template semantics

`{name}` matches exactly one non-empty segment; the template covers the whole path; literal segments are compared
exactly and case-sensitively. Captured segments become descriptor keys visible to the rules of their own block and are
usable in `counters` ("a counter per `{orderId}`"); a placeholder name follows the shared descriptor key pattern
`^[a-z][a-zA-Z0-9_]*$` (at most 63 characters, camelCase allowed), and the names `path`, `method`, `token`, and
`client` are forbidden for placeholders; see "Validations". Inside a block whose route is a Template, the `path` axis
takes the value of the template itself rather than the raw path: axis cardinality is bounded by construction.

### Prefix and Exact semantics

`Exact` is byte equality of the path with the query already stripped: `/orders` and `/orders/` are different paths,
and there is no normalization. `Prefix` is a prefix on a segment boundary: the match ends at the end of the path or at
a `/`; `/api/v1/orders` matches `/api/v1/orders` and `/api/v1/orders/42` but not `/api/v1/orders-archive`; a trailing
`/` in the value means "sub-paths only". Both types are case-sensitive. This differs from Envoy's plain string
`prefix_match`, and the difference is deliberate: the matcher lives in the engine, and segment semantics removes the
"accidentally caught a neighboring resource" class of mistakes.

## Descriptor keys

| Key | Source | Note |
| --- | --- | --- |
| `path` | the request's `:path` | the query string is stripped before matching and axes; as an axis: the template string under `Template`, the raw path under `Prefix`/`Exact` |
| `method` | the request's `:method` | |
| `client` | built-in: the `sub` claim, lowercased | works with an empty `mappings`; overridden by a `key: client` entry |
| mapping keys | `spec.mappings` (`roles`, `tenant`, ...) | types and normalization per the entry |
| captures | the block's `Template` routes | visible to the rules of their own block; shadow a mapping key of the same name (an informational entry) |

Where a key is allowed: `matches[].key` is `client`, a `mappings` key, or a capture of the same block (`path`,
`method`, and `token` are forbidden in `matches`: routes are described by `target`); `counters[]` is `client`, `path`,
`method`, a scalar `mappings` key, or a capture (`path` under `Template` is the template string, under
`Prefix`/`Exact` the raw path). `token` is an input of extraction, not a key. The effective key set of a domain is
`client`, `path`, `method`, and the `spec.mappings` keys; `status.effectiveKeys` publishes exactly that set. Captures
extend it only inside their own block and are not listed in `effectiveKeys`. A missing or malformed token is not an
error: there are simply no identity keys, the rules on them do not match, and the rest apply. The gateway, not the
component, enforces that a token is required.

## Evaluation semantics

1. **Blocks are additive with each other.** A request that falls into several blocks must fit within the verdict of
   each. `mode` acts only inside a block; the effect of `behavior: Bypass` does not leave its own block: in `FirstMatch`
   it ends the cascade with an allow, in `All` it frees the matched requests from the rules named in its
   `replacedRules` and from nothing else.
2. **`mode: All`** applies all matched rules of the block; `replacedRules` is available for targeted overrides.
3. **`mode: FirstMatch`** applies the first matched rule in list order; the order is semantics. A rule with
   `behavior: Shadow` counts but does not stop the cascade; `behavior: Bypass` ends the cascade with an allow;
   `replacedRules` is forbidden by validation.
4. **A missing axis**: a rule whose `counters` axis is absent from the request (for example `client` for an anonymous
   caller) does not match; there is nothing to key the bucket with.
5. **The verdict**: `OVER_LIMIT` if at least one applied rule (of any block) is exceeded; the `x-ratelimit-*` headers
   come from the strictest matched rule.
6. **Request cost**: the protocol field `hits_addend` (default 1); a cost above the burst capacity produces a
   deterministic refusal, not a wait.
7. **A refusal does not spend quota**, a guarantee of every algorithm: a refused request does not advance the counter
   state. Shadow follows the same logic: a Shadow bucket is charged only when its own verdict is "allow", mirroring
   what enforcement would do; unconditional charging would accumulate unbounded debt and inflate the "would have
   refused" metric.
8. **Direct gRPC consumers** send already extracted descriptor pairs; the service matches on the keys that are
   present. Several descriptors in one request are decided independently, per Envoy semantics: each charges its own
   counters per its own verdict, the overall response is a refusal if at least one descriptor refuses, and the headers
   come from the strictest decision; per-descriptor verdicts (statuses) are not returned in v1: if you need a separate
   verdict, send separate checks. A request without descriptors is one decision over an empty request: the domain's
   unconditional limits apply. An empty value of a descriptor entry means the key is absent, as in the identity layer.
   The number of descriptors is unbounded: the 128-bucket budget applies to the gRPC call as a whole, summed over all
   its descriptors; exceeding it is an explicit refusal (`OVER_LIMIT`), not an error.
9. **A key is a set** (a scalar is a one-element set, an array is its elements, a missing key is the empty set);
   operators are predicates over sets. The compiler rejects an incompatible operator/type pair as a blocking
   `IncompatibleOperator` problem; it never reaches the matcher.
10. **An unknown key** (one outside the effective key set of the domain) is rejected by the compiler. There is no
    runtime invariant on top of that: the conditions are checked against the effective set at compile time,
    and a predicate over such a key never reaches the matcher (a snapshot that bypasses the compiler is outside the
    contract: policies arrive only through the CR). The semantics of `DoesNotExist` is "the key is produced but absent
    from the request", not "nobody has heard of the key".

## Request lifecycle

The path of one request from the gateway to the verdict, through every layer:

```text
client ──HTTP──> gateway ──jwt_authn──> (token signature verified)
                    │
                    └──gRPC──> component ──1 atomic script──> store
                    <──── OK / OVER_LIMIT + headers ───┘
```

1. **The gateway sends a flat descriptor**: `domain`, `path` (with the query), `method`, `token`, `request_id`.
2. **Preparation**: the query is stripped from `path` (otherwise `?page=2` would split one endpoint across different
   buckets); the token payload is decoded without signature verification, since the gateway has already done it; the
   identity keys are extracted per the mapping. No token means no identity keys, and this is not an error.
3. **Matching**: the blocks whose `target` matched are selected; inside a block, `mode` decides between all matched
   rules and the first one. A rule without its axis (`client` for an anonymous caller) does not match. A `Bypass` rule
   ends its cascade with an allow and does not go to the store.
4. **Expansion**: every window of every matched rule is a separate bucket; a single builder constructs the keys.
5. **One trip to the store, two passes inside**: first, all buckets are only evaluated; if no enforcing bucket refused,
   the second pass writes the new states and TTLs. If at least one refused, there is no second pass and no bucket is
   charged: the daily quota is not spent on requests refused by the minute limit. A shadow bucket has no veto and is
   charged only per its own verdict.
6. **Response**: the verdict is an AND over the enforcing buckets; the `x-ratelimit-*` headers come from the strictest
   matched bucket (the minimal remaining when the request is allowed, the maximal retry-after on a refusal; on a tie, a
   deterministic tie-break by bucket key). A refusal is `OVER_LIMIT` with `retry-after`; a cost that can never fit gets
   no retry headers. If the store does not answer within the budget, the service answers `UNAVAILABLE` and the gateway's
   failure mode decides: with `failClosed: false`, the default, the request passes unlimited, and with `true` the
   gateway answers 503. The error metric grows either way. A check some rule already refused answers `OVER_LIMIT`
   regardless.

## Compilation model

A domain is one object, and compilation is a pure function of it:

```text
compile(RateLimitPolicy) =
    keys:   built-in + spec.mappings (+ captures of Template routes, visible to their own block)
  + groups: spec.groups
  + blocks: spec.limits in the author's order

verdict(request) = AND over all buckets of all matched blocks
```

Properties of the model:

- **Determinism.** The same object yields a byte-for-byte identical snapshot on any replica; order affects the verdict
  only in the rule list of `FirstMatch`; in `fallbacks` it affects extraction.
- **Two compilers, one module.** The operator compiles every generation to validate it and to check that the
  compressed ConfigMap fits. The service compiles the validated spec it reads from the ConfigMap to enforce it. Both
  import the same engine module (`engine/`), so the operator's verdict on a generation matches the snapshot a replica
  builds from it.
- **Replicas are equal.** Each compiles on its own from the same ConfigMap; there is no shared state between them, and
  the operator alone writes the status and the ConfigMap.
- **Response headers are deterministic**: the "strictest" rule is chosen by the minimal remaining when the request is
  allowed and by the maximal retry-after on a refusal (after the longest pause every window is open); on a tie,
  lexicographically by bucket key rather than by traversal order (otherwise the headers would jitter between replicas).

Consequences for operations on names:

| Operation | Effect |
| --- | --- |
| renaming a block or a rule | fresh buckets; the old ones expire by TTL (distortion ≤ one window); for an exact carry-over, a reset in the management API |
| editing `requests`/`burst` | the live state is reinterpreted, not reset |
| changing a rule's algorithm or window | new buckets from zero (key segments); the old ones expire |
| deleting the policy | the domain disappears: the operator drops it from the ConfigMap on the next reconcile, and the replicas apply the removal within the kubelet sync period; requests are allowed as unknown domain, counters expire by TTL |

## Counter key

```text
rl:<version>:{<namespace>/<domain>}:<block>/<rule>:<algorithm>:<window>:<axes...>:
```

Example: `rl:v1:{core-1-core/gateway.public}:api/per-user:gcra:60:alice:`. The service substitutes the namespace
segment,
its own, through the Downward API; Redis is dedicated to the installation, and the segment guards against two
installations connecting to one store (details in the store contract). There is no policy segment: a domain has one
policy, and its name is the domain itself. The algorithm segment is the algorithm name in lowercase (`gcra`,
`fixedwindow`). Every segment is terminated, including the last one: a bucket key is at the same time the prefix of its
own subtree, so one string addresses an exact bucket and safely bounds scans and partial resets (`alice` does not match
`alice2`), which is why management needs no manual prefix assembly.

The hash tag is on the domain, and this is a load-bearing decision: a request's verdict covers several buckets and must
be charged atomically, in one server-side script. A shared slot for all keys of a domain makes such a script valid on
any Redis topology, including Cluster. The price is accepted deliberately: the throughput of one domain is bounded by
one shard; domains spread freely across shards.

`requests` and `burst` are deliberately not part of the key: editing a limit reinterprets the live state rather than
resetting it. Fixed window keeps the spent count (a quota raised in the middle of the day remembers what was consumed),
and GCRA keeps the drain depth in time. Axis values and names are escaped when the key is assembled; empty axis values
do not exist by construction (no axis means the rule did not match); the service's single builder constructs the keys,
so management and matching agree byte for byte; the raw token never gets into a key.

## Validity and last-good

**1. The schema cuts off the shape; the compiler judges the content.** The API server rejects on `kubectl apply` only
what is visible without context: patterns, enums, ranges, duplicate names, `metadata.name == spec.domain`. An object
with a broken reference, an impossible window, or an exceeded budget lands in etcd, and that is normal: the judge is
the operator's compiler, on every generation, and it runs the engine module the service replicas run.

**2. Generation validity is atomic.** A generation with at least one blocking problem (the table of reasons is in the
"Status" section) is invalid as a whole: none of its rules enters the snapshot, `Accepted: False`,
`Ready: False / NotCompiled`, `Stalled: True`, `ruleProblems` entries with the address of the rule; the operator leaves
the previous generation in the ConfigMap, and the replicas keep enforcing it (`activeGeneration`). Partially enforced
generations do not exist; otherwise a `FirstMatch` cascade with a dead rule would silently hand traffic to neighboring
rules. Schema version skew takes the same path. The operator's informer works on unstructured objects, and the operator
decodes the object's `spec` into the typed structure strictly: an unknown field there is a blocking `InvalidSpec` whose
message names the field path.

```text
unknown field "spec.burstProfile"
```

Strictness covers the spec alone. The status and the metadata are read leniently, because during the operator's own
rollout its two pods overlap, and a status field the newer one writes would otherwise make the older read every policy
as skewed.

An unknown enum value (a new `behavior`, `algorithm`, or `operator`) is also an `InvalidSpec` from the compiler. Old
objects under a newer schema need nothing: additive fields take their defaults.

**3. Last-good survives a restart.** The operator persists the enforced generation of every domain of the namespace
(its validated spec, its number, and the object's UID) in the one ConfigMap `ratelimit-config`. It writes the whole
object on every reconcile, even when the namespace holds no policy, and creates it with an `ownerReference` to the
operator Deployment; no chart renders it.

```text
ConfigMap ratelimit-config             owner: the operator Deployment; the operator writes, every service replica mounts it
├── binaryData.<domain>.json.gz        the validated spec in the resource's own format, gzip-compressed; one key per domain
└── data.manifest                      plain JSON: an integer formatVersion, operatorVersion, and per domain generation, uid, hash
```

- **UID guard**: a recreated policy of the same name has a different UID; a manifest entry with another UID is
  discarded, not resurrected;
- the order at a reconcile: if the generation compiles and fits, the operator writes it; if it does not and the
  manifest holds the domain with the same UID, that entry stays and the status shows the
  `observedGeneration`/`activeGeneration` divergence; if there is neither, the domain is absent from the ConfigMap and
  empty;
- the replicas read the ConfigMap through a volume, and it outlives both an operator restart and a replica restart. A
  replica that has never applied a manifest stays NotReady until the first apply; after it the replica keeps its
  snapshot in memory through vanished files or a refused manifest;
- the compressed total of all domains is bounded by the 1 MiB of a ConfigMap: rules compress about 20 to 40 times, a
  client list of UUIDs about 1.8 times ([limits](limits.md)). The operator checks the size before it writes. A
  generation that does not fit is `Ready: False`, `Stalled: True` with reason `ConfigMapTooLarge`, distinct from
  `NotCompiled`, and last-good stays enforced. A write error counts in `ratelimit_config_write_errors_total` by
  reason (`size`, `api`, `other`) and leaves a log line; the write is retried with the workqueue's backoff. The
  operator writes only `Warning` events: on `NotCompiled`, one event per generation change rather than per probe;
  it never writes `Normal` events.

Persistence is needed because an invalid object in etcd is a normal case, not an exception: an edit with a typo in a
reference passes the API server. A rollout restarts all replicas at once, and without last-good such an edit would
mean a wholly unprotected domain.

**4. Domain budgets live in the compiler.** The worst case of a decision (`All` sums the windows of all rules in the
block, `FirstMatch` takes the widest rule plus `Shadow`; summed over blocks) does not exceed 128 buckets: a generation
beyond that is a blocking `DomainBudgetExceeded`, and last-good stays enforced. The number of blocks is unbounded: the
object size itself keeps the linear scan of targets (~20 ns per target) cheap. The budget binds one decision, the
decision of one descriptor; a gRPC check carries at most 16 descriptors, each its own decision and its own atomic
script. The service's runtime backstop (a decision that gathers more than 128 buckets: `ErrTooManyBuckets` →
`OVER_LIMIT` regardless of the gateway's `failClosed` setting) is unreachable in normal operation; when the library is
embedded without the CRD, the adapter must treat this error as a refusal: it is a configuration violation, not store
unavailability.

Prior art. "Keep last-good on an invalid update" is the standard of the class (ingress-nginx when `nginx -t` fails,
ACK/NACK semantics in xDS, the CoreDNS reload), usually in memory; persistence is rarer, and the closest analog in shape
is Helm, which stores release revisions in Secrets. We chose not to reject content at admission: a validating webhook
means certificate infrastructure, a cluster-scoped configuration object, and tying the writability of the CR to the
liveness of the operator; CEL on the CRD for the same checks was rejected after measurement, since the cost estimator
forces list bounds for its own sake and a second copy of the compiler's rules ([limits](limits.md)).

**The operator's RBAC** is a namespace-scoped Role, the only Role of the delivery: `ratelimitpolicies` get/list/watch,
`ratelimitpolicies/status` update/patch, Lease create/update/get (the Lease covers the overlap of two operator pods
during a rollout), the EndpointSlice of the Service `ratelimit` get/list/watch, the ConfigMap `ratelimit-config`
get/list/watch/create/update/patch/delete, its own Deployment get (the ConfigMap's owner), `events` create/patch. There
is no ClusterRole; the operator chart installs the CRD. The service pod carries no Role and mounts no ServiceAccount
token (`automountServiceAccountToken: false`).

## Status

The operator writes the status. Terms: `activeGeneration` is the enforced generation, the one whose snapshot answers
requests; `replicas.applied` counts the ready replicas that enforce it. The conditions follow the Kubernetes API
conventions: **`Accepted`** says whether the object compiles; `Accepted: False` always carries
`reason: CompilationFailed`, and its `message` is a summary such as
`generation 8 does not compile: 2 blocking problems (UnresolvedKeyReference, InvalidWindow)`; the individual reasons
live only in `ruleProblems[]`. **`Ready`** is the strict summary condition, binary: `True` or `False` with a reason.
**`Stalled`** means "stuck" and separates "in progress" from "broken"; its reasons are `Progressing` when `False`, and
`ReplicaStale`, `NotCompiled`, `ConfigMapTooLarge`, or `ReplicaFormatUnsupported` when `True`. `Ready: Unknown`
appears only when the operator could not observe the replicas. If the pair `observedGeneration` (the last generation
seen) and `activeGeneration` diverges, the latest generation does not compile (schema version skew or a blocking
problem) or does not fit into the ConfigMap, and last-good is enforced.

```yaml
status:
  observedGeneration: 7
  activeGeneration: 7                  # the latest generation is enforced
  effectiveKeys: [client, method, path, roles, plan]   # domain-wide keys of activeGeneration; captures are not listed
  replicas:                            # what the operator sees through the EndpointSlice of the Service ratelimit
    total: 3                           # ready replicas at the time of the probe
    applied: 2                         # of them, enforcing activeGeneration
    summary: "2/3"                     # applied/total as one string: the REPLICAS printer column reads it
    lastCheckTime: "2026-09-02T12:00:05Z"
  conditions:
  - type: Accepted                     # the object compiles (no blocking problems);
    status: "True"                     # False -> reason: CompilationFailed, message is a summary, causes in ruleProblems
    reason: RulesCompiled
    lastTransitionTime: "2026-09-02T12:00:00Z"
    observedGeneration: 7
  - type: Ready                        # ALL ready replicas enforce the latest generation
    status: "False"                    # in progress: Stalled below says this is not a breakage
    reason: Propagating
    message: '2 of 3 replicas enforce generation 7; ratelimit-service-7c9d-x2k1 reports 6'
    lastTransitionTime: "2026-09-02T12:00:05Z"
    observedGeneration: 7
  - type: Stalled                      # stuck; under an alert
    status: "False"
    reason: Progressing
    lastTransitionTime: "2026-09-02T12:00:05Z"
    observedGeneration: 7
  ruleProblems: []                     # root causes only
```

`Ready: True` requires exactly three conditions at once: the operator sees the latest generation
(`observedGeneration == metadata.generation`); it is compiled and enforced (`activeGeneration == observedGeneration`,
not last-good); every ready replica has reported this same generation (`replicas.applied == replicas.total > 0`). "All
replicas" means the ready endpoints of the Service at the time of the probe, not the Deployment's `spec.replicas`: a pod
that is not ready receives no traffic and is not part of the denominator. The comparison is by the generation + UID
pair from the `/debug/applied` payload.

| Situation | `Ready` | `Stalled` | reason |
| --- | --- | --- | --- |
| all ready replicas enforce the latest generation | True | False | `AllReplicas` |
| the operator has not yet reached the latest generation | False | False | `Reconciling` |
| the kubelet is projecting the new generation into the replicas, the lag is below the threshold (90 s) | False | False | `Propagating` |
| there is no ready replica at all | False | False | `NoReplicas` |
| a replica lags longer than the threshold (90 s, above the kubelet sync period): the kubelet has not projected the update or the replica's watcher is broken | False | True | `ReplicaStale` |
| the latest generation does not compile, last-good is enforced | False | True | `NotCompiled` |
| the latest generation compiles but does not fit into the ConfigMap with the other domains, last-good is enforced | False | True | `ConfigMapTooLarge` |
| a replica refuses the manifest's format version and keeps its snapshot | False | True | `ReplicaFormatUnsupported` |
| the operator could not probe the replicas (the EndpointSlice or the `metrics` port is unavailable) | Unknown | False | `ProbeFailed` |

The threshold counts from the moment this generation started spreading, not from the previous status change:
`lastTransitionTime` of `Ready` is rewound when the reason enters `Reconciling`, `Propagating`, or `ReplicaStale` from
any other reason, and when the condition's `observedGeneration` changes, so an edit that repairs a broken policy or a
pod that comes back after `NoReplicas` starts its own clock. The API conventions move the stamp only on a status
change; the departure is deliberate, and the condition's own `observedGeneration` is what gives the stamp its
per-generation meaning.

The replica probe: the operator discovers the ready replicas through the EndpointSlice of the Service `ratelimit` and
takes the port number from the EndpointSlice by the port name `metrics`. It reads from every ready replica the JSON
endpoint `/debug/applied` on that port. The payload reports the applied generation and UID per domain, the format
versions the replica reads, and a refusal with its reason. One round of answers serves every domain of a cycle: the
replicas are asked together, once per probe interval of 10 s, and a reconcile answered from the round requeues for the
moment the round stops being reused. A reconcile of a generation the status has not observed asks the fleet afresh,
and a pod that joined or left retakes the round, so an EndpointSlice change is seen at once. The comparison is by the
generation and UID from that payload. The `ratelimit_policy_applied_generation{domain}` gauge stays for Prometheus and
alerts but is not the source of `Ready`. The `/debug/` prefix is read-only diagnostics on the cluster-internal metrics
port: no mutations, no authentication, not part of the management API, and outside the compatibility promises. From
the probe result the operator writes `status.replicas` and the conditions; it writes only on a change and with a
`resourceVersion` precondition, and `lastCheckTime` is the time the fleet was asked, the freshness of the answers the
status rests on, never older than the interval plus the length of a round. `summary` repeats `applied/total` as one
string, because the `REPLICAS` printer column is a JSONPath expression and cannot join two numbers. `NoReplicas` is
written by the operator when the EndpointSlice holds no ready endpoint; when the operator itself is not running, nobody
writes: the status freezes, and the age of `lastCheckTime` shows it.

Scaling and rollouts do not make `Ready` flicker: a new pod enters the denominator only once ready, and it becomes ready
after its first applied manifest, already with the current generation; a terminating pod leaves the denominator
immediately. The upgrade order is the service first, then the operator, and a rollback reverses it. A pair rolled out
in the wrong order is the only case where `Ready` leaves `True` without an edit to the object. `activeGeneration` is
the operator's point of view, and a replica that refuses the format version the operator writes lands in
`ReplicaFormatUnsupported` by name until the service rollout completes.

A start on last-good (generation 8 in etcd does not compile, the manifest of `ratelimit-config` holds 7 with the same
UID):
`observedGeneration: 8`, `activeGeneration: 7`, `replicas: {total: 3, applied: 3}`, everyone unanimously enforcing 7,
but `Ready: False / NotCompiled`, `Stalled: True`, `Accepted: False / CompilationFailed` with a summary `message`, and
`ruleProblems` with the root causes. If there is no last-good or the UID does not match: `activeGeneration: 0`, the
domain is empty, `message: 'no generation is enforced: domain is unprotected'`.

For Argo CD: by default it does not assess the health of a CR; the platform's Lua check (given in the
[Helm doc](helm-chart.md)) reads `Ready` and `Stalled`: `Stalled: True` is Degraded, `Ready: True` is Healthy,
everything else is Progressing. A sync wave closes only when every pod enforces the rule. A Helm release does not wait
for CR statuses: it only puts the policies in place.

Diagnostics live in `ruleProblems[]` (conditions are a map by `type`; several simultaneous problems cannot be expressed
in them) and contain only root causes:

| Reason | Weight |
| --- | --- |
| `UnresolvedKeyReference`: a key outside the effective set of the domain | blocking |
| `UnresolvedGroupReference`: `InGroup` on a non-existent group | blocking |
| `UnresolvedReplacedRules`: `replacedRules` names a rule outside its own block | blocking |
| `IncompatibleOperator` / `InvalidCounterAxis`: the key type does not suit the operator or the axis | blocking |
| `InvalidSpec`: a structural defect invisible to the schema: predicate arity, `Bypass` without `replacedRules` in `All`, a repeated placeholder, a template segment that is neither a literal nor a single placeholder (a brace outside a placeholder, an empty segment), an unknown field or enum value of a newer schema | blocking |
| `InvalidWindow`: a window the math cannot enforce | blocking |
| `DomainBudgetExceeded`: the worst case of a decision above 128 buckets | blocking |
| `CaptureShadowsMappedKey`: shadowing; inside the block the capture is in effect | informational |

At least one blocking entry makes the whole generation invalid. Printer columns: `READY`, `REPLICAS` (`applied/total`),
`RULES`, `PROBLEMS`, `AGE`; the domain is not duplicated, since it is the object's name.

## Validations: schema and compiler

The split is simple: the **schema** holds the shape of values, and the **operator's compiler** holds everything that
relates fields to each other. The operator runs the compiler on every generation before it writes the ConfigMap. The
service replicas run the same engine module on the validated spec to enforce it; a replica refuses only a manifest
whose format version it does not read. CEL on the CRD is one rule, `metadata.name == spec.domain`. The numbers and
their origin are in [limits](limits.md).

Schema (OpenAPI):

- `domain`: format and length, see the binding section; the same pattern on the chart values side;
- block, rule, group, and key names: a pattern and a length ≤ 63 (they are part of the counter key); every descriptor
  key (`mappings[].key`, `Template` placeholders, `matches[].key`, `counters[]`) uses one pattern,
  `^[a-z][a-zA-Z0-9_]*$`, camelCase allowed (`{orderId}` in the examples is valid); predicate values, clients, and
  claim paths ≤ 256, the engine's sanitary limit on an extracted value, so a longer literal can never match; a route
  path ≤ 2048 (the conventional URL limit);
- uniqueness through list types: `limits`, `rules`, and `groups` are a `map` by `name`, `mappings` a `map` by `key`,
  `rates` a `map` by `periodSeconds`, `methods` a `set`; `conditions` a `map` by `type`; the remaining lists are
  atomic;
- enums for `mode`, `behavior`, `algorithm`, `type`, `normalization`, `operator`, `methods`; `periodSeconds` is
  1..86400; `requests` and `burst` are 1..2 147 483 647; `ruleProblems[].message` ≤ 1024 characters and
  `ruleProblems` ≤ 64 entries, both cut by the operator before the write; `status.problems` counts every problem,
  past 64 too, so a `PROBLEMS` column of 70 beside 64 entries is expected; required fields are marked `+required`,
  optional ones `+optional`;
- apart from the status's `ruleProblems`, there is no `maxItems` on the lists: the only CEL rule walks no lists, and
  the bounds that mean something to the engine are held by the compiler.

The operator's compiler, on every generation, with the result in `status.ruleProblems`, `Accepted`/`Ready`, and
last-good:

- references: a predicate key is `client`, a `mappings` key, or a capture of a `Template` route of its own block; an
  axis key is `client`, `path`, `method`, a scalar `mappings` key, or the same kind of capture
  (`UnresolvedKeyReference`); `InGroup` names a group from `groups` (`UnresolvedGroupReference`); `replacedRules`
  names rules of its own block (`UnresolvedReplacedRules`);
- types: `Equals` does not apply to a `StringArray` key unless a capture shadows it (`IncompatibleOperator`); an array
  key cannot be an axis (`InvalidCounterAxis`);
- structure (`InvalidSpec`): `matches` parameters match the operator: `Equals`/`Contains`/`InGroup` take only `value`,
  `In` takes only a non-empty `values`, `Exists`/`DoesNotExist` take no parameters; `matches` does not accept
  `path`/`method`/`token`; `Bypass` carries no `rates`, all others carry at least one window; `replacedRules` only in
  `All`; `Bypass` in `All` names `replacedRules`, otherwise `InvalidSpec` (a silent no-op is not acceptable);
  `mappings[].key` is not `path`/`method`/`token` (`client` is an allowed override), and exactly one of
  `claim`/`claimPath`; `Template`: segments are literals or a single `{name}`, placeholders do not repeat and do not
  coincide with the built-in keys `path`, `method`, `token`, `client` (for `client` the ban is fundamental: the caller
  controls the path, and a capture would let it assign itself a client identity); an unknown field or enum value of a
  newer schema: the object is decoded strictly (`DisallowUnknownFields`), and the field path goes into the message;
- windows (`InvalidWindow`, the engine's window check): `burst` only with GCRA; `requests ≤ periodSeconds × 10⁶`;
  with an emission < 100 µs `periodSeconds × 10⁶` is divisible by `requests` without remainder;
  `burst × emission ≤ 10¹⁵ µs`;
- domain budget (`DomainBudgetExceeded`): the worst case of a decision ≤ 128 buckets.

Why not CEL: the cost of a CEL rule grows with list cardinality, since the estimator multiplies it by the product of
`maxItems` along the path to the rule, and holding references and budgets at admission would mean bounding lists for
the estimator's sake and maintaining a second copy of the compiler's rules. The only gain would be a message on `apply`
instead of a status. The measurements are in [limits](limits.md).

List markup for server-side apply: `+listType=map` for `limits`, `rules`, and `groups` by `name`, `mappings` by `key`,
`rates` by `periodSeconds`, `conditions` by `type`; `methods` is a `set`; the remaining lists (`matches`, `routes`,
`counters`, `fallbacks`, `clients`, `replacedRules`) are atomic.

## A worked example

[`ratelimitpolicy-example.yaml`](ratelimitpolicy-example.yaml) is a commented policy that exercises the whole spec in
one object: claim mappings for a scalar and an array claim, named groups, an `All` block with per-path, per-client,
plan-override, bypass, group, role, and shadow rules, and a `FirstMatch` block over template routes that counts by a
path capture. A second, minimal document in the same file shows the smallest policy that does anything.
