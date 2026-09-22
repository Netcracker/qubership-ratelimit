# Rate limit engine

The rate limit service answers `ShouldRateLimit` for the Istio ambient gateways and for direct gRPC consumers. This
document describes the engine behind that answer: the protocol, the configuration channel, rule semantics, counting,
storage, the token handling, the management surface, and the operational envelope. The operator side (the policy
informer, the status, last-good), the resource schema, and the Helm wiring are in the
[resource specification](ratelimitpolicy-cr-spec.md), the [topology](deployment-topology.md), and the
[chart](helm-chart.md); the numbers are in [limits](limits.md).

The engine is the component's own, not `envoyproxy/ratelimit`: gateways send one descriptor of four entries (`path`,
`method`, `token`, `request_id`) per request, and the engine, not Envoy, composes the counting axes from it. Rules are
authored as the `RateLimitPolicy` of the namespace, one object per domain, and reach the engine through the ConfigMap
`ratelimit-config` that the operator writes and the service mounts.

## Protocol and integration

- The service implements `envoy.service.ratelimit.v3.RateLimitService` over gRPC. This is the only decision API: Istio
  gateways, waypoints, Envoy Gateway, and application code all call the same endpoint.
- `domain` is the rule-set namespace. A request for a domain with no rules is allowed and counted in
  `ratelimit_unknown_domain_checks_total`; it is never an error. Counter keys embed the domain, so the same client
  crossing two gateways never shares a bucket. The domain format is schema-validated:
  `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`, length 1..63 — no `:` (the key segment separator), no `{` or `}` (Redis Cluster
  hash tags), no uppercase (comparison is exact and case-sensitive). The naming convention is `<type>.<name>`:
  `gateway.public`, `service.billing`.
- The descriptor arrives flat and the counting axes are decomposed internally, per the rule set. A caller never has to
  enumerate axis combinations as separate descriptors.
- `hits_addend` is the request cost, defaulting to 1. A cost that can never be admitted, greater than the rule's burst
  capacity, produces a deterministic `OVER_LIMIT`, never a wait or a loop.
- The verdict is aggregated: `OVER_LIMIT` if any matched rule is exceeded, `OK` otherwise. `statuses` stays empty: the
  response carries `overall_code` and headers, and per-descriptor detail is not returned, so a caller that needs
  separate verdicts sends separate checks. Per-rule detail (which rule fired, remaining, retry-after) comes back in the
  response headers `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset` or `retry-after`, taken from the
  strictest matched rule. "Strictest" is deterministic: minimal remaining on an admission; longest retry-after on a
  refusal (every refusing bucket has about zero remaining, and a short hint would steer the client's retry into the
  next refusal, whereas after the longest wait every window is open); ties break lexicographically by the bucket key.
  Key order differs from pair order for names carrying `-` or `.`; that only decides whose name the headers carry on an
  exact tie, and it is the same on every replica, so headers do not jitter.
- Direct gRPC consumers get the same contract. They may send pre-extracted descriptor entries and no token; the engine
  matches on whatever keys are present.
- The standard gRPC health service is exposed for direct gRPC consumers. Deployment readiness and liveness use HTTP
  `readyz` and `healthz` on the service chart's `healthProbe.port` (8081 by default), and `readyz` opens after the first
  manifest is applied from the ConfigMap volume; the probes do not use the gRPC health service.

## The configuration channel

One ConfigMap per namespace carries the configuration from the operator to the service. The status semantics of the
operator are in the [resource specification](ratelimitpolicy-cr-spec.md).

- **The channel** is the ConfigMap `ratelimit-config`, exactly one per namespace, and the operator is its only writer.
  It writes the whole object on every reconcile, creates it with an ownerReference to its own Deployment, and writes it
  even when the namespace holds no policy; no chart renders it. Under `binaryData` the object holds one
  `<domain>.json.gz` key per domain: the validated spec in the resource's own format, gzip-compressed. Under `data` it
  holds the key `manifest`: plain JSON with an integer `formatVersion`, the `operatorVersion`, and per domain the
  `generation`, the `uid`, and the `hash`. The ConfigMap is the last-good state of the namespace. Before the write the
  operator checks the compressed total against the 1 MiB limit of a ConfigMap; a generation that does not fit is
  reported with reason `ConfigMapTooLarge` (`Ready: False`, `Stalled: True`), distinct from `NotCompiled`, and the
  last-good state stays enforced. Rules compress about 20 to 40 times and a client list of UUIDs about 1.8 times, so
  about 45000 UUIDs fill the object.
- **The read side.** The service mounts the ConfigMap as a whole directory at `/etc/ratelimit/config` with
  `optional: true` and watches the `..data` symlink for the kubelet's swap. On a swap it decodes the manifest, compiles
  every domain with the engine module, and swaps its snapshot atomically: a request is evaluated against the old
  snapshot or the new one, never a mix. The pod name and the namespace come from the Downward API. A change reaches the
  replicas within the kubelet sync period, one minute by default.
- **The manifest decoder is strict.** An unknown field or an unknown format version refuses the manifest as a whole, and
  a payload that does not decompress, or decompresses past 8 MiB, refuses the same way; the replica keeps its snapshot
  and reports the refusal on `/debug/applied`, which the operator turns into the status reason
  `ReplicaFormatUnsupported`. The service reads format versions N and N-1, and the operator writes N. Any change of what
  the operator writes, a field added to the spec included, increments the version. Golden manifests per format version
  live in the repository; a decoder test reads all supported ones, and a check fails when the writer's output changes
  without a new version; both are unit tests, and no e2e mixes images of two versions. An upgrade installs the service
  before the operator, and a rollback reverses the order. A fresh installation needs no order: the service waits
  NotReady until the operator writes. The repository has one version line, and both images and both charts carry it.
- **Ready of a replica.** A replica that has never applied a manifest is NotReady and out of Endpoints, without a
  timeout, so a missing operator never turns into traffic without enforcement. An explicitly empty manifest is a
  configuration: the replica is Ready, and every request passes as an unknown domain. After the first apply the replica
  keeps its snapshot in memory and stays Ready when the files vanish or a later manifest is refused.
- **`/debug/applied`** on the metrics port reports the applied generation and UID per domain, the format versions the
  replica reads, and a refusal with its reason. The operator discovers the replicas through the EndpointSlice of the
  Service `ratelimit`, takes the port number from the EndpointSlice by the port name `metrics`, and reads the endpoint
  once per probe cycle (10 s). The port stays open inside the cluster, read-only and without authentication. The
  `ReplicaStale` threshold that separates a stale replica from `Propagating` is 90 s, above the kubelet sync period.
  The same port answers `/debug/snapshot` and `/debug/snapshot/{domain}`, which render what this replica enforces for a
  human with a port-forward; nothing in the delivery reads them.
- **The service holds no Kubernetes credentials**: its pod carries no Role, sets `automountServiceAccountToken: false`,
  and writes nothing to the API server. The repository enforces the boundary: `operator/` and `service/` each hold a
  `cmd` and an `internal` tree, so Go's path rule for `internal` makes an import across the halves a compile error; a
  depguard rule forbids client-go and controller-runtime under `service/`; CI reads the build information of the service
  binary and fails when client-go is present.
- **The contract between the two components** is constants in one Go package under `api/` that both binaries import: the
  Service `ratelimit`, its gRPC port 9000 named `grpc`, the probe port published on the Service under the name `metrics`
  (the service's metrics port, 8080 by default), the ConfigMap `ratelimit-config`, the mode rule, and one namespace for
  both charts. The mode rule: satellite if and only if `BASELINE_ORIGIN` is non-empty, otherwise the whole stack;
  `BASELINE_CONTROLLER`, when set in a satellite, replaces `BASELINE_ORIGIN` as the namespace half of the RLS address
  `ratelimit.<namespace>.svc.cluster.local:9000`; in a satellite the operator chart renders the EnvoyFilters only and
  the service chart renders nothing. A CI test renders both charts and compares the rendered names and ports with the
  constants, the [chart document](helm-chart.md) lists the contract, and `rls.port` exists in neither chart.

## Rule model and matching

- **The snapshot is immutable** and swapped atomically; a request is evaluated against exactly one snapshot. Partial
  rule sets are impossible by construction.
- **The rule model is two-level.** A policy holds blocks (`limits[]`); a block is a `target` (routes) plus a `mode` plus
  `rules[]`. A rule is `matches` (a conjunction of identity predicates) plus `counters` (the axes that key the bucket)
  plus `rates[]`. Empty `matches` matches every request of the block; empty `counters` yields one shared bucket for the
  rule; a block without a `target` sees all traffic of the domain. The model expresses the three counting shapes: per
  path, per client, per client and path.
- **Routes live in `target`, identity lives in `matches`**; `path`, `method`, or `token` in `matches` is a blocking
  `InvalidSpec` from the compiler. `target.routes` is an OR-list, and within a route the fields are AND: `path` with the
  types `Exact`, `Prefix`, and `Template` (a template such as `/api/v1/orders/{orderId}/items`, where `{name}` matches
  exactly one non-empty segment, the template covers the whole path, comparison is exact and case-sensitive, and
  repeated placeholder names are rejected; it is implemented as a segment-wise comparison, with no regex), plus
  `methods`, a list that ORs over its values and, when absent, means any method. The `matches` operators are `Equals`,
  `In`, `InGroup` (a named client list), `Contains` (for array-valued keys such as roles), `Exists`, and
  `DoesNotExist` (key-presence predicates, for anonymous traffic). The semantics are set-based: a key is a set (a scalar
  is a singleton, an array is its elements, absent is empty); `In` and `InGroup` are a non-empty intersection ("any
  element"), `Contains` is element membership and never a substring, `Equals` is equality to a singleton set and is
  rejected for array keys, and `Exists`/`DoesNotExist` are non-emptiness and emptiness. An incompatible operator/type
  pair is a blocking `IncompatibleOperator` entry in `status.ruleProblems`. Array keys are forbidden as `counters` axes,
  a blocking `InvalidCounterAxis` entry.
- **Named groups** are client lists defined once per policy and referenced by `InGroup`, giving a shared bucket over an
  enumerated set of clients.
- **Rule combination.** Across blocks it is always additive: a request matching several blocks must fit the verdict of
  each, and there is no default deny, so a request outside all rules is allowed. Within a block it follows `mode`: `All`
  (the default) applies every matching rule, `FirstMatch` applies only the first matching rule in list order, which
  makes order semantics. In a `FirstMatch` cascade a `behavior: Shadow` rule counts but does not stop the cascade, a
  `behavior: Bypass` rule terminates the cascade with an allow, and `replacedRules` is rejected by validation. Domain
  compilation is a pure function of the set of its objects: apply order, recreation, and timestamps do not affect the
  result. Ordering is meaningful in exactly one place, the rule list of a `FirstMatch` block within one YAML document.
- **Evaluation is single-pass**, and a refusal rolls nothing back because there is nothing to roll back: matched buckets
  are first only evaluated, and states are written only when no enforcing bucket refused. The two passes live inside one
  atomic store script, so a two-phase compensation protocol is unnecessary by construction. Unlike upstream RLS, which
  charges matched limits regardless of the verdict, a refusal here charges no bucket of the decision. Independence of
  charges applies one level up, between the descriptors of one direct gRPC call: each descriptor is its own decision,
  and one refusal does not touch another descriptor's charges.
- **Rule behavior** is the enum `behavior: Enforce (default) | Shadow | Bypass`. `Shadow` maintains the counter and
  emits metrics, but the rule never contributes to the verdict, which is what makes introducing a limit on live traffic
  possible. A shadow bucket is charged only when its own verdict allows, mirroring enforcement: unconditional charging
  would grow unbounded debt and make the would-be metric report permanent rejection. `Bypass` is an explicit bypass: a
  matched rule allows the request without touching storage, and such a rule carries no `rates`. In an `All` block
  `Bypass` acts only through `replacedRules`; without them it is `InvalidSpec`, since it would otherwise be a silent
  no-op.
- **`replacedRules`** lets a matched rule suppress named other rules, expressing overrides (an enterprise tier replacing
  the default per-client limit) without mutually exclusive `matches` clauses. References resolve within the rule's own
  block only, and only under `mode: All`.
- **Multiple windows per selector** are a `rates[]` list inside one rule: each entry is an independent bucket with its
  own period, and a burst for GCRA; periods are unique within a rule. The algorithm is a property of the entry, the
  window: optional in the entry, GCRA by default, so one rule may carry windows of different algorithms, such as a
  minute rate on GCRA plus a daily quota on fixed window. The engine imposes no cap on the number of windows beyond the
  performance targets.
- **Names.** The block namespace is the policy, which is the domain: block names are unique within a policy and rule
  names within a block (`listType: map`), and the counter key carries the block/rule pair. Renaming a block or a rule
  therefore starts fresh buckets; the old ones expire by TTL, the distortion is at most one window, and a precise
  transfer goes through a management API reset.
- **Value bounds in `rates[]`.** The window period is `periodSeconds`, an integer from 1 to 86 400 (one day) inclusive:
  the Kubernetes API conventions express durations as integers with the unit in the field name, not as strings. Periods
  within a rule are unique (`listType: map`), and the number of windows is unbounded; `requests` and `burst` start at 1
  with an explicit int32 upper bound; `burst` is allowed only in an entry whose effective algorithm is GCRA, explicit
  or default, and defaults to `burst = requests`, a full bucket. The CRD schema holds the ranges (`minimum` and
  `maximum`); the compiler holds the window math (`algo.Check`, `InvalidWindow`), which is not checked at admission.
  Below one second, counting with a network round trip to the store loses its meaning; above one day a counter stops
  being a rate limit and becomes a quota, a long-lived state with different reset and accounting semantics, which the
  engine does not cover. Bounding the period from above also bounds the worst-case key TTL, and with it store memory.
  The schema's lists carry no bounds; the number of blocks, axes, and windows is unbounded, held only by the object
  size and the bucket budget, and the full list is in [limits](limits.md).
- **Path handling and captures.** The query string is stripped from the `path` value before any path predicate is
  applied and before `path` is used as an axis: Envoy's `:path` arrives with it, and without normalization `?page=2`
  splits one endpoint into separate buckets. Placeholders of a block's `Template` routes become descriptor keys visible
  to the rules of that block and usable in their `counters`, giving "a counter per `{orderId}`". Within a block whose
  matched route is a `Template`, the `path` axis takes the template string rather than the raw path, so axis cardinality
  is bounded by construction; when a non-template route matched, capture keys are absent. Placeholder names must not
  collide with the built-in keys `path`, `method`, `token`, and `client`, and the compiler checks it (`InvalidSpec`).
  For `client` the ban is load-bearing: a capture is a value taken from the path, the caller controls the path, and
  `{client}` would let callers pick their own client identity within the block, minting a fresh bucket per invented name
  or writing into someone else's. Collision with a `spec.mappings` key is shadowing: the capture wins within its block,
  and the operator records `CaptureShadowsMappedKey` in `status.ruleProblems`.
- **A missing axis means the rule does not match.** A rule whose `counters` axis is absent from the request (`client` on
  an anonymous call, or a capture of a route that did not match) does not match: there is nothing to key the bucket
  with. This is a mechanism, not an error, and it is what lets a per-user rule skip anonymous traffic with no explicit
  exclusion. An unknown key, one outside the domain's effective set (built-ins plus `spec.mappings` plus block
  captures), blocks the validity of the whole generation (`UnresolvedKeyReference`); a predicate over such a key never
  reaches the matcher, since conditions are validated against the effective set at compile time and there is no runtime
  invariant on top of that. Policies arrive through custom resources only, so a snapshot assembled by hand, bypassing
  the compiler, is outside the contract. `DoesNotExist` therefore means "the key is produced but absent from this
  request", not "nobody has heard of the key": the same compile-time validation is what keeps that reading true.
- **Groups** are defined once, in `spec.groups` of the domain's policy, and are visible to all of its rules. `InGroup`
  naming a non-existent group is a blocking `UnresolvedGroupReference` entry in `status.ruleProblems`.
- **Generation validity is atomic.** The CRD schema cuts off only the shape (patterns, enums, ranges, duplicate names,
  `name == domain`); the content (references, types, structure, window math, budgets, and schema version skew) is judged
  by the operator's compiler on every generation. A generation with at least one blocking problem
  (`UnresolvedKeyReference`, `UnresolvedGroupReference`, `UnresolvedReplacedRules`, `IncompatibleOperator`,
  `InvalidCounterAxis`, `InvalidSpec`, `InvalidWindow`, `DomainBudgetExceeded`) is invalid as a whole: none of its rules
  enters the snapshot, `Ready: False`, `Accepted: False`, and last-good stays in force. Partially enforced generations
  do not exist; otherwise a `FirstMatch` cascade with a dead rule would silently hand traffic to neighboring rules.
  `CaptureShadowsMappedKey` is informational and does not block validity.
- **Claim mappings and groups are part of the policy object** (`spec.mappings`, `spec.groups`), not a separate resource:
  editing them is the same generation as editing rules, applied atomically with it, and the compiler checks the
  references from rules to keys and groups inside the one object. There are no cross-object transactions or gates.
- **Last-good survives restarts.** The operator writes the enforced state of every domain, the good spec with its
  generation and the object UID, into the ConfigMap `ratelimit-config` (gzip in `binaryData`, the generation and the UID
  in the manifest). A generation that compiles replaces the domain's entry; a generation that does not compile is not
  written, and the entry stays as it is if the UID matches, so a recreated policy of the same name inherits nobody's
  good spec; otherwise the domain is empty. A replica that starts enforces what the ConfigMap holds, whether the object
  in etcd compiles or not. A write failure is a `ratelimit_config_write_errors_total` increment by reason and a log
  line; the replicas keep the configuration they mounted, and the status reports `ReplicaStale` 90 s later.
- **The decision budget is bounded statically by the compiler.** The worst case of one decision over the domain, where
  an `All` block sums its counting rules and `FirstMatch` takes its widest counting rule plus every Shadow rule (shadow
  buckets travel to the store like any other), summed over blocks, does not exceed 128 buckets: a generation beyond that
  is a blocking `DomainBudgetExceeded`, and last-good stays in force. The number of blocks is unbounded, since the
  object size keeps the linear scan of targets cheap, and the number of rules is bounded by nothing except the object
  size. The formula also sums blocks with disjoint targets, so it is deliberately pessimistic. The budget binds one
  decision, the decision of one descriptor: a gRPC check with several descriptors is several decisions and several
  atomic scripts, and the adapter bounds the check at 16 descriptors, refused past that before any decision is made, so
  the worst case of one check is 16 scripts of 128 buckets. The engine's runtime backstop refuses a decision that
  gathers more than 128 buckets with `ErrTooManyBuckets`, before the store is touched; that error reports a
  configuration violation, not unavailability, so an adapter maps it to a denial regardless of its fail-open policy, or
  a budget overflow would turn the widest paths into unlimited ones. In normal operation the error is unreachable. The
  contract is pinned by adapter tests: `ErrTooManyBuckets` maps to `OVER_LIMIT` under every fallback setting, and a
  check of two descriptors that each fill the budget is answered `OK`. Every bucket is one read and, on admit, one write
  inside a single atomic script, and an unbounded worst case would let one object monopolize the domain's shard. The
  origin of every number is in [limits](limits.md).

## Counting algorithms

- **Algorithms are pluggable** behind one interface (decide, and report limit, remaining, and retry-after); adding an
  algorithm touches the registry and nothing else.
- **Two algorithms ship**: GCRA (the default: a single value per bucket, no window-boundary doubling, exact
  retry-after) and fixed window (the simplest, universally understood window semantics). The algorithm is selected at
  the `rates[]` entry, the window, and GCRA applies when it is unspecified.
- **A denied request does not consume quota**: a deny never advances counter state. The invariant holds for the decision
  as a whole rather than per bucket: a refused request charges none of its buckets, those that would individually allow
  included; a shadow bucket is charged per its own verdict. GCRA satisfies this natively, and an implementation that
  cannot is not added.
- **The server-side math** is integer microseconds of Unix time: exact in int64 and in Lua doubles alike (integers stay
  exact until about the year 2255), so comparisons need no epsilon guards. The GCRA emission interval rounds up to a
  whole microsecond, so the enforced rate errs only toward the strict side; near the resolution, with intervals under
  100 µs, the period must divide evenly by `requests`, which is a validation error instead of a silent distortion. The
  validation bounds are at most one request per microsecond and a bucket depth `burst × emission ≤ 10¹⁵ µs`: integers
  stay exact in Lua doubles (2⁵³ ≈ 9 × 10¹⁵), and the `time.Duration` nanoseconds (10¹⁸ ns) keep headroom below the
  int64 ceiling. The in-memory reference and the Lua script agree on these formulas, and a differential test catches
  divergence.

## Counter storage

The full contract, the interfaces, and the implementations are in the [store contract](store-contract.md).

- **Counters live in a shared store** (Redis or Valkey) so that correctness is independent of the replica count. The
  engine itself is stateless.
- **One network round trip per decision**, regardless of how many rules matched: one decision is one `EVALSHA` over all
  of its buckets, atomic across them. Pipelining happens only between independent decisions, the descriptors of one
  call. Read-modify-write races between replicas are impossible.
- **The key schema** is `rl:<version>:{<namespace>/<domain>}:<block>/<rule>:<algorithm>:<window>:<axes>:`. There is no
  policy segment, because the domain has one policy and its name is the domain; the namespace segment comes from the
  service's Downward API; the algorithm segment is the lowercase passport name (`gcra`, `fixedwindow`). Every segment is
  terminated, the last one included, so a bucket key is the prefix of its own subtree, which gives management scans and
  partial resets with no hand-built prefixes. The version segment allows counter resets by schema bump. The algorithm
  segment makes switching a live rule's algorithm safe: new buckets start fresh, old ones expire by TTL, and one
  algorithm's state is never read by another's code — fixed window stores an integer counter, GCRA a timestamp — where
  without this segment a switch would mean garbage decisions or Redis `WRONGTYPE` errors. The window segment is
  `periodSeconds`; it separates the buckets of one rule's `rates[]` entries and rules out divergent spellings of the
  same duration. The hash tag wraps the domain: a decision spans several buckets and commits as one atomic script, so
  every key of a domain shares one Redis Cluster slot; the price is one domain bounded by one shard, with domains
  spreading freely. `requests` and `burst` are not in the key, so tuning a limit reinterprets live state (fixed window
  keeps the consumed count, GCRA keeps drain depth in time) rather than resetting it. Keys come from the engine's single
  builder; management and matching agree to the byte.
- **Every key carries a TTL** derived from its rule's period; there is no separate cleanup process.
- **Raw token values never appear in keys.** Identity axes use extracted claims only, so rotating a token resets no
  counter.
- **Time comes from the store** (`TIME` inside the script), not from the replicas: clock skew between pods does not
  affect decisions.
- **A storage failure or timeout fails open**: the request is allowed and an error metric is incremented. Fail closed
  exists only for the unavailability or timeout of the RLS itself, and the gateway filter implements it
  (`failure_mode_deny`, the operator chart's `gateways.<role>.failClosed`), per domain, for consumers that prefer
  rejection over unlimited traffic. A store failure inside the engine always fails open.
- **Store operations carry a budget** of tens of milliseconds, enforced with context timeouts, so a slow store degrades
  to fail-open rather than stalling the gateway filter.

## Token and identity

- **The JWT payload is decoded without verifying the signature.** The trust model: the gateway's `jwt_authn` filter has
  already verified it, and an `AuthorizationPolicy` requires a valid token, so the engine never receives an unverified
  token from a gateway. Direct gRPC callers are trusted by network policy, not by token inspection.
- **Claim extraction is defined in `spec.mappings`** of the domain's policy, the single object of the domain
  (`metadata.name == spec.domain` by CEL; object-name uniqueness in the namespace makes a second object
  unrepresentable). An entry carries `key`; `claim` (a dot path) or `claimPath` (a segment list for claim names
  containing dots); `type: String | StringArray`; `normalization`; and `fallbacks` (the first non-empty result).
  Array-valued claims are supported, which is the reason extraction lives in the engine at all: Istio's
  claim-to-header cannot export arrays. `sub -> client`, lowercased, is built in and works with an empty `mappings`; an
  entry with `key: client` overrides it. The sanitary limits (token size, value length, array size) are engine
  constants, not fields, and axis values are escaped when embedded into counter keys. The mapping is applied atomically
  with the rules: one object, one generation.
- **Values are normalized at extraction**, at minimum by configurable lowercasing, which is what preserves
  case-insensitive membership semantics. Group values (`groups[].clients`) are compared after the effective
  normalization of the `client` key; when `client` is overridden by an entry with `normalization: None`, they are
  compared as written.
- **The raw token never appears** in logs, metrics labels, or storage. Redaction of the `token` descriptor value is part
  of the gRPC server.
- **A missing or undecodable token is not an error**: identity-based keys are absent from the request, rules referencing
  them do not match, and the remaining rules apply. Enforcing token presence belongs to the gateway, not the engine.

## Management surface

The [management API](management-api.md) is served on a port of its own, behind the private gateway and an
AuthorizationPolicy ([chart](helm-chart.md)). `/debug/*` on the metrics port is not the management API: it is read-only
diagnostics with no mutations and no authentication.

- Counters are reset on demand, by rule and by rule plus axis values (a specific client). A reset takes effect
  immediately on the shared store, without a restart.
- The management endpoints are authenticated and never exposed through the gateways' data path.
- Every management mutation is written to a structured audit journal: who called, which key they used, what they
  addressed, and what came of it.
- The read endpoints cover the effective rule set per domain, current usage for a rule or a client, and the list of
  currently limited keys.

## Observability

- **Metrics.** Decisions by domain, rule, and outcome (`ok`, `over_limit`, `shadow_over_limit`) plus a separate
  near-limit counter with a configurable threshold; `unknown_domain` without a domain label, because the caller controls
  the name, which instead goes to a sampled log; storage errors, a decision latency histogram, and a store round-trip
  latency histogram. The extraction metrics are `ratelimit_extraction_skips_total{domain, key, reason}`
  (`decode_failed`, `bad_type`, `too_long`, `too_many_items`) and a per-domain, per-key success counter: together they
  are the "key declared, tokens arriving, zero extractions" detector, the only way to catch a semantically broken claim
  path. Every process also carries `ratelimit_build_info`, labelled with the component and the version it runs. The
  full table of names and labels is in the [chart document](helm-chart.md).
- **Label cardinality is bounded by configuration**: domains and rule names only. There are no per-axis-value metrics,
  and no field in the schema asks for them.
- **Structured logs with redaction**, at most one line per rejected request, sampled if volume requires.
- **The conditions that mean silent misconfiguration or degradation** are `unknown_domain > 0`, storage errors above
  zero, a decision p99 above budget, the extraction detector firing, blocking `ruleProblems` entries on a policy,
  `Stalled: True` (a lagging replica, schema skew, a generation stuck on last-good, a namespace over the 1 MiB ConfigMap
  cap, or a manifest format a replica refuses), and `Ready: False` beyond any reasonable rollout. Neither chart ships
  alert rules; expressions for these conditions are in the [chart document](helm-chart.md).

## Operational envelope

- **Latency.** The gateway filter runs with a ~50 ms timeout and fail-open. The engine's budget within it is p99 ≤ 10 ms
  per decision with the store in the same availability zone, and p99 ≤ 1 ms for decisions that need no store round trip
  (no matching rules, `behavior: Bypass`).
- **Horizontal scaling** by replica count, with no coordination on the decision path and no sticky routing; the store is
  the only shared state. The service has no leader: the operator writes the status and the ConfigMap, and its Lease
  covers its own rollout and has no effect on traffic serving.
- **Propagation.** Rule changes reach every replica within the kubelet sync period, one minute by default, since the
  service reads the ConfigMap through a volume. Replicas may disagree during propagation, bounded by that period, and
  the policy reports `Propagating` for the window: that is the price of a data plane without API access.
- **Graceful shutdown**: stop accepting, drain in-flight decisions, then exit, so a rolling restart of replicas fails no
  request.
- **Throughput.** A single replica sustains at least 5 000 decisions/s within the latency budget on the reference
  resource profile; the figure is validated by a load test in CI.

Measured reference points, non-normative and serving as the module's benchmark baseline (a laptop-class core, Redis 8 on
one core): the storeless engine path takes ~1.4 µs per authenticated decision with a warm token cache and ~3.3 µs cold,
and ~20 ns for a request outside every `target`; the store script costs ~9 µs fixed plus ~3.7 µs per admitted bucket
(the refusal path is ~1.2 µs per bucket, since state serialization is built only in front of an actual write). One
domain is one cluster slot, so its ceiling is on the order of 80 000 decisions/s with one bucket and ~38 000/s with
four. These numbers guard against regressions.

## What the engine does not do

- **Response-status-conditional counting** ("do not count backend 5xx"): the RLS protocol runs on the request path and
  never sees responses. The one case that matters, throttled requests not consuming quota, is guaranteed by the
  deny-never-charges invariant instead. Anything beyond that is `ext_proc` territory.
- **Concurrency (in-flight) limiting**: the protocol has no release call to decrement on a response.
- **Token signature verification, key management, JWKS**: the gateway's job.
- **Billing-grade usage accounting**: counter state answers "may this request proceed", not "how many requests did this
  tenant make last month".
- **Generating or mutating Envoy configuration**: the operator chart owns the gateway filters.
