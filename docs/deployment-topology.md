# Deployment topology: operator and service, singleton policy, composites

Rate limiting is delivered as **two components** per namespace. The operator, `ratelimit-operator`, reads the policies
of its own namespace, validates them, writes them into one ConfigMap, and writes the policy status. The service,
`ratelimit-service`, mounts that ConfigMap, compiles it, and serves gateways over the Envoy RLS protocol. Both are
installed in every namespace where a domain lives: in the application's single namespace or in the baseline of a
composite. There are no cluster-level components: no cluster-wide operator, no ClusterRole, no auxiliary CRs. The only
user-facing resource is `RateLimitPolicy`, one per domain; it holds the rules, the extraction of keys from the token,
and the client groups ([specification](ratelimitpolicy-cr-spec.md)).

## Deployment schemes

Business applications are installed in one of two schemes. The deployer marks the role with one variable:
`BASELINE_ORIGIN` is set, and non-empty, only in a satellite; a baseline and a single namespace do not receive it.

1. **Single namespace.** Everything in one place: both components, the gateway filters, and the policy.
2. **Composite.** A set of related namespaces: one **baseline** and one or more **satellites**. Every namespace has a
   gateway; the operator and the service are installed **only in the baseline**; the policy is placed only in the
   baseline. Satellites get only EnvoyFilters: the RLS address is computed at install time from `BASELINE_ORIGIN` and
   the fixed name of the Service `ratelimit`.

Blue-Green applies to satellites only; the baseline is never Blue-Green'd. Both namespaces of a Blue-Green satellite
receive the same `BASELINE_ORIGIN`, so their filters point at the one baseline RLS, and a switch between them changes
nothing on the rate-limiting side.

The operator sees only its own namespace. A policy placed in a satellite is processed by nobody: it never gets a
status and does not affect traffic. Both charts read `BASELINE_ORIGIN`, so the pair installed in a satellite renders
the EnvoyFilters and nothing else. A service installed there would wait for an operator that never comes, stay
NotReady, and fail the readiness gate of the deployment; the empty render protects against that mistake.

## Composite: one rate-limiting realm

Per-satellite rules do not exist as a class: a composite has one policy per domain. The gateways of all namespaces in
the composite send **the same domain** and one descriptor with four entries (path, method, request_id, token). A
request through the baseline gateway and a request through a satellite gateway are indistinguishable to the service
and are charged against the same buckets; the shared budget is the only behavior, and there is no mode for it.

If a per-satellite need appears, it is added additively: a static descriptor with the namespace name in the filter plus
a built-in key in the service. These entities do not exist today.

## Flows

```text
team ── kubectl apply ──► RateLimitPolicy <domain>                       ns: single | baseline
                                   │  informer (own ns only)
                                   ▼
                          ratelimit-operator ── status ──► RateLimitPolicy
                          (one replica: decode → compile → size check;
                           a Lease covers the rollout overlap)
                                   │  writes the whole object on every reconcile
                                   ▼
                          ConfigMap ratelimit-config                     (the last-good state)
                          (<domain>.json.gz per domain + manifest)
                                   │  the kubelet projects the volume (sync period, 1 min by default)
                                   ▼
                          ratelimit-service ◄── /debug/applied probe ── ratelimit-operator (every 10 s)
                          (REPLICAS replicas: decode → compile → swap; no API access)
                                   ▲            └── atomic Lua ──► Redis Cluster (dedicated, same ns)
                                   │  gRPC ShouldRateLimit
                                   │
gateways (baseline and satellites) with EnvoyFilter ◄── operator chart at install of each ns
```

Two flows cross the picture. On the request path a gateway calls `ShouldRateLimit` on the Service `ratelimit`, and
every service replica decides against the dedicated Redis Cluster. The configuration path runs through the
ConfigMap: the operator validates and writes, the kubelet projects, and the service replicas decode, compile, and swap.

For a visual picture with the composite, the satellites, and the request path, see the
[interaction diagram](topology-diagram.md).

## Resource

`RateLimitPolicy` is one object per domain, `metadata.name == spec.domain`. Inside: `mappings` (which token claims
become keys), `groups` (named client lists), `limits` (limit blocks: target + rules + windows). The resource is atomic:
an edit to the single object changes the rules, the key extraction, and the groups at once; by construction there is
no window between their updates. A second object for the same domain in a namespace cannot be represented: the object
name is unique, and it is also the domain.

The API server checks the object's shape (patterns, enums, ranges, duplicate names, `name == domain`); the content
(cross-field references, window math, domain budgets) is checked by the operator's compiler, which reports through
the status. The full list of bounds and their origin is in [limits](limits.md).

## Components

Two binaries, two images. The operator holds the control plane of its namespace, and the service holds the data
plane:

- **Operator** `ratelimit-operator`: a Deployment with one replica and a Lease that covers the overlap of two pods
  during a rollout. An informer on the `RateLimitPolicy` of its own namespace: event → strict decode → compile → size
  check → a write of the ConfigMap `ratelimit-config` and of the policy status. It is the only writer of both. Its
  chart ships the CRD, its ServiceAccount with the only Role of the delivery, the EnvoyFilters in every mode, and its
  own PodMonitor.
- **Service** `ratelimit-service`: a Deployment with `REPLICAS` replicas. gRPC `ShouldRateLimit` on all replicas, with
  no coordination; the Redis Cluster is dedicated to the service. Every replica mounts the ConfigMap as a whole
  directory at `/etc/ratelimit/config` (`optional: true`), watches the `..data` symlink swap, decodes the manifest
  strictly, compiles every domain with the engine module, and swaps the in-memory snapshot atomically. All replicas
  compile independently and deterministically; there is no shared state between them. Pod name and namespace come
  from the Downward API. Its chart ships the Service `ratelimit`, a ServiceAccount without a mounted token
  (`automountServiceAccountToken: false`), the AuthorizationPolicy of the management port, its own PodMonitor, and
  the Grafana dashboard.
- **Ready of a replica.** A replica that has never applied a manifest is NotReady and out of Endpoints, without a
  timeout. An explicitly empty manifest is a configuration: the replica is Ready, and every request is an unknown
  domain. After the first apply the replica keeps its snapshot in memory and stays Ready if the files vanish or a
  later manifest is refused.
- **RBAC** is the operator's namespace-scoped Role: `ratelimitpolicies` get/list/watch, `ratelimitpolicies/status`
  update/patch, Lease create/update/get, EndpointSlice of the Service `ratelimit` get/list/watch, ConfigMap CRUD, its
  own Deployment get (the ConfigMap's owner), `events` create/patch. No ClusterRole. The service has no Role and no
  token: a depguard rule forbids client-go and controller-runtime under `service/`, and CI reads the build information
  of the service binary and fails when client-go is present.
- **Contract** is a set of constants in one Go package that both binaries import: the Service `ratelimit`, its gRPC
  port 9000 named `grpc`, the probe port published on the Service under the name `metrics` (the service's metrics
  port, 8080 by default), the ConfigMap `ratelimit-config`, the mode rule, and the one namespace for both charts.
  Satellites compute the RLS address from the Service name, `ratelimit.<BASELINE_ORIGIN>.svc.cluster.local:9000` (or
  `BASELINE_CONTROLLER` when the deployer sets it, read for parity with `control-plane`), and the operator reads its
  fleet through the same name. A CI test renders both charts and compares the rendered names and ports with the
  constants, and the [chart document](helm-chart.md) lists the contract.
- **Counter key** carries the service's namespace in the hash tag: `rl:v1:{<namespace>/<domain>}:<block>/<rule>:…`.
  The service substitutes the segment (Downward API), as insurance against two installations connecting to one Redis
  by mistake; filters and gateways take no part in the key shape.
- **Runtime backstop**: a decision that gathers more than 128 buckets is refused (`ErrTooManyBuckets` → `OVER_LIMIT`
  under any failure mode); the budget binds one decision, the decision of one descriptor, and a gRPC check carries at
  most 16 descriptors. The compiler holds the same budget statically (`DomainBudgetExceeded`), so in normal operation
  the backstop is unreachable.
- **`/debug/`** on the service's cluster-internal metrics port is read-only diagnostics. `/debug/applied` reports the
  applied generation and UID per domain, the format versions the replica reads, and a refusal with its reason, and the
  operator reads it for the strict `Ready`. `/debug/snapshot` answers a human with a port-forward: a summary of the
  domains this replica enforces, each with the generation it was applied from, its `ruleSetVersion`, its block, rule,
  and worst-case bucket counts, and its effective keys; `/debug/snapshot/{domain}` renders the compiled domain in full,
  the identity keys with the claim paths behind them and every group resolved into the client list the engine tests.
  Both answer JSON, or YAML on `?format=yaml` or an Accept header that asks for it, and every method but GET is 405.
  Every document is built from one load of the rule set, so a request that lands inside an apply describes one state
  whole. No mutations, no authentication; this is not the management API (a separate port behind the private gateway,
  see [helm](helm-chart.md)) and it is outside the compatibility promises. The binary's version is the
  `ratelimit_build_info` gauge, labelled by component.
- **Management API** lives in the service, on a port of its own behind an AuthorizationPolicy that admits the private
  gateway alone ([helm](helm-chart.md)). Its command records live in the counter store, so the service writes nothing
  to the API server.

## Validation: schema and compiler

The API server rejects on `kubectl apply` only the shape: patterns, enums, ranges, duplicate names, `name == domain`;
the only CEL rule on the CRD is `metadata.name == spec.domain`. Everything that relates fields to each other is judged
by the operator's compiler on every generation, before the write. The service compiles the same spec with the same
engine module to enforce it, so the operator validates exactly what the service enforces:

- predicate and axis references to keys, group references to `groups`, `replacedRules` references to rules of its own
  block; key types against operators and axes;
- structure: predicate arity, `Bypass` and `replacedRules`, `Template` placeholders;
- window math (`algo.Check`) and the domain budget: 128 worst-case buckets;
- **schema version skew**: an object written for a newer CRD schema than the operator. The informer works on
  unstructured objects, and the operator decodes them into the typed structure strictly (`DisallowUnknownFields`):
  an unknown field is a blocking `InvalidSpec` with the field path, an unknown enum value is an `InvalidSpec` from
  the compiler; last-good stays in effect.

An invalid generation produces `status.ruleProblems` entries with the address of the rule, `Accepted: False`,
`Ready: False / NotCompiled`, `Stalled: True`; the operator leaves the last applied generation in the ConfigMap, and
last-good stays enforced until a generation that compiles arrives. A generation that compiles is written only when the
compressed total of the namespace fits the 1 MiB cap of a ConfigMap; one that does not fit is reported with
`Ready: False / ConfigMapTooLarge` and `Stalled: True`, and last-good stays enforced. Why not CEL is in
[limits](limits.md): the cost estimator would force list bounds for its own sake.

## Last-good

The operator persists the active state of every domain of the namespace in one ConfigMap, `ratelimit-config`. Under
`binaryData`, one `<domain>.json.gz` key per domain holds the validated spec in the resource's own format,
gzip-compressed. Under `data`, the `manifest` key holds plain JSON with an integer `formatVersion`, the
`operatorVersion`, and per domain the `generation`, the `uid`, and the `hash` of the content. The operator writes the
whole object on every reconcile, creates it with an `ownerReference` to its own Deployment (deleting the operator
release removes it too), and writes it even when the namespace holds no policy. No chart renders it. A service replica
starts from what the kubelet mounted: if the live object compiles, its generation is in the ConfigMap; if it does not,
the last-good generation is, provided the UID matches, and the status shows the `observedGeneration`/`activeGeneration`
divergence. If there is neither, the domain is empty.

Persistence is needed because an invalid object in etcd is a normal case: an edit with a typo in a reference passes
the API server, and with per-namespace delivery a skew between the operator version and the schema version is a
normal scenario: an object newer than the operator fails the strict decode and stays `InvalidSpec` until the operator
is updated, while the domain runs on last-good the whole time. A rollout restarts all service replicas at once, and
each of them starts from the ConfigMap; without last-good in it such an edit would mean a wholly unprotected domain. A
restart of the operator reads the same ConfigMap back, so the last-good entry survives it as well.

The operator emits `Warning` events on the policy on a ConfigMap write error and on `NotCompiled`, one per generation
change; there are no `Normal` events.

## Status

The policy's conditions follow the Kubernetes API conventions:

- **`Accepted`**: the object compiles (no blocking problems).
- **`Ready`** is strict: **all ready service replicas** execute the latest generation. The operator reads the
  EndpointSlice of the Service `ratelimit`, takes the probe port number from it by the port name `metrics`, fetches
  `/debug/applied` from every ready replica in one round per probe cycle (10 s) that serves every domain of the
  namespace (JSON: per domain `generation`, `uid`, `appliedAt`, plus the format versions the replica reads and a
  refusal with its reason), and writes `status.replicas: {total, applied, summary, lastCheckTime}`; the
  `ratelimit_policy_applied_generation` gauge stays for Prometheus only. It is binary: `False` with a reason
  (`Reconciling`, `Propagating`, `NoReplicas`, `ReplicaStale`, `NotCompiled`, `ConfigMapTooLarge`,
  `ReplicaFormatUnsupported`); `Unknown` only when the operator could not probe the replicas (`ProbeFailed`).
- **`Propagating`** covers the kubelet: it projects a new ConfigMap into the volume within its sync period, one minute
  by default, so after every change the condition reports `Propagating` for up to that long. The threshold that
  separates `Propagating` from `ReplicaStale` is 90 s, above the sync period.
- **`Stalled`** means "stuck" (`ReplicaStale`, `NotCompiled`, `ConfigMapTooLarge`, `ReplicaFormatUnsupported`):
  Argo CD reads it through the platform's Lua check ([helm](helm-chart.md)). `ReplicaFormatUnsupported` names a
  replica that refuses the manifest's format version; the replica keeps its snapshot, stays Ready, and reports the
  refusal on `/debug/applied`.

Scaling and rollouts do not make `Ready` flicker: a pod enters the denominator only once it is ready, that is, once it
has applied the manifest the kubelet mounted at its start, and drops out as soon as it is terminating. Only the
operator writes the status, and the two no-replica cases differ: when the operator is alive but there are no ready
endpoints, the result is `Ready: False / NoReplicas`; when the operator has no pod, nobody can write, the status
freezes, and the age of `lastCheckTime` shows how stale it is. Details and examples are in the
[specification](ratelimitpolicy-cr-spec.md).

## Delivery: monorepo, one application

The code lives in a monorepo; the delivery is **one application**, `ratelimit`, made of **two charts** and **two
images**, `qubership-ratelimit-operator` and `qubership-ratelimit-service`. The charts live under
`helm-templates/ratelimit-operator` and `helm-templates/ratelimit-service`, the deployer installs the same pair in
every namespace, and both derive their contents from `BASELINE_ORIGIN`:

| Scheme | `ratelimit-operator` renders | `ratelimit-service` renders |
| --- | --- | --- |
| single namespace | CRD, Deployment (one replica), ServiceAccount, Role/RoleBinding, EnvoyFilters; behind `MONITORING_ENABLED`, PodMonitor | Deployment (`REPLICAS` replicas), Service `ratelimit`, ServiceAccount, AuthorizationPolicy of the management port; behind `MONITORING_ENABLED`, PodMonitor and GrafanaDashboard |
| composite, baseline | the same | the same |
| composite, satellite | only EnvoyFilters that target the baseline RLS; no ServiceAccount, no RBAC | nothing: an empty release |

Each chart declares only the values its templates read, and shared deployer inputs keep identical key names in both.
`REPLICAS` exists only in the service chart, the filter settings move to the operator chart under `filter`, and
`rls.port` exists in neither: the port is a contract constant. The values are listed in [helm](helm-chart.md).

The repository holds one root Go module plus the engine module: `operator/cmd`, `operator/internal`, and
`operator/Dockerfile`; `service/cmd`, `service/internal`, and `service/Dockerfile`; shared code in the root
`internal/`; the resource types and the contract in `api/`; `config/` and `tests/e2e-go` in the root module. Go's path
rule for `internal` makes an import across the halves a compile error. Both images are built on every pull request
from the components list of `.github/docker-dev-config*.json`.

The repository has one version line, and both images and both charts carry it. The ConfigMap format carries its own
integer `formatVersion` in the manifest: the operator writes version N, and the service reads N and N-1. Any change of
what the operator writes, a field added to the spec included, increments the version. An upgrade installs the service
first, then the operator, and a rollback reverses the order. A fresh installation needs no order: the service waits
NotReady until the operator writes.

**The CRD ships in the operator's chart** with `helm.sh/resource-policy: keep`: the first release in the cluster
installs the type, and deleting a release does not remove the type. Schema changes stay additive. Schema version skew
between namespaces is a normal scenario and is held together by schema compatibility: changes are additive, the API
server's ratcheting lets unchanged fields of old objects through, and an older operator rejects a generation that
carries an unknown field (`InvalidSpec` through strict decoding) and keeps last-good enforced; there is no partial
enforcement.

## Limits

Decision budgets, window math, formats, and the physical walls of the object size are collected in one document that
says where each number comes from and who checks it: [limits and their origin](limits.md). There are no bounds for the
validator's sake. One wall belongs to the configuration channel: the compressed configuration of a namespace, the
ConfigMap `ratelimit-config`, is bounded by 1 MiB. Rules compress about 20 to 40 times and a client list of UUIDs about
1.8 times, so about 45000 UUIDs fill the object; a generation that does not fit is reported with `ConfigMapTooLarge`,
and last-good stays enforced.

## Verification (e2e)

The e2e workflow builds both images from the components list and creates a kind cluster with a lowered kubelet
`syncFrequency`; the stand's kind configuration carries the same setting. It installs both charts in the baseline
namespace, the operator first. The composite scenario runs in CI too: the workflow creates a second, satellite
namespace with its own gateways (a second mesh-config release) and installs both charts there with
`BASELINE_ORIGIN`; the `satellite` suite finds it through `E2E_SATELLITE_NAMESPACE` and skips without it, so a run
against a plain stand still passes. Four specs: the satellite namespace holds the two EnvoyFilters of the operator
chart and no Deployment, Service, ServiceAccount, or Role, and the service chart's release is empty; the satellite
gateway's own Envoy config dump, read instead of the EnvoyFilter object, names
`outbound|9000||ratelimit.<baseline>.svc.cluster.local` as the RLS cluster, so the spec sees what the gateway calls and
not what the chart wrote; a `2/1h` policy (GCRA, so no calendar boundary inside a run) in the baseline admits one
request through each gateway and refuses the third through either, in that order, so the satellite's request has to
land in the bucket the baseline's request opened; and the negative control: a policy placed in the satellite
namespace, on a path of its own, changes nothing for three requests through the satellite gateway and keeps an empty
status for 30 s, because no operator reads that namespace. The same setup on a local stand is the workflow's "Set up
the satellite namespace" step, run with `make test-e2e-go E2E_SATELLITE_NAMESPACE=<namespace>`.

The suites cover both halves:

- The data-plane suites (`ratelimit`, `jwt`, `budget`, `failopen`, `redis`, `shadow`, `unknowndomain`, `management`,
  `snapshot`) exercise the service through the gateway, the management port, and the diagnostics port.
- The `policy`, `lagging`, `rollout`, `metrics`, and `satellite` suites cover the configuration path: the operator
  writes the status and the ConfigMap, and a policy change reaches the replicas through the volume.
- The operator suite covers its rollout: the one pod is replaced under the Lease, rate limiting continues throughout,
  and the new pod resumes the status writes.
- The `coldstart` suite covers a service without an operator: a replica started with only the ConfigMap to stand on
  enforces the last-good spec and reports Ready, and a replica started with no ConfigMap stays NotReady and out of
  Endpoints until the operator writes.
- Further specs cover an operator without a service (`NoReplicas`), an unsupported format
  (`ReplicaFormatUnsupported`), the size limit (`ConfigMapTooLarge`), and a deleted ConfigMap (the replicas keep their
  snapshot and stay Ready until the operator writes the object again).

Three scenarios verify the strict `Ready`:

1. **Same-version rollout** of the service: `Ready` stays `True` throughout, and `status.replicas` counts the whole
   fleet once the rollout settles; this is the guarantee under test.
2. **Lagging replica**: one service replica is made unreachable for the operator's probe (an AuthorizationPolicy that
   denies its metrics port): `Ready: False / Propagating`, then after the 90 s threshold `ReplicaStale` and
   `Stalled: True` with the pod name, and `True` once the replica is reachable again.
3. **Propagation**: after a policy change the condition passes from `Propagating` to `True`; the spec asserts the
   sequence rather than its duration, because the kind cluster runs with a lowered kubelet `syncFrequency`, and the
   production delay is the sync period documented under [Status](#status).

Version skew between the operator and the service is verified by unit tests, not by e2e: golden manifests per format
version live in the repository, a decoder test reads all supported ones, and a check fails when the writer's output
changes without a new version. No e2e mixes images of two versions; the unsupported-format spec above covers the
refusal path.
