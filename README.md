# ratelimit

Rate limiting for an Istio ambient mesh with two ingress gateways. The gateways call this service over the Envoy rate
limit service (RLS) protocol; the rules arrive as `RateLimitPolicy` custom resources.

| Item          | Value                                                                       |
|---------------|-----------------------------------------------------------------------------|
| API group     | `ratelimit.netcracker.com`                                                  |
| Kind          | `RateLimitPolicy` — one per domain, holding rules, identity keys and groups |
| gRPC RLS port | 9000                                                                        |
| Health probes | 8081                                                                        |
| Scope         | namespaced — one installation, one namespace                                |

**What is built today**: the resource and its validation, the lifecycle around it — atomic generations, last-good
fallback, and the fleet view behind the `Ready` condition — and the decision engine that enforces the compiled rules.
Counters live in Redis when `redis.addresses` is set, which is what makes a limit a limit of the domain rather than of
each replica; without it each replica counts in its own memory and a limit of 100 admits 100 per replica.

**What is not built**: the gateways do not verify the tokens they forward. The identity-keyed rules below extract claims
from the `authorization` header without checking a signature, so a limit keyed on `client` or `tenant` is only as
trustworthy as the traffic reaching the gateway. Put `jwt_authn` ahead of the rate limit filter before relying on one to
separate tenants.

## How it fits together

A policy binds to a gateway through a domain string that has to match on both sides: the rate limit filter of the
gateway carries it, and the CR names it. Nothing validates the match. A mismatch surfaces only as an `unknown rate limit
domain` line in the service log, so that line is the one to alert on.

On every request the gateway sends one flat descriptor — `path`, the `authorization` header as `token`, and
`x-request-id`. Those are the inputs the schema is written against: a rule matches on identity read out of the token,
and on the path through the routes of its block.

The delivery is two components in one namespace, joined by one ConfigMap. The operator, one replica, watches the
policies of its namespace, compiles them, and writes `ratelimit-config`: a manifest with the generation, UID, and
content hash of every domain, and one compressed payload per domain. The service replicas mount that ConfigMap as a
volume, hold no Kubernetes credentials at all, apply what the kubelet projects, and answer checks from it. The operator
also reads `/debug/applied` on every ready replica through the Service and writes the policy status from what it
finds. The operator's Lease covers the overlap of two pods during its own rollout; it signs the lease with its pod
name, which the chart passes as `POD_NAME` through the Downward API.

| Component            | Runs in               | Does                                                             |
|----------------------|-----------------------|------------------------------------------------------------------|
| Configuration writer | the operator          | compiles the namespace, writes `ratelimit-config` on every event |
| Status reconciler    | the operator          | probes the replicas; writes `Accepted`, `Ready`, `Stalled`       |
| Configuration reader | every service replica | applies the mounted ConfigMap on the kubelet's swap of it        |
| gRPC RLS server      | every service replica | answers a check                                                  |

The split is a security requirement as much as an operational one: the process that parses tokens from the internet
reaches no API server object, and the operator and the service roll out, restart, and scale on their own.

## The resource model

A domain is one object. `metadata.name` equals `spec.domain` and object names are unique within a namespace, so a
second policy for a domain cannot be created: the API server rejects it with `AlreadyExists`, and there is no "which of
the two wins" question to answer. Compilation is a pure function of the
objects, so the order they arrived in, their recreation, and their timestamps change nothing.

A block is a target plus rules. **Blocks always add up**: a request that lands in several has to fit the verdict of
each. `mode` decides only how the rules inside one block combine — `All` applies every matched rule, `FirstMatch`
applies the first one and makes the order of the list the meaning. `behavior: Bypass` ends its own block with a pass and
touches no counter; `behavior: Shadow` counts and records but never rejects, which is how a tighter limit is tried out
over a live one.

A rule carries axes (`counters`) and windows (`rates`). Each window is an independent bucket, so a smoothed minute and a
daily quota live in one rule and either can reject. `GCRA` meters at a steady rate with a burst allowance; `FixedWindow`
counts per wall-clock window and resets at the boundary. A rule whose axis the request does not carry does not match at
all — there is nothing to key the bucket by, which is what excludes an anonymous caller from a rule counting by
`client`.

`spec.mappings` declares how identity is read out of the JWT and `spec.groups` holds the named client lists `InGroup`
resolves against. Both live in the same object as the rules that reference them, which is the point of the singleton:
they change in one edit and apply as one generation, so a request never sees new rules over old extraction. The
built-in `client` key — the `sub` claim, lower-cased — works with no mapping at all, and an entry named `client`
overrides it.

`config/samples/` holds a full public-gateway policy and a production Azure API Management policy translated into one
`RateLimitPolicy`. An envtest spec applies all of them against a real API server on every `make test`, so a
sample that stopped being valid fails the build.

### A generation is enforced whole or not at all

The schema rejects what it can see; the compiler reports what needs the domain to judge. Those land in
`status.ruleProblems`, and the `PROBLEMS` printer column counts them:

| Reason                     | Weight        | Means                                                                       |
|----------------------------|---------------|-----------------------------------------------------------------------------|
| `UnresolvedKeyReference`   | blocking      | nothing produces the key — no built-in, no mapping, no capture              |
| `UnresolvedGroupReference` | blocking      | `InGroup` names a group the policy does not define                          |
| `UnresolvedReplacedRules`  | blocking      | `replacedRules` names a rule outside its own block                          |
| `IncompatibleOperator`     | blocking      | the operator cannot apply to the type of the key, e.g. `Equals` on an array |
| `InvalidCounterAxis`       | blocking      | an array key cannot key a bucket                                            |
| `InvalidSpec`              | blocking      | a structural defect the schema cannot see, an unknown field among them      |
| `InvalidWindow`            | blocking      | a window the counting math cannot honor                                     |
| `DomainBudgetExceeded`     | blocking      | the worst-case decision is over 128 buckets                                 |
| `CaptureShadowsMappedKey`  | informational | inside this block a route capture wins over the mapped key                  |

One blocking entry invalidates the whole generation: not one of its rules enters the snapshot. Applying the healthy
rules of a broken generation would be worse than applying none — a `FirstMatch` cascade missing a rule silently hands
its traffic to the neighbours, which are stricter or looser than the author intended, and nothing in the response says
so.

The blast radius is the domain, and the last-good generation keeps serving it. A typo therefore costs an answer, never
the limits: it gives a status that says which reference does not resolve, while the rules that were running go on
running.

## Two generations: observed and active

A policy reports a pair. `observedGeneration` is the latest spec the operator has seen; `activeGeneration` is the one
actually being enforced. They diverge when the latest edit does not compile and an earlier, last-good generation keeps
running. `activeGeneration: 0` means the domain is unprotected: nothing is in effect at all.

```console
$ kubectl get rlp
NAME              READY   REPLICAS   RULES   PROBLEMS   AGE
gateway.public    False   3          5       1          5d
gateway.private   True    3          2       0          5d
```

Reading it: the latest generation of `gateway.public` does not compile, an earlier one is still serving its five rules,
and `Accepted` carries the summary while `ruleProblems` carries the address of the rule at fault.

Last-good specs are what `ratelimit-config` carries: one gzipped payload per domain, the validated spec of the
generation in effect, beside a manifest with its generation, UID, and hash. etcd holds only the latest generation of
the policy, which may be the rejected one; the ConfigMap is the copy that lets a service replica born after the edit
enforce the good spec, and lets the operator restart without forgetting what is running. The operator writes it whole
on every reconcile, and a UID check keeps a recreated object from inheriting the spec of its namesake.

### Ready is a statement about every replica

The operator pod holding the Lease is the only process that writes status, but "the rules I wrote are the rules being
enforced" is only true when every pod receiving traffic says so. The operator therefore reads `/debug/applied` from
each ready endpoint of the service's Service — read-only diagnostics on the metrics port, no mutations and no
authentication — and compares the generation and UID each replica reports with the one it expects.

The same port answers `/debug/snapshot` for a human: a summary of the domains a replica enforces, with the generation
each was applied from, and `/debug/snapshot/<domain>` with the compiled domain in full, the identity keys with the
claim paths behind them, and every group resolved into the client list the engine tests. Add `?format=yaml` for
YAML. Read it through a port-forward to one pod, and compare pods when a rollout looks skewed:

```bash
kubectl -n <namespace> port-forward pod/<service-pod> 8080:metrics
curl -s localhost:8080/debug/snapshot/gateway.public?format=yaml
```

The denominator is the ready endpoints, not the Deployment's `spec.replicas`: a pod that is not ready receives no
traffic, so it neither enforces anything nor belongs in the fraction. That is also what keeps `Ready` from flickering
during a rollout — a new pod joins only once ready, and it becomes ready after its first compilation, already on the
current generation.

`Ready` is the summary; `Stalled` separates "in progress" from "stuck", so a rollout pages nobody and a broken informer
does:

| Situation                                                    | `Ready` | `Stalled` | Reason         |
|--------------------------------------------------------------|---------|-----------|----------------|
| every ready replica enforces the latest generation           | True    | False     | `AllReplicas`  |
| no replica has taken the new generation up yet               | False   | False     | `Reconciling`  |
| some have, and the lag is under 30 s                         | False   | False     | `Propagating`  |
| the Service has no ready endpoint                            | False   | False     | `NoReplicas`   |
| a replica lags past the threshold: broken informer, or skew  | False   | True      | `ReplicaStale` |
| the latest generation does not compile, last-good is running | False   | True      | `NotCompiled`  |
| the operator could not observe the replicas at all           | Unknown | False     | `ProbeFailed`  |

For Argo CD: `Stalled: True` is Degraded, `Ready: True` is Healthy, everything else is Progressing. A sync wave closes
only once every pod enforces the rules.

## Install

The delivery is two charts under `helm-templates/`, installed into one namespace in either order:

```bash
helm upgrade --install ratelimit-operator helm-templates/ratelimit-operator \
  --namespace <business-namespace> \
  -f helm-templates/ratelimit-operator/resource-profiles/dev.yaml \
  --set image.tag=<tag>
helm upgrade --install ratelimit-service helm-templates/ratelimit-service \
  --namespace <business-namespace> \
  -f helm-templates/ratelimit-service/resource-profiles/dev.yaml \
  --set image.tag=<tag>
```

The profile is not optional. Each chart's `resource-profiles/` holds the four the platform deployer picks from, `dev`,
`dev-ha`, `prod-nonha`, `prod`, and they are the only source of `CPU_REQUEST`, `MEMORY_REQUEST`, `CPU_LIMIT`,
`MEMORY_LIMIT`, and, for the service, `REPLICAS`. Each `values.schema.json` requires its keys, so an install without
`-f` fails with `missing properties 'CPU_REQUEST', ...` rather than rendering a Deployment with empty resources. The
`-ha` and `prod` profiles of the service differ from their siblings only by running two replicas; the operator runs one.

`MEMORY_LIMIT` is not only a cgroup ceiling: the platform's `memlimit` package derives `GOMEMLIMIT` from it at startup,
so it governs when the Go heap starts collecting.

`ratelimit-operator` renders the CRD, one operator replica with the only `Role` of the delivery, one `EnvoyFilter`
per enabled gateway, and a `PodMonitor`. Its values are the filter's (`filter.*`; the port the filters send checks
to is the contract's 9000 and not a value), `runtime.*`, `gateways.*`, the gateway names, and the resource sizes
without `REPLICAS`. It installs no `ClusterRole` and no `ClusterRoleBinding`; the `Role` reaches the ConfigMap
`ratelimit-config` and the operator's own Deployment by name, and nothing else in the namespace beyond the policies,
the Lease, the Events, and the EndpointSlices.

`ratelimit-service` renders `REPLICAS` service replicas that mount the `ratelimit-config` ConfigMap at
`/etc/ratelimit/config` with `optional: true`, hold no token and no `Role`, the `Service` `ratelimit` with the ports
`grpc`, `metrics`, and `management`, the management `AuthorizationPolicy`, a `PodMonitor`, and the dashboard. Its
values are `redis.*`, `healthProbe.*`, `metrics.*`, `management.*`, and the five resource keys. Neither chart renders
the ConfigMap: the operator writes it. Both read `BASELINE_ORIGIN` the same way: a satellite gets the filters from the
operator chart and nothing from the service chart, so the deployer installs the same pair in every namespace.

The `Service` is named `ratelimit` whatever the release is called, and `fullnameOverride` does not rename it. A
satellite computes the RLS address from that name and the baseline's namespace, so the name cannot depend on how the
baseline was installed. The CI install exercises exactly that shape by naming its releases after the charts with a
suffix.

The management port, when `management.enabled` is set, is exposed on the same `Service` rather than on one of its own.
The `AuthorizationPolicy` that keeps the port reachable from the private gateway alone is enforced at the pod, so a
dedicated `Service` would add a name without adding a boundary; the gateway's `HTTPRoute` names the port on the one
`Service`. The identity the API reads is configured under `management.claims` (the claim names, dotted for a nested
claim such as `realm_access.roles`) and `management.roles` (the IdP's role names mapped onto `viewer` and `operator`).

An empty `redis.addresses` selects the in-process counter store, which counts per replica. The service chart accepts
it only with `REPLICAS: 1`; any other count fails the render with `in-process store needs exactly one replica; set
redis.addresses`, because a limit of 100 across three replicas would admit 300.

A fresh installation needs no order: the service waits `NotReady` until the operator writes. An upgrade installs the
service before the operator and a rollback reverses the order, because the service reads the current and the previous
manifest format version and the operator writes the current one. The root of each schema is open, so the deployer's
one parameter set reaches both charts and each ignores the other's blocks; the blocks a chart reads are closed. A CI
test renders both charts and compares the Service name and ports, the filters' address, the volume's ConfigMap, and
the mount path with the constants of `api/contract`.

A policy change reaches the service replicas within the kubelet's sync period, one minute by default: the operator
writes the ConfigMap at once, and the kubelet projects it into the volume on its next sync. `Ready` on the policy
reads `Reconciling` and then `Propagating` for that window and `True` once every replica applied the generation. The
e2e clusters lower the period to seconds (`tests/e2e/kind-config.yaml`); production keeps the default.

### Composite installations

A business application is installed either into one namespace or as a composite: one baseline namespace plus
satellites, each with its own gateway. Every gateway of the composite sends the same domains, the component runs in the
baseline alone, and a satellite gets the gateway filters and nothing else.

Both charts read the deployer's composite variables, the same ones `core-operator` renders by:

| `BASELINE_ORIGIN` | Operator chart renders            | Service chart renders | Filters send checks to             |
|-------------------|-----------------------------------|-----------------------|------------------------------------|
| empty             | everything                        | everything            | `ratelimit.<own namespace>:9000`   |
| set               | the `EnvoyFilter` objects only    | nothing               | `ratelimit.<BASELINE_ORIGIN>:9000` |

`BASELINE_CONTROLLER` is read for parity with `control-plane`, which resolves the baseline the same way, and takes
precedence over `BASELINE_ORIGIN` as the target namespace when set. On this platform the baseline is never blue-green'd,
so the deployer leaves it empty. The e2e workflow and the local install above run in the first row.

The gateway names are not this chart's to choose. They are deployment parameters shared with
`qubership-core-mesh-config`, the chart that creates the `Gateway` objects, and the deployer injects the same set into
every chart of the application:

```yaml
ISTIO_PUBLIC_GATEWAY_NAME: public-gateway
ISTIO_PRIVATE_GATEWAY_NAME: private-gateway
```

Override them in one chart and not the other, and the `EnvoyFilter` attaches to a gateway that does not exist — with no
error, because a `targetRefs` pointing at a missing `Gateway` is simply inert.

What this chart owns per gateway is whether to rate limit it and under which domain:

```yaml
gateways:
  public:
    enabled: true
    domain: gateway.public
  private:
    enabled: true
    domain: gateway.private
```

`namespace` is accepted per gateway and defaults to the release namespace. `qubership-core-mesh-config` sets no
`metadata.namespace` on its Gateways, so they land in the business namespace next to this release and the default is
right. Set it only if they move — Istio resolves `targetRefs` within the `EnvoyFilter`'s own namespace, so the filter
has to follow the gateway.

### The CRDs are shared

`ratelimitpolicies.ratelimit.netcracker.com` is cluster-scoped, and every namespace installation shares that one
object. With several per-namespace releases, the releases race for its ownership and version. The chart annotates it
with `helm.sh/resource-policy: keep` so that uninstalling one release does not take it — and every other namespace's
policies — with it. Settle CRD upgrade ownership with the platform
team: this is a deploy-time concern, and the service itself never touches the CRD objects.

## Develop

```bash
make build              # compile both binaries, bin/ratelimit-operator and bin/ratelimit-service
make test-unit          # unit tests only; no envtest, no cluster, no network
make test               # everything, including the envtest controller suite
make manifests generate # regenerate the CRD, the RBAC, and the DeepCopy methods
make sync-helm-crds     # copy the generated CRD into the operator chart (alias: make helm-crd)
make lint               # golangci-lint
make helm-lint          # helm lint of both charts against their values.schema.json
```

`make test-e2e-go` runs the Ginkgo suites in `tests/e2e-go/` against a cluster that already has Istio ambient, the two
gateways, and this chart installed — it installs nothing and uninstalls nothing, so point it at a namespace where the
release is already deployed. It writes a JUnit report to `artifacts/e2e-go.xml` and renders it as
`artifacts/e2e-go.html` (via `tests/e2e-go/report`); CI uploads both as the `e2e-go-report` artifact, and attaches the
stdout of every pod the run touched — captured by `tests/e2e/manifests/fluent-bit.yaml`, split per pod — as
`e2e-pod-logs`:

```bash
make test-e2e-go E2E_NAMESPACE=core
```

The `satellite` suite needs a second namespace, installed as a satellite of the first: its own gateways from a second
`mesh-config` release, both charts with `BASELINE_ORIGIN` set to the baseline's namespace, and the probe backend.
Name it in `E2E_SATELLITE_NAMESPACE` and the suite proves the composite model against it: a policy of two requests an
hour in the baseline, one request through each gateway, a third refused through either, and a policy placed in the
satellite that gets neither a status nor an effect. Without the variable the suite skips. The recipe for the namespace
is the workflow's "Set up the satellite namespace" step; the command below runs the suite against it:

```bash
make test-e2e-go E2E_NAMESPACE=core E2E_SATELLITE_NAMESPACE=core-sat
```

The `redis` suite is the exception to "run everything": it asserts what only a
shared counter store can do — that the operator selected Redis rather than
falling back, that the counters carry the documented key, and that a spent budget
survives the process that spent it. An install without `redis.addresses` is a
valid install, so that suite skips rather than fails on one.

It covers what no unit test can: that the installed CRD is the one carrying the current validation, that a policy
change reaches every service replica through the ConfigMap, that an earlier generation keeps running while an edit is
rejected and the last-good state stays in `ratelimit-config`, that a replica reports what it enforces on
`/debug/snapshot`, that the gateway is configured with this release's Service and the agreed descriptors, that the
stub refuses traffic over its limit with 429 and allows it again when the window reopens, that the two gateways count
independently, and that a check logs its domain and path and request id while never logging the `Authorization`
value.

The `operator` suite is the exception to "changes nothing": that every replica applies the configuration cannot be
observed with a single one, so it scales the service release to two, deletes the operator pod, and asserts that the
checks stay clean on every replica while the pod is replaced, that the Lease moves to the replacement, and that the
replacement resumes the status writes. It restores the original replica count through Helm — a `kubectl scale` would
take field-manager ownership of `.spec.replicas` and make every later `helm upgrade` conflict.

`make test` runs the envtest suites of `operator/internal` against a real API server, which is where the CRD schema
and the status subresource actually exist — the fake client the other tests use validates nothing. The first run
downloads the envtest binaries into `bin/`, so it needs internet; `make test-unit` never does. Both derive their
Kubernetes version from `go.mod`, so the test control plane cannot drift from the client libraries the operator is
built against.

`helm-templates/ratelimit-operator/templates/crd-*.yaml` is generated. Edit the Go types and run `make sync-helm-crds`
instead of editing them.

The CRD carries CEL rules, and the cost estimator budgets each one against the declared `MaxLength` and `MaxItems`. Two
structural checks the estimator would not accept live in the compiler instead — template placeholder uniqueness, and
`replaces` naming a rule of its own block — and a policy failing either is rejected with `Accepted: False`, exactly as
the API server would have rejected it.

Run the pair from your host. The operator talks to the cluster of your current kubeconfig; the service talks to
nothing but a directory, which `make service-config` fills from the live `ratelimit-config` of the namespace:

```bash
CLOUD_NAMESPACE=<ns> make service-config   # export the ConfigMap into bin/config
CLOUD_NAMESPACE=<ns> make run              # the operator and the service together
CLOUD_NAMESPACE=<ns> make run-operator     # or one at a time
CLOUD_NAMESPACE=<ns> make run-service
```

The operator is told its Deployment's name as the chart tells it (`OPERATOR_DEPLOYMENT`, `ratelimit-operator` by
default); off cluster it warns that there is no Deployment to adopt and writes the ConfigMap without an owner. It
probes the service replicas at their pod IPs, so from a host that cannot reach the pod network, kind included, every
policy reads `Ready: Unknown` with `ProbeFailed`; the status is right, the host is not a peer of the pods. The service
reads `SERVICE_CONFIG_DIR` (`bin/config` by default) the way it reads the mounted volume in a pod, and any directory
holding a manifest and its payloads works. In the pair the service keeps the defaults, metrics on `:8080` and probes
on `:8081`, and the operator moves to `:8090` and `:8091` (`OPERATOR_METRICS_ADDR`, `OPERATOR_PROBE_ADDR`), since
both binaries default to the same two ports and whichever binds second would die. `make docker-build` builds both
images, `OPERATOR_IMG` and `SERVICE_IMG`, from the two Dockerfiles.

`CLOUD_NAMESPACE` has no default. An unset value is a startup error for either process, not a fallback to watching
the cluster: it is what keeps the operator's RBAC a `Role`, and it is a segment of every counter key the service
writes. It is read through `configloader`, so any property source the platform configures can supply it.
