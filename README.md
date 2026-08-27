# ratelimit

Rate limiting for an Istio ambient mesh with two ingress gateways. The gateways call this service over the Envoy rate
limit service (RLS) protocol; the rules arrive as `RateLimitPolicy` custom resources.

| Item          | Value                                                                    |
|---------------|--------------------------------------------------------------------------|
| API group     | `ratelimit.netcracker.com`                                               |
| Kinds         | `RateLimitPolicy` (rules), `RateLimitMapping` (identity keys and groups) |
| gRPC RLS port | 9000                                                                     |
| Health probes | 8081                                                                     |
| Scope         | namespaced — one installation, one namespace                             |

**What is built today**: the two resources and their validation, the lifecycle around them — atomic generations,
last-good fallback, and the transaction gate on a mapping update — and the decision engine that enforces the compiled
rules. Counters live in Redis when `redis.addresses` is set, which is what makes a limit a limit of the domain rather
than of each replica; without it each replica counts in its own memory and a limit of 100 admits 100 per replica.

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

Controller and RLS endpoint share one binary and one Deployment. `--mode=all|controller|rls` selects the components, so
splitting them later is a Helm change rather than a refactor. Only `all` is exercised today.

| Component       | Runs on       | Leader election | Does                                                       |
|-----------------|---------------|-----------------|------------------------------------------------------------|
| Store updater   | every replica | no              | recompiles every domain on any policy or mapping event     |
| gRPC RLS server | every replica | no              | answers a check; a stub until the evaluator lands          |
| Reconcilers     | leader only   | yes             | write `Accepted`, `Ready`, `ruleProblems`, `effectiveKeys` |
| State writer    | leader only   | yes             | persists the last-good spec of each object before a swap   |

The split is a correctness requirement. `Reconcile` runs on the leader alone, so a store filled there would leave every
other replica answering checks from an empty store — limits that apply on some pods and not others.

## The resource model

Policies are units of ownership and review rather than units of evaluation. Any event recompiles the whole domain, and
after compilation there are no policies left — one flat set of blocks. Compilation is a pure function of the set of
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

`RateLimitMapping` is the singleton of its domain, and the singleton comes out of the naming rule rather than out of
arbitration: `metadata.name` equals `spec.domain`, and object names are unique in a namespace, so a second mapping for
one domain cannot be created. It declares how identity is read out of the JWT and holds the client groups the policies
of the domain share. A policy does not wait for it, and does not run half-way either: a policy over built-in keys alone
works with no mapping present, while one referencing declared keys or shared groups is invalid as a whole until the
mapping appears.

`config/samples/` holds a full public-gateway policy, a mapping, and a production Azure API Management policy translated
into one `RateLimitPolicy`. An envtest spec applies all of them against a real API server on every `make test`, so a
sample that stopped being valid fails the build.

### A generation is enforced whole or not at all

The schema rejects what it can see; the compiler reports what needs the domain to judge. Those land in
`status.ruleProblems`, and the `PROBLEMS` printer column counts them:

| Reason                     | Weight        | Means                                                                       |
|----------------------------|---------------|-----------------------------------------------------------------------------|
| `UnresolvedKeyReference`   | blocking      | nothing produces the key — no built-in, no mapping, no capture              |
| `UnresolvedGroupReference` | blocking      | `InGroup` names a group neither the policy nor the mapping defines          |
| `IncompatibleOperator`     | blocking      | the operator cannot apply to the type of the key, e.g. `Equals` on an array |
| `InvalidCounterAxis`       | blocking      | an array key cannot key a bucket                                            |
| `CaptureShadowsMappedKey`  | informational | inside this block a route capture wins over the mapped key                  |

One blocking entry invalidates the whole generation: not one of its rules enters the snapshot. Applying the healthy
rules of a broken policy would be worse than applying none — a `FirstMatch` cascade missing a rule silently hands its
traffic to the neighbours, which are stricter or looser than the author intended, and nothing in the response says so.

The blast radius is the policy itself. That makes the layout of a namespace a design choice: keep the safety-net total
limits in a small policy of their own, over built-in keys, where it can hardly ever become invalid.

A typo therefore costs a policy, never a trap: it gives rules that do not run, and a status that says which reference
does not resolve.

## Two generations: observed and active

Every object reports a pair. `observedGeneration` is the latest spec the operator has seen; `activeGeneration` is the
one actually being enforced. They diverge when the latest edit is rejected and an earlier, last-good generation keeps
running. `activeGeneration: 0` means nothing of this object is in effect.

```console
$ kubectl get rlp
NAME           DOMAIN           READY   PROBLEMS   ACTIVE   AGE
order-mgmt     gateway.public   False   1          3        5d
api-defaults   gateway.public   True    0          7        5d
```

Reading it: `order-mgmt` generation 4 does not compile, and generation 3 is still serving traffic. The `Ready` reason
names the fix — `MappingRequired` when the domain has no mapping at all, `UnresolvedReferences` when it has one that
does not declare the key, `IncompatibleReferences` when the reference resolves but cannot be used that way,
`InvalidSpec` when the spec is structurally wrong.

Last-good specs are persisted, one gzipped ConfigMap per domain (`ratelimit-state-<domain>`), because etcd holds only
the latest generation — which may be the rejected one. Without the copy a restart would forget what is running and turn
a rejected edit into an outage at the next rollout. The write happens before the snapshot swap, so a crash in between
converges to a state that was valid when it was written, and a UID check keeps a recreated object from inheriting the
specs of its namesake. Only the leader writes; every replica reads once, at startup.

### Updating a mapping is a transaction

A mapping is a platform resource that the policies of many teams depend on, so a new generation of it has to pass a
gate: **it is accepted only if no policy that is running something would be left with nothing to run.**

```text
candidate = built-in keys + the new mapping spec
for each policy of the domain:
    running before = its active spec, or nothing
    running after  = its latest spec if valid under the candidate,
                     else its last-good spec if valid under the candidate,
                     else nothing
    running before != nothing and running after == nothing  ->  veto
```

Any veto and the candidate is refused: `activeGeneration` stays where it was, `Ready` goes false with
`RejectedByPolicies`, and `status.rejectedBy` names every culprit with the generation that was vetoing — which may be an
active generation rather than the latest one, because that spec may no longer exist as written.

Two properties of the gate are worth stating, because they are the ones that make it usable:

- **A policy already broken by its own spec has no vote.** A vote is a veto, and only the policies the candidate makes
  worse get one. If the gate demanded validity of everything, one team's typo would freeze a platform resource for the
  whole domain forever. Such a policy is not forgotten — it is re-checked after the candidate lands and revives as soon
  as either side is fixed.
- **The latest spec wins over the last-good one in "running after".** etcd is the desired state and a last-good spec is
  a crutch, so as soon as the desired spec becomes valid under the candidate it is the one that would run. Without that
  priority a stuck policy could never be fixed through the mapping: its stale spec would demand compatibility with
  itself forever.

A deliberately breaking change — renaming or removing a key — goes expand/contract. Add the new name alongside the old
one (no regression, accepted), let the teams migrate, then remove the old name. The gate tells you when the second step
is safe: until someone has migrated, it refuses the change and lists who is behind.

Symmetry of responsibility: a broken policy punishes only itself, and a broken mapping punishes nobody. **Deleting** a
mapping is outside the gate — it is a deliberate administrative act, the domain falls back to its built-in keys, and the
policies depending on it lose validity. RBAC is the guard against doing it by accident, not the controller.

## Install

```bash
helm upgrade --install ratelimit helm-templates/ratelimit \
  --namespace <business-namespace> \
  -f helm-templates/ratelimit/resource-profiles/dev.yaml \
  --set image.tag=<tag>
```

The profile is not optional. `resource-profiles/` holds the four the platform deployer picks from — `dev`, `dev-ha`,
`prod-nonha`, `prod` — and they are the only source of `CPU_REQUEST`, `MEMORY_REQUEST`, `CPU_LIMIT`, `MEMORY_LIMIT` and
`REPLICAS`. `values.schema.json` requires all five, so an install without `-f` fails with `missing properties
'REPLICAS', 'CPU_REQUEST', ...` rather than rendering a Deployment with empty resources. The `-ha` and `prod` profiles
differ from their siblings only by running two replicas.

`MEMORY_LIMIT` is not only a cgroup ceiling: the platform's `memlimit` package derives `GOMEMLIMIT` from it at startup,
so it governs when the Go heap starts collecting.

The chart installs a `ServiceAccount`, a `Role` and `RoleBinding` pair, a `Deployment`, a `Service`, both CRDs, and one
`EnvoyFilter` per enabled gateway. It installs no `ClusterRole` and no `ClusterRoleBinding`. The `Role` also carries
`configmaps` in its own namespace, for the last-good state described above.

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

`ratelimitpolicies.ratelimit.netcracker.com` and `ratelimitmappings.ratelimit.netcracker.com` are cluster-scoped, and
every namespace installation shares those two objects. With several per-namespace releases, the releases race for their
ownership and version. The chart annotates both with `helm.sh/resource-policy: keep` so that uninstalling one release
does not take them — and every other namespace's policies — with it. Settle CRD upgrade ownership with the platform
team: this is a deploy-time concern, and the service itself never touches the CRD objects.

## Develop

```bash
make build              # compile the manager binary
make test-unit          # unit tests only; no envtest, no cluster, no network
make test               # everything, including the envtest controller suite
make manifests generate # regenerate the CRD, the RBAC, and the DeepCopy methods
make sync-helm-crds     # copy the generated CRD into the chart (alias: make helm-crd)
make lint               # golangci-lint
make helm-lint          # helm lint against values.schema.json
```

`make test-e2e` runs the suite in `tests/e2e/` against a cluster that already has Istio ambient, the two gateways, and
this chart installed — it installs nothing and uninstalls nothing, so point it at a namespace where the release is
already deployed:

```bash
make test-e2e E2E_NAMESPACE=core
```

`tests/e2e/redis/` is the exception to "run everything": it asserts what only a
shared counter store can do — that the operator selected Redis rather than
falling back, that the counters carry the documented key, and that a spent budget
survives the process that spent it. An install without `redis.addresses` is a
valid install, so that suite skips rather than fails on one.

It covers what no unit test can: that the installed CRD is the one carrying the current validation, that a policy event
reaches the store in the running pod, that a mapping revives a policy that referenced its key, that an earlier
generation keeps running while an edit is rejected and the state reaches its ConfigMap, that the gate refuses a mapping
which would stop running rules and names the culprit, that the gateway is configured with this release's Service and the
agreed descriptors, that the stub refuses traffic over its limit with 429 and allows it again when the window reopens,
that the two gateways count independently, and that a check logs its domain and path and request id while never logging
the `Authorization` value.

The `leader` test is the exception to "changes nothing": the leader-election split cannot be observed with a single
replica, so it scales the release to two, kills the leader, and asserts that rate limiting continues while the lease
moves and that the new leader resumes status writes. It restores the original replica count through Helm — a `kubectl
scale` would take field-manager ownership of `.spec.replicas` and make every later `helm upgrade` conflict.

`make test` runs `internal/controller` against a real API server through envtest, which is where the CRD schema and the
status subresource actually exist — the fake client the other tests use validates nothing. The first run downloads the
envtest binaries into `bin/`, so it needs internet; `make test-unit` never does. Both derive their Kubernetes version
from `go.mod`, so the test control plane cannot drift from the client libraries the service is built against.

`helm-templates/ratelimit/templates/crd-*.yaml` are generated. Edit the Go types and run `make sync-helm-crds` instead
of editing them.

The CRD carries CEL rules, and the cost estimator budgets each one against the declared `MaxLength` and `MaxItems`. Two
structural checks the estimator would not accept live in the compiler instead — template placeholder uniqueness, and
`replaces` naming a rule of its own block — and a policy failing either is rejected with `Accepted: False`, exactly as
the API server would have rejected it.

Run the service against your current kubeconfig:

```bash
CLOUD_NAMESPACE=<ns> make run
```

`CLOUD_NAMESPACE` has no default. An unset value is a startup error, not a fallback to watching the cluster — it is what
keeps the service's RBAC a `Role`. It is read through `configloader`, so any property source the platform configures can
supply it.
