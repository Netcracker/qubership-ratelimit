# The ratelimit Helm charts: values, schemas, templates

The delivery contract: a reference for the values variables, their JSON schemas, and the structure of the templates.
The delivery is **one application** of **three charts** and **two images** ([topology](deployment-topology.md)): one
cluster chart and two namespace charts. The cluster chart, `ratelimit-crds` under `helm-templates/ratelimit-crds`,
holds the cluster-scoped `RateLimitPolicy` CRD and is installed once per cluster, see "The CRD chart". The namespace
charts are `ratelimit-operator` under `helm-templates/ratelimit-operator` with the image
`qubership-ratelimit-operator`, and `ratelimit-service` under `helm-templates/ratelimit-service` with the image
`qubership-ratelimit-service`. The platform installs the same pair in every namespace of an application. The set of
objects each namespace chart renders is derived from the platform's `BASELINE_ORIGIN`: the whole stack where a domain
lives, the gateway filters alone in a satellite.

The operator chart owns the operator deployment; the service chart owns the service deployment, the Service
`ratelimit`, and the Envoy configuration (the ratelimit filter on the gateways). The ConfigMap
`ratelimit-config` between the two is written by the operator on every reconcile and rendered by neither chart. Helm
and Argo CD overwrite what a chart renders on every sync. Rules, claim extraction, and groups do not live in
values; they belong to `RateLimitPolicy`, one per domain, see the [resource specification](ratelimitpolicy-cr-spec.md).

## Chart contents

The operator chart:

```text
helm-templates/ratelimit-operator/templates/
├── _helpers.tpl                   # mode (satellite iff BASELINE_ORIGIN; every template is wrapped in it, so a
│                                  #   satellite release is empty)
├── Deployment.yaml                # ratelimit-operator, one replica active; single namespace and baseline
│                                  #   only, as is every template
├── ServiceAccount.yaml            # bound to the only Role of the delivery
├── Role.yaml                      # policies and their status, leases, endpointslices, configmaps, events, all in
│                                  #   its own namespace
├── RoleBinding.yaml
├── PodMonitor.yaml                # behind MONITORING_ENABLED
└── PrometheusRule.yaml            # the alert rules over the policy status, behind MONITORING_ENABLED and
                                   #   policyAlerts.enabled
```

The service chart:

```text
helm-templates/ratelimit-service/templates/
├── _helpers.tpl                   # mode (satellite iff BASELINE_ORIGIN; every template but EnvoyFilter.yaml is
│                                  #   wrapped in it, so a satellite release holds the filters alone),
│                                  #   serviceName (the constant ratelimit), grpcPort, serviceNamespace,
│                                  #   rlsAuthority/rlsCluster, statPrefix, validateDomains (fails the render on a
│                                  #   duplicate domain), dbaasNamespace, millicores (the autoscaler's CPU target)
├── Deployment.yaml                # the Deployment ratelimit-service, REPLICAS replicas; mounts ratelimit-config
│                                  #   at /etc/ratelimit/config with optional: true and the counter store's
│                                  #   Secret under /etc/secrets/dbaas-secrets without it; the ServiceAccount
│                                  #   token only with management.enabled
├── HorizontalPodAutoscaler.yaml   # autoscaling/v2 on CPU, from the HPA_* parameters; both directions Disabled
│                                  #   without HPA_ENABLED
├── PodDisruptionBudget.yaml       # maxUnavailable: 1, only when the service runs more than one replica:
│                                  #   REPLICAS, or HPA_MIN_REPLICAS with HPA_ENABLED
├── InternalDatabase.yaml          # the counter store's Redis database, behind redis.dbaas.enabled
├── DatabaseSecretClaim.yaml       # the claim on the database's connection properties, which dbaas-operator
│                                  #   writes into the Secret <SERVICE_NAME>-redis; behind redis.dbaas.enabled
├── Service.yaml                   # FIXED name ratelimit; grpc 9000 (appProtocol: grpc is mandatory), metrics (the
│                                  #   operator's probe port), management behind management.enabled
├── ServiceAccount.yaml            # automountServiceAccountToken: false; no Role
├── AuthorizationPolicy.yaml       # DENY on the management port for every source but the callers, or the
│                                  #   listed gateway; behind management.enabled
├── EnvoyFilter.yaml               # one per enabled gateway (public/private roles); in all modes
├── PodMonitor.yaml                # behind MONITORING_ENABLED
├── PrometheusRule.yaml            # the alert rules over the data plane, behind MONITORING_ENABLED and
│                                  #   alerts.enabled
└── Dashboard.yaml                 # GrafanaDashboard CR (grafana-operator), behind MONITORING_ENABLED
```

The mode is selected by one platform parameter, read the same way by both charts: `BASELINE_ORIGIN` is set, and
non-empty, only in a satellite. Absent or empty renders the whole stack of each chart (a single namespace and a
baseline are the same case). Non-empty renders the filters only from the service chart, with the RLS address built
from its value, and nothing from the operator chart. The platform installs the same pair in every namespace. A service
installed in a satellite would wait for an operator that never comes, stay NotReady, and fail the readiness gate of
the deployment; rendering no service there protects against that mistake. The defaults are overridden by explicit
values:

| Deployment scheme | `ratelimit-operator` renders | `ratelimit-service` renders |
| --- | --- | --- |
| single namespace | the operator (Deployment, SA, Role/RoleBinding); with `MONITORING_ENABLED`, its PodMonitor and PrometheusRule | the service (Deployment, Service, SA, HPA) and the EnvoyFilters; with `redis.dbaas.enabled`, InternalDatabase and DatabaseSecretClaim; with `management.enabled`, the AuthorizationPolicy; with `MONITORING_ENABLED`, PodMonitor, PrometheusRule, and the dashboard |
| composite, baseline | the same | the same |
| composite, satellite | nothing: an empty release | only the filters, which target the baseline RLS; no service, no Service, no ServiceAccount |

The contract between the charts and the binaries is a set of constants in one Go package under `api/`, imported by
both binaries:

- the Service `ratelimit`;
- its gRPC port 9000, named `grpc`;
- the probe port, published on the Service under the name `metrics` (the service's metrics port, 8080);
- the ConfigMap `ratelimit-config`.

The mode rule, satellite iff `BASELINE_ORIGIN` is non-empty, is the `ratelimit.mode` helper in the `_helpers.tpl` of
each namespace chart, and the two namespace charts are installed in one namespace; the CRD chart has neither.

The templates of both charts carry the same names and ports as fixed strings. A CI test renders both charts and
compares the rendered names and ports with the constants (see "Installation and upgrade"). A satellite release of the
service chart uses the Service name and port to compute the RLS address from the baseline namespace, so the name is
the constant `ratelimit` and depends on neither the release name nor `SERVICE_NAME`. The port is a contract
constant, so `rls.port` exists in neither chart. The namespace half of that address is `BASELINE_ORIGIN`, or
`BASELINE_CONTROLLER` when the platform sets it: the service chart reads it for parity with `control-plane`, which
resolves the baseline the same way; on this platform the baseline is never Blue-Green'd, so it stays empty. Each
chart ships its own alert rules as a `PrometheusRule`, see "Alerts".

## The CRD chart

The `RateLimitPolicy` CRD (the type definition) is a cluster-scoped object, the policies themselves are namespaced, and
the namespace releases are many, so the CRD ships in a chart of its own, `ratelimit-crds`, with these rules:

```text
helm-templates/ratelimit-crds/templates/
└── crd-ratelimitpolicies.yaml     # generated by make sync-helm-crds from config/crd/bases; do NOT edit by hand;
                                   #   the helm CI job catches drift of the copy; helm.sh/resource-policy: keep
```

- one release per cluster owns the CRD, installed before the namespace charts; the namespace charts carry no copy, so
  their releases do not contend for its ownership, and an upgrade of an older namespace cannot put its older schema back
  for the whole cluster. The chart takes no values and renders the same in every namespace scheme;
- an operator started before the CRD exists exits at manager creation and restarts until the CRD release is installed;
  it never serves `/readyz`, so the `--wait` of its install times out. Its log ends in
  `create manager: failed to determine if *unstructured.Unstructured is namespaced: failed to get restmapping: no
  matches for kind "RateLimitPolicy" in version "ratelimit.netcracker.com/v1"`, and installing `ratelimit-crds`
  repairs it ([runbook](runbook.md), section 0);
- the release's name and namespace are fixed for the cluster's lifetime: the CRD that `keep` leaves after
  `helm uninstall` still carries the `meta.helm.sh/release-name` and `meta.helm.sh/release-namespace` annotations, and
  an install under another name or namespace fails with `invalid ownership metadata`. Reinstall it under the same name
  and namespace, or move it with `--take-ownership` as below;
- the CRD release is upgraded first, to the newest operator version in the cluster, and schema version skew between
  namespaces is a normal scenario: each namespace's operator may be older than the schema;
- `helm.sh/resource-policy: keep`: uninstalling or reinstalling the release does not remove the type; the policies of
  all namespaces would vanish with it;
- schema compatibility is the responsibility of development: changes are additive (new fields are optional, bounds are
  not tightened, schema rules are only relaxed), API server ratcheting lets unchanged fields of old objects through,
  and an old-version operator rejects a generation with unfamiliar fields (`InvalidSpec` from strict decoding of
  the unstructured object) and leaves `ratelimit-config` on the last-good generation: neither half crashes, and
  nothing enforces the object partially.

A cluster that already has the CRD moves it to the CRD release once. Helm refuses to install a release over an
object another release owns (`invalid ownership metadata`), which is the case after an operator release installed it,
and over an object without the label `app.kubernetes.io/managed-by: Helm`
(`label validation error: missing key "app.kubernetes.io/managed-by"`), which is the case after
`kubectl apply -f config/crd/bases` (`make install`). `--take-ownership` (Helm 3.17 and later) adopts the object in
both cases; later upgrades of the release run without it:

```bash
helm upgrade --install ratelimit-crds helm-templates/ratelimit-crds --namespace <platform-namespace> --take-ownership
```

The next upgrade of the operator release then drops the CRD from that release and leaves it in the cluster. Helm
decides what to keep from the previous release's manifest, not from the live object, and the operator chart's CRD
template carried `helm.sh/resource-policy: keep`.

## Platform parameters and resource profiles

The platform installs both charts with one parameter set, and they take part of their configuration from its
cross-cutting parameters. Shared inputs keep identical key names in both charts, and each chart declares
only the keys its templates read:

| Parameter | Read by | What it does |
| --- | --- | --- |
| `REPLICAS` | both | the replica count, from the resource profile; the operator's `dev-ha` and `prod` profiles set 2, and the second operator replica is a standby that takes the Lease over, not added capacity |
| `CPU_REQUEST`, `MEMORY_REQUEST`, `CPU_LIMIT`, `MEMORY_LIMIT` | both | installation size; there are NO defaults in values, the resource profile supplies them |
| `MONITORING_ENABLED` | both | enables the PodMonitor and the PrometheusRule of each chart and the GrafanaDashboard of the service chart; false by default, since all three need the CRDs of their operators |
| `ISTIO_PUBLIC_GATEWAY_NAME` | the service chart | the name of the public Gateway object the filter targets; it must match the parameters of qubership-core-mesh-config, which creates the Gateways |
| `ISTIO_PRIVATE_GATEWAY_NAME` | the service chart | the name of the private Gateway object the filter targets; it must match qubership-core-mesh-config the same way |
| `BASELINE_ORIGIN` | both | the baseline namespace, set only in a satellite; empty renders the whole stack of each chart, non-empty renders only the service chart's filters, targeting `ratelimit.<BASELINE_ORIGIN>.svc:9000`, and nothing from the operator chart; the value of `NAMESPACE`, the namespace the release installs into, fails both renders with `BASELINE_ORIGIN "<ns>" is this release's own namespace` |
| `BASELINE_CONTROLLER` | the service chart | read for parity with `control-plane`; when set in a satellite it replaces `BASELINE_ORIGIN` as the namespace of the RLS address in the service chart; on this platform the baseline is never blue-green'd, so it stays empty |
| `CLOUD_TOPOLOGY_KEY` | both | the node label each Deployment spreads its pods over, `kubernetes.io/hostname` by default: one topology spread constraint with `maxSkew: 1` and `whenUnsatisfiable: ScheduleAnyway`, selecting the Deployment's own pods |
| `SERVICE_NAME` | both | the name of each chart's Deployment and ServiceAccount (and the operator's RBAC pair), its `app.kubernetes.io/name` and `name` labels, and in the service chart the DBaaS classifier's `microserviceName`; `ratelimit-operator` and `ratelimit-service` by default; the Service stays `ratelimit`; a DNS label of at most 63 characters, which the schema checks |
| `NAMESPACE` | both | the namespace every object lands in, as on the platform's other services; required, and the schema refuses an empty one. The pods read their namespace back through the Downward API, so the installation's scope, the counter key prefix, and the DBaaS classifier follow it |
| `IMAGE_REPOSITORY`, `TAG` | both | the image; `TAG` is required, and the schema refuses an empty one |
| `LOG_LEVEL` | both | the root level of the platform logger, passed as `LOGGING_LEVEL_ROOT` in lower case |
| `APPLICATION_NAME`, `MANAGED_BY`, `ARTIFACT_DESCRIPTOR_VERSION` | both | `app.kubernetes.io/part-of` and `managed-by` on every object (`MANAGED_BY` is `Helm` in `values.yaml`, and empty renders empty); `version` on the Deployment and its pods (empty renders empty) |
| `DEPLOYMENT_SESSION_ID` | both | `deployment.netcracker.com/sessionId` on every object but the pods; required, and the schema refuses an empty one |
| `PAAS_PLATFORM`, `READONLY_CONTAINER_FILE_SYSTEM_ENABLED` | both | on `KUBERNETES` the container runs as group 10001 and, with the flag set (the default), on a read-only root filesystem; on `OPENSHIFT` the platform assigns both and the root filesystem is writable |
| `DEPLOYMENT_STRATEGY_TYPE`, `DEPLOYMENT_STRATEGY_MAXSURGE`, `DEPLOYMENT_STRATEGY_MAXUNAVAILABLE` | both | the rollout, read the way the platform's other services read it; the four types and what each does to the RLS endpoint are described below the table |
| `LIVENESS_PROBE_INITIAL_DELAY_SECONDS` | both | the delay before the first liveness probe, 15 by default |
| `HPA_*` | the service chart | the platform's HorizontalPodAutoscaler on CPU, from the resource profile: off in `dev`, between `HPA_MIN_REPLICAS` and `HPA_MAX_REPLICAS` in the others, at a target that is a share of `CPU_LIMIT`; the keys are listed under "Values reference", and what `HPA_ENABLED` does to `replicas` is described below the table |
| `CLOUD_TOPOLOGIES` | both | the platform's list of topologies; when set, it replaces `CLOUD_TOPOLOGY_KEY` with one constraint per entry, each with its `topologyKey` and optional `maxSkew` and `whenUnsatisfiable` |

The rollout types: unset and `ramped_slow_rollout` are `maxSurge: 1, maxUnavailable: 0`; `recreate` stops every old pod
first and leaves the gateways without an RLS endpoint during a service rollout; `best_effort_controlled_rollout` is
`maxSurge: 0, maxUnavailable: 80%`, which at one replica does the same and at two or more keeps at least one old replica
serving until the new ones are Ready; `custom_rollout` alone reads `DEPLOYMENT_STRATEGY_MAXSURGE` and
`DEPLOYMENT_STRATEGY_MAXUNAVAILABLE`, `25%` each when unset or empty, a `0` rendered as zero; both at zero fail the
render, since no rollout can make progress with them. The other types ignore both parameters. With `HPA_ENABLED` the
Deployment renders no `replicas`, so an upgrade keeps the scaled count, and an upgrade that turns the autoscaler on
starts at one replica, the API default, until the HPA raises it to `HPA_MIN_REPLICAS` on its next sync; with the
autoscaler off, both directions are `Disabled` and `REPLICAS` sizes the service.

An eviction takes one service replica at a time when the service runs more than one: a `PodDisruptionBudget` with
`maxUnavailable: 1` makes a node drain, a cluster-autoscaler consolidation, or a descheduler wait until the
replacement is Ready. The chart renders it only for more than one replica, `REPLICAS` or, with `HPA_ENABLED`,
`HPA_MIN_REPLICAS`; at one replica the chart promises no availability through an eviction, and the gateways' failure
mode decides the checks while the replacement starts.

The resource parameters are required in the schema of each chart: the four sizes and `REPLICAS` in both, and the
service's profiles also carry the `HPA_*` parameters. An installation without `-f resource-profiles/<profile>.yaml`
fails with a clear error instead of rendering a Deployment with empty resources. One source of truth: the defaults
cannot drift apart from the profiles because there are no defaults. `GOMEMLIMIT` is derived from `MEMORY_LIMIT`
automatically (the memlimit import in the binaries), so the limit governs the Go heap, not only the cgroup ceiling.

`NAMESPACE`, `TAG`, and `DEPLOYMENT_SESSION_ID` are required in both schemas as well, and the platform passes all three.
A manual install passes `--set NAMESPACE=<namespace>` with the same namespace as `-n`, `--set TAG=<tag>`, and
`--set-string DEPLOYMENT_SESSION_ID=<session>`; with `--set`, a numeric session becomes a number, and the schema refuses
it with `at '/DEPLOYMENT_SESSION_ID': got number, want string`. An install that leaves any of them empty fails with
`at '/NAMESPACE': minLength: got 0, want 1`, or the same line for the parameter it left out.

## Values reference

The full file of each chart, with comments, is the values contract; this is the map. Each key is listed with the
template that reads it; a key one chart does not read does not exist in that chart.

The operator chart, `helm-templates/ratelimit-operator/values.yaml`:

```yaml
SERVICE_NAME: ratelimit-operator     # every template: the platform's parameters, see "Platform parameters"
NAMESPACE: ""                         # every template; required, the schema refuses it empty
IMAGE_REPOSITORY: ghcr.io/netcracker/qubership-ratelimit-operator   # Deployment.yaml
TAG: ""                              # required, the schema refuses it empty; do not use floating tags
APPLICATION_NAME: ratelimit          # every template's labels; an empty ARTIFACT_DESCRIPTOR_VERSION
MANAGED_BY: Helm                     #   renders an empty version label
ARTIFACT_DESCRIPTOR_VERSION: ""
DEPLOYMENT_SESSION_ID: ""            # required, the schema refuses it empty
PAAS_PLATFORM: KUBERNETES            # Deployment.yaml: the container's security context
READONLY_CONTAINER_FILE_SYSTEM_ENABLED: true
LIVENESS_PROBE_INITIAL_DELAY_SECONDS: 15   # Deployment.yaml; DEPLOYMENT_STRATEGY_TYPE is not set here:
                                     #   unset = maxSurge 1, maxUnavailable 0

LOG_LEVEL: info                      # Deployment.yaml: goes out as LOGGING_LEVEL_ROOT (the platform logger);
                                     # NOT --zap-log-level: LOG_LEVEL only applies until configloader initializes;
                                     # debug caps the bridged logr verbosity at 4: no client-go body dumps

MONITORING_ENABLED: false            # PodMonitor.yaml, PrometheusRule.yaml; see "Platform parameters"

policyAlerts:                        # PrometheusRule.yaml: the rules over the policy status; see "Alerts"
  enabled: true                      # read only with MONITORING_ENABLED; false keeps the scrape, drops the rules
  stalledFor: 5m                     # RatelimitStalled: above the propagation deadline, so a late rollout is quiet
  notEnforcedFor: 5m                 # RatelimitNotEnforced: a policy that enforces no generation at all
  notReadyFor: 30m                   # RatelimitNotReadyLong: longer than any rollout, shorter than a shift
  ruleProblemsFor: 5m                # RatelimitRuleProblems: room for an author to fix a typo
  noReplicasFor: 5m                  # RatelimitNoReplicas: past a rollout's surge pod, far below notReadyFor
  checksStoppedWindow: 10m           # RatelimitChecksStopped: the window that has to see no check of the domain;
  checksStoppedFor: 15m              #   raise it for a domain idle for long stretches
  configWriteErrorsWindow: 15m       # RatelimitConfigWriteErrors: any write error in the window fires
  configWriteErrorsKeepFiring: 30m   #   and keeps firing this long after the last one, past the retry backoff
  reconcileErrorsWindow: 15m         # RatelimitOperatorReconcileFailing: a controller that completed no reconcile
  noLeaderFor: 5m                    # RatelimitNoOperatorLeader: past the Lease's own handover

BASELINE_ORIGIN: ""                  # _helpers.tpl (mode): the platform's composite variable, see "Platform
                                     #   parameters": empty = the whole stack (single namespace or baseline),
                                     #   set = an empty release

CLOUD_TOPOLOGY_KEY: kubernetes.io/hostname   # Deployment.yaml: topologySpreadConstraints, maxSkew 1, ScheduleAnyway;
                                     #   CLOUD_TOPOLOGIES, the platform parameter, replaces it with one constraint
                                     #   per {topologyKey, maxSkew, whenUnsatisfiable} entry
```

The service chart, `helm-templates/ratelimit-service/values.yaml`:

```yaml
SERVICE_NAME: ratelimit-service      # every template; also the DBaaS classifier's microserviceName
NAMESPACE: ""                         # every template; required, the schema refuses it empty
IMAGE_REPOSITORY: ghcr.io/netcracker/qubership-ratelimit-service    # Deployment.yaml
TAG: ""                              # required, the schema refuses it empty; do not use floating tags
APPLICATION_NAME: ratelimit          # every template's labels, as in the operator chart
MANAGED_BY: Helm
ARTIFACT_DESCRIPTOR_VERSION: ""
DEPLOYMENT_SESSION_ID: ""            # required, the schema refuses it empty
PAAS_PLATFORM: KUBERNETES            # Deployment.yaml: the container's security context
READONLY_CONTAINER_FILE_SYSTEM_ENABLED: true
LIVENESS_PROBE_INITIAL_DELAY_SECONDS: 15   # Deployment.yaml; DEPLOYMENT_STRATEGY_TYPE is not set here: recreate,
                                     #   and best_effort_controlled_rollout at one replica, leave the gateways
                                     #   without an RLS endpoint during the rollout; see "Platform parameters"

LOG_LEVEL: info                      # Deployment.yaml: goes out as LOGGING_LEVEL_ROOT (the platform logger);
                                     # NOT --zap-log-level: LOG_LEVEL only applies until configloader initializes

redis:                               # InternalDatabase.yaml, DatabaseSecretClaim.yaml; see "The counter store
  dbaas:                             #   from DBaaS"
    enabled: true                    # render the InternalDatabase and the DatabaseSecretClaim; false = the Secret
                                     #   <SERVICE_NAME>-redis is written by someone else in DBaaS's format (CI)

API_DBAAS_ADDRESS: http://dbaas-aggregator.dbaas:8080   # _helpers.tpl (ratelimit.dbaasNamespace): the platform's address of
                                     #   dbaas-aggregator; the second label of its host names the dbaas-operator's
                                     #   namespace on both objects, see "The counter store from DBaaS"

metrics:                             # (there are no port values: probes 8081, metrics 8080, and management 8082
                                     #   are fixed in the templates)
  nearLimitRatio: "0.9"              # Deployment.yaml: an allowed request counts as near-limit once this share of
                                     #   the window's capacity is used up: the burst of a GCRA window, the requests
                                     #   of a fixed one; goes out as METRICS_NEAR_LIMIT_RATIO. A ratio in (0, 1),
                                     #   quoted so YAML cannot reshape it. The schema does not check the range: a
                                     #   value outside it, or one that does not parse, is not rejected, and the
                                     #   service logs `METRICS_NEAR_LIMIT_RATIO="1.5" is not a ratio in (0, 1),
                                     #   using 0.9` and uses 0.9

responseHeaders:
  ietf: true                         # Deployment.yaml: the ratelimit-policy and ratelimit fields of
                                     #   draft-ietf-httpapi-ratelimit-headers-11 beside x-ratelimit-* (engine.md);
                                     #   false leaves them out, for clients that misread them or must not learn the
                                     #   rule names, and keeps x-ratelimit-* and retry-after. Goes out as
                                     #   RESPONSE_HEADERS_IETF; a boolean by the schema

management:                          # Deployment.yaml, Service.yaml, AuthorizationPolicy.yaml: the interface for
  enabled: false                     #   human operators (management-api.md), off by default: the port can lift a
                                     #   limit; on, it is port 8082 on the pod and the Service plus
                                     #   --management-bind-address
  callers: []                       # the ServiceAccounts that may call the API, each holding operator: <name> in
                                     #   NAMESPACE, <namespace>/<name> elsewhere; at least one while enabled
  m2m:
    audience: netcracker             # the audience a caller's token is issued for; any other gets 401; no leading
                                     #   or trailing space
  authorizationPolicy:               # DENY on that port for every source but the listed service accounts; ztunnel
    enabled: true                    #   enforces it, so it holds only while the pod is in the mesh
    allowedServiceAccounts: []       # empty = the callers; in their grammar, set it to the gateway's
                                     #   (<gateway>-istio) and any direct caller when the callers come through one
  gatewayDomains: [gateway.private]  # the rate limit domains of the gateways that route to the API: its paths are
                                     #   exempt from the checks of these domains (see "Management API port")

filter:                              # EnvoyFilter.yaml: installation defaults; each gateway can override its own
                                     # (there is no rls.port value: 9000 is a contract constant)
  timeout: 0.05s                     # protobuf duration (seconds with a fraction); Envoy rejects Go forms like 50ms
  failClosed: false                  # limiter unavailable: false = traffic flows without limits, true = 503;
                                     # the filter's failure_mode_deny, applied when the RLS is unreachable or
                                     # times out and when its counter store fails (the service answers UNAVAILABLE)
  rateLimitedStatus: 429             # refusal status for the client; one of Envoy's 4xx/5xx StatusCode values
  grpcAsResourceExhausted: false     # RESOURCE_EXHAUSTED instead of UNAVAILABLE for gRPC calls behind the gateway
  xRateLimitHeaders: "OFF"           # the filter's enable_x_ratelimit_headers, OFF or DRAFT_VERSION_03; the
                                     # service sends x-ratelimit-*, retry-after, and the ratelimit-policy and
                                     # ratelimit fields of draft-ietf-httpapi-ratelimit-headers-11 itself, as
                                     # ready-made headers, and DRAFT_VERSION_03 changes nothing while its responses
                                     # carry no per-descriptor statuses for Envoy to render headers from

runtime:                             # EnvoyFilter.yaml: gateway-side kill switches for the filter, independent of
  enabledPercent: 100                # behavior: Shadow; rendered as Envoy runtime fractions
  enforcedPercent: 100               # (ratelimit.<gw>.enabled/.enforced), so they can be overridden with a runtime
                                     # override without a redeploy: enforcedPercent 0 = global dry run,
                                     # enabledPercent 0 = filter off

MONITORING_ENABLED: false            # PodMonitor.yaml, PrometheusRule.yaml, Dashboard.yaml; see "Platform
                                     #   parameters"

alerts:                              # PrometheusRule.yaml: the rules over the data plane; see "Alerts"
  enabled: true                      # read only with MONITORING_ENABLED; false keeps the scrape, drops the rules
  latencyBudgetSeconds: 0.01         # RatelimitDecisionLatencyHigh: the decision budget, a number above zero
  latencyFor: 10m                    # so a burst does not page
  unknownDomainFor: 5m               # RatelimitUnknownDomain: the window's own length, so one stray check ages out
  storeErrorsFor: 5m                 # RatelimitStoreErrors: likewise, so one retried timeout never pages
  keyNotExtractedWindow: 15m         # RatelimitKeyDeclaredNotExtracted: the rate window of both halves
  keyNotExtractedFor: 30m            # and the hold over it
  domainBudgetWarnAt: 104            # RatelimitDomainBudgetNearLimit: 80 percent of the budget of 128
  configAbsentFor: 5m                # RatelimitConfigurationAbsent: past the projection of a recreated ConfigMap

ISTIO_PUBLIC_GATEWAY_NAME: public-gateway     # EnvoyFilter.yaml: the Gateway of the public role
ISTIO_PRIVATE_GATEWAY_NAME: private-gateway   # EnvoyFilter.yaml: the Gateway of the private role;
                                              #   AuthorizationPolicy.yaml: the default allowed principal
BASELINE_ORIGIN: ""                  # _helpers.tpl (mode, serviceNamespace): the platform's composite variables,
BASELINE_CONTROLLER: ""              #   see "Platform parameters": empty = the whole stack (single namespace or
                                     #   baseline), set = the filters only

gateways:                            # EnvoyFilter.yaml and validateDomains: two fixed roles; a third gateway = a
  public:                            # template change (deliberately: the platform defines exactly public/private)
    enabled: true
    domain: gateway.public           # the linking key: must equal the policy's spec.domain; the pattern is the CRD's;
                                     #   in a composite, one domain per role across all namespaces = a shared budget
    # namespace: the Gateway's namespace, where the EnvoyFilter is created; NAMESPACE when unset
    # timeout / failClosed / rateLimitedStatus / grpcAsResourceExhausted:
    #   per-gateway overrides of the filter.* defaults; the typical case is a private
    #   gateway failing closed while the public one fails open
  private:
    enabled: true
    domain: gateway.private

CLOUD_TOPOLOGY_KEY: kubernetes.io/hostname   # Deployment.yaml: topologySpreadConstraints, maxSkew 1, ScheduleAnyway;
                                     #   CLOUD_TOPOLOGIES, the platform parameter, replaces it with one constraint
                                     #   per {topologyKey, maxSkew, whenUnsatisfiable} entry
```

The service's resource profile, `helm-templates/ratelimit-service/resource-profiles/<profile>.yaml`, carries the
`HPA_*` keys beside `REPLICAS` and the sizes, and `HorizontalPodAutoscaler.yaml` reads them. The values below are the
`prod` profile's; `dev` sets `HPA_ENABLED: false` and `HPA_MIN_REPLICAS: 1`, and `prod-nonha` sets
`HPA_MIN_REPLICAS: 1`:

```yaml
HPA_ENABLED: true                    # the autoscaler owns the count: the Deployment renders no replicas, and an
                                     #   upgrade that turns it on starts at one replica until the first sync; false
                                     #   renders both directions Disabled, and REPLICAS sizes the service (the
                                     #   object is rendered either way)
HPA_MIN_REPLICAS: 2                  # minReplicas; REPLICAS when unset
HPA_MAX_REPLICAS: 5                  # maxReplicas; with HPA_ENABLED the render fails without it:
                                     #   `HPA_MAX_REPLICAS is required when HPA_ENABLED is true`
HPA_AVG_CPU_UTILIZATION_TARGET_PERCENT: 75   # the CPU target as a percent of CPU_LIMIT, rendered as the
                                     #   utilization of CPU_REQUEST it amounts to; 75 when unset
HPA_SCALING_UP_STABILIZATION_WINDOW_SECONDS: 60    # behavior.scaleUp.stabilizationWindowSeconds; 0 when unset
HPA_SCALING_UP_PODS_VALUE: 1         # the Pods policy of scaleUp: value and periodSeconds, rendered when the
HPA_SCALING_UP_PODS_PERIOD_SECONDS: 60   #   value is set, with an empty period when the period is not; set both
HPA_SCALING_DOWN_STABILIZATION_WINDOW_SECONDS: 300  # behavior.scaleDown.stabilizationWindowSeconds; 300 when unset
HPA_SCALING_DOWN_PODS_VALUE: 1       # the Pods policy of scaleDown, as above
HPA_SCALING_DOWN_PODS_PERIOD_SECONDS: 60
# Platform parameters no profile sets; the schema admits them and the template reads them when they are passed:
# HPA_SCALING_UP_PERCENT_VALUE and HPA_SCALING_UP_PERCENT_PERIOD_SECONDS, a Percent policy of scaleUp beside the
#   Pods one, rendered when the value is set (set both); HPA_SCALING_DOWN_PERCENT_VALUE and
#   HPA_SCALING_DOWN_PERCENT_PERIOD_SECONDS, the same for scaleDown;
# HPA_SCALING_UP_SELECT_POLICY and HPA_SCALING_DOWN_SELECT_POLICY, Min, Max, or Disabled; Max when unset, and
#   Disabled whatever is set while HPA_ENABLED is false
```

The service release creates each EnvoyFilter in the namespace of its Gateway, `gateways.<role>.namespace`, which is
`NAMESPACE` by default, where qubership-core-mesh-config puts the gateways (`targetRefs` resolves in
the namespace of the EnvoyFilter itself; Istio forbids cross-namespace references).

What is **deliberately absent** from values:

| Absent | Where it lives | Why |
| --- | --- | --- |
| limit rules, claim extraction, groups | `RateLimitPolicy` | a matter for the teams, not for the installation |
| the descriptor list | hardwired in the EnvoyFilter template | the four fields `path`/`method`/`token`/`request_id` are a contract with the service; extending it is a deliberate chart change |
| the Lease | always on, in the operator | the Lease holder alone writes the status and `ratelimit-config`, a standby takes over when it goes, and the Lease covers the overlap of two pods during a rollout |
| the ConfigMap `ratelimit-config` | written by the operator | Helm and Argo CD overwrite what a chart renders on every sync; the channel to the service cannot come from a chart |
| the Service name and port | contract constants (`ratelimit`, 9000) | fixed in the templates of both charts and checked against the Go constants by the CI render test; there is no `rls.port` value |
| `healthProbe.port`, `metrics.port`, `management.port` | fixed in the service chart's templates: probes 8081, metrics 8080, management 8082 | the operator chart and the charts of the qubership-core services fix their container ports too, and the gateway's `HTTPRoute` to the management API names port 8082 |
| sanity bounds (token size and the like) | constants in the binaries | not knobs: nobody tunes them |
| `replicaCount`, `resources` | resource profiles (`REPLICAS`, `CPU_*`, `MEMORY_*`, and the service's `HPA_*`) | one source of truth with the platform |
| `image.*`, `logLevel`, `nameOverride`, `fullnameOverride` | the platform parameters `IMAGE_REPOSITORY` and `TAG`, `LOG_LEVEL`, and `SERVICE_NAME` | the charts of the qubership-core services declare none of these keys either |
| `podAnnotations`, `nodeSelector`, `tolerations`, `affinity` | pod placement: the topology spread constraints built from `CLOUD_TOPOLOGY_KEY` or `CLOUD_TOPOLOGIES`; pod annotations: none | the charts of the qubership-core services declare none of these keys either |
| `serviceAccount.create`, `serviceAccount.name` | the ServiceAccount each chart renders outside a satellite, named `<SERVICE_NAME>` | the charts of the qubership-core services declare none of these keys either |
| the RLS address for a satellite | computed from `BASELINE_ORIGIN` | the Service name and port are fixed by contract |
| `DestinationRule` for the service cluster | none | see "What the charts do not install" |

## values.schema.json

Each chart ships a schema that rejects invalid values at `helm install`/`upgrade`/`template`, before anything reaches
the cluster. Key points:

- **the gateway domain pattern is byte-for-byte the CRD's** (`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`, 1..63), in the
  service chart: a value that a policy physically cannot carry is rejected already at installation instead of living
  on as an eternal "unknown rate limit domain" line in the log;
- `filter.timeout` is a protobuf duration above zero, such as `0.05s`: Envoy rejects Go forms like `50ms`, and a zero
  timeout fails every check;
- `filter.rateLimitedStatus` is one of the 37 4xx and 5xx codes of Envoy's `StatusCode` enumeration: Envoy rejects the
  filter for any other code, 418 or 451 among them, and with it the whole listener update of the gateway, while
  `helm upgrade` succeeds; `runtime.*Percent` is 0..100;
- `metrics.nearLimitRatio` lies in (0, 1), as a number or as a string such as `"0.9"`;
- `BASELINE_ORIGIN` and `BASELINE_CONTROLLER` are a namespace as Kubernetes spells it, at most 63 characters, or
  empty: `Biz`, `biz.svc`, or a trailing space would compare unequal to the release's namespace and render the chart
  as a satellite;
- `redis.dbaas.operatorNamespace` is a namespace or empty; with it empty, the host of `API_DBAAS_ADDRESS` has to read
  `<aggregator>.<namespace>` (see "The counter store");
- the profile's resource parameters are required in both charts (see above);
- `NAMESPACE`, `TAG`, and `DEPLOYMENT_SESSION_ID` are required and non-empty in both charts (see above);
- every `alerts.*` and `policyAlerts.*` duration is a positive Prometheus duration (`^[1-9][0-9]*(ms|s|m|h|d|w|y)$`) and
  `alerts.latencyBudgetSeconds` is a number above zero: a zero duration renders `[0m]` or `for: 0m`, which Prometheus
  refuses to load, taking the chart's other rules with it, and a budget at or below zero renders a comparison every
  check satisfies;
- the root of each schema stays **open**, and each chart closes its own blocks, the ones its templates read. The
  platform distributes common installation parameters to the charts and passes one parameter set to every chart of
  the application. The service's `redis` and `filter` blocks therefore reach the operator chart. A closed root would
  fail on every new parameter and on the other chart's blocks. For the same reason no two charts close a block under
  one name: the operator's alert values are `policyAlerts`, beside the service's `alerts`.
  A typo inside a block fails the render; the price of the open root is that a typo at the root is silently ignored.

The schema cannot express domain uniqueness; the `validateDomains` helper of the service chart holds it (see the
templates): a duplicate domain among the enabled gateways of one release, or an enabled gateway without a domain,
fails the render with a clear error. Matching domains **across the releases of a composite** are the model itself
rather than an error: one domain per role, a shared budget. Every replica the service chart renders counts in its DBaaS
database: the service refuses to start without `--redis-dbaas-microservice`, or `--redis-addr` for a local Redis in the
developer loop, so no replica counts on its own.

## Templates

### _helpers.tpl

Both charts read the mode the same way: `mode` is `satellite` when `BASELINE_ORIGIN` is set and `baseline` otherwise; a
single namespace and a baseline render the same objects, so there is no third value. In the service chart every template
but the filters is wrapped in that check; in the operator chart every template is, so a satellite release of the
operator chart is empty. `serviceName` is the constant `ratelimit` in both charts: the installation is namespace-scoped
by construction (`CLOUD_NAMESPACE`), one per namespace, and a fixed name is a computable RLS address for the satellites.
The operator discovers the service replicas through the EndpointSlice of the same Service the filters target. The
templates write their names, namespaces, and labels inline, the way the platform's other services do: every object
carries `app.kubernetes.io/name`, `part-of`, `managed-by`, and the deployment session; the Deployment and its pods add
`name`, `app.kubernetes.io/instance` (the name and the namespace), the version, the component, and the technology, and
`name: <SERVICE_NAME>` alone is the selector. The service chart also holds `serviceNamespace`: `NAMESPACE`, or in a
satellite `BASELINE_CONTROLLER` when set and `BASELINE_ORIGIN` otherwise; `rlsAuthority`:
`<serviceName>.<serviceNamespace>.svc.cluster.local`; `rlsCluster`: `outbound|9000||<fqdn>`; `statPrefix`: the gateway
name with `-` replaced by `_`; `validateDomains`, described above; `dbaasNamespace`, the namespace of the dbaas-operator
that reconciles the counter store's claim; and `millicores` for the autoscaler's CPU target. The Secret of the counter
store is `<SERVICE_NAME>-redis`: the `DatabaseSecretClaim` names it and the Deployment mounts it.

### EnvoyFilter.yaml (service chart): the core of the filter part

One object per enabled role (`public`/`private`); the Gateway name comes from `ISTIO_*_GATEWAY_NAME`. Per-gateway
overrides of `filter.*` are computed in the template; booleans go through `hasKey` so that an explicit `false` beats a
global `true`.

```yaml
typed_config:
  "@type": .../envoy.extensions.filters.http.ratelimit.v3.RateLimit
  domain: <gateways.<role>.domain>
  failure_mode_deny: <failClosed>
  status_on_error: { code: 503 }         # only with failClosed: otherwise deny would answer with the default 500
  timeout: <timeout>
  enable_x_ratelimit_headers: <xRateLimitHeaders>   # OFF by default: the service sends the headers itself
  rate_limited_status: { code: <rateLimitedStatus> }
  rate_limited_as_resource_exhausted: <grpcAsResourceExhausted>
  stat_prefix: <gateway statPrefix>
  filter_enabled:                        # the emergency pair: Envoy re-reads runtime fractions live
    runtime_key: ratelimit.<gateway>.enabled
    default_value: { numerator: <enabledPercent>, denominator: HUNDRED }
  filter_enforced:
    runtime_key: ratelimit.<gateway>.enforced
    default_value: { numerator: <enforcedPercent>, denominator: HUNDRED }
  rate_limit_service:
    transport_api_version: V3
    grpc_service:
      envoy_grpc: { cluster_name: <rlsCluster>, authority: <rlsAuthority> }
```

`failure_mode_deny` is the one failure-mode switch, and it covers two cases: the RLS itself is unreachable or times out,
and the RLS answers `UNAVAILABLE` because its counter store failed. Either way the check is counted as
`verdict="unavailable"` on the service's scrape when the service answered, and `failClosed` decides whether the traffic
flows unlimited or gets a 503. A request to the management API through a gateway whose domain is in
`management.gatewayDomains` is outside both cases while the service answers: its check reads no counter store (see
"Management API port").

There are four descriptor actions (VIRTUAL_HOST, MERGE), and they are a contract with the service:

```yaml
- request_headers: { header_name: ":path", descriptor_key: path }
- request_headers: { header_name: ":method", descriptor_key: method }
- request_headers: { header_name: "authorization", descriptor_key: token, skip_if_absent: true }
- request_headers: { header_name: "x-request-id", descriptor_key: request_id, skip_if_absent: true }
```

`request_id` is only for correlating a check with the gateway access log (the service puts it into the logging
context); it is never an identity.

### Service.yaml (service chart): the critical detail

The name is the constant `ratelimit` whatever the release is called, and `SERVICE_NAME` does not rename it. The
e2e install names the service release differently from the Service, so the suite exercises the fixed name. The `grpc`
port carries `appProtocol: grpc`; without it, Istio decides the port is HTTP/1.1. The Service also publishes the
service's metrics port under the name `metrics`: the operator takes the port number from the EndpointSlice by that
name and reads `/debug/applied` on it. The `management` port is added behind `management.enabled`.

### Role.yaml (operator chart)

Everything is namespace-scoped, and there is no ClusterRole. The operator's ServiceAccount is the only one of the
delivery that a Role is bound to; the service pod mounts its token only with `management.enabled`, to verify the
management API's callers, and its ServiceAccount has no Role:

| Resource | Verbs | Purpose |
| --- | --- | --- |
| `ratelimitpolicies` | get, list, watch | the policy informer of its own namespace |
| `ratelimitpolicies/status` | update | the operator writes the status with an update, never a patch |
| `leases` (coordination.k8s.io) | get, create, update | the Lease that keeps one writer while two operator pods overlap during a rollout |
| `endpointslices` (discovery.k8s.io) | get, list, watch | the ready service replicas of the Service `ratelimit`, and the probe port by its name, for the strict `Ready` |
| `configmaps` | create | the one verb RBAC cannot narrow by name: the object does not exist yet |
| `configmaps`, `resourceNames: [ratelimit-config]` | get, list, watch, update | `ratelimit-config`, the configuration of the service and the last-good state of the namespace; list and watch pass under the name because the operator's cache selects the object by `metadata.name`; no delete, no patch, and nothing on the ConfigMaps of the other applications in the namespace |
| `events` (core and events.k8s.io) | create, patch | `Warning` events; leader election records through the core group, the writer of `ratelimit-config` through events.k8s.io |
| `deployments` (apps), `resourceNames: [<its own name>]` | get | the operator's own Deployment, read once at start: `ratelimit-config` carries an ownerReference to it, so the object goes with the operator; a Deployment the operator cannot read leaves the object without an owner, with a warning |

### Deployment.yaml of the operator chart: the essentials

- `REPLICAS` replicas, 2 in `dev-ha` and `prod`: only the Lease holder writes the status and `ratelimit-config`, another
  replica is a standby, and the Lease keeps one writer while two pods overlap during a rollout;
- args: `--health-probe-bind-address=:8081`, `--metrics-bind-address=:8080`, and `--deployment=<SERVICE_NAME>`, the
  operator's own Deployment, the owner of `ratelimit-config` (the `microservice.name` property when the flag is
  empty); `-kubeconfig`, controller-runtime's flag, is not passed: the pod uses the in-cluster configuration, and the
  flag serves a run outside the cluster;
- env: `LOGGING_LEVEL_ROOT` (not `--zap-log-level`), `CLOUD_NAMESPACE` from a fieldRef (the namespace scope is
  mandatory, the process does not start without it), `POD_NAME` from a fieldRef (the Lease identity);
- the ConfigMap `ratelimit-config` is not rendered here either: the operator creates it on the first reconcile with an
  ownerReference to this Deployment, so it goes away with the operator and never with a policy;
- resources come from the profile; `ephemeral-storage` is limited in the template itself (the process writes no
  files); the metrics port is named `metrics` for the PodMonitor.

### Deployment.yaml of the service chart: the essentials

- `REPLICAS` replicas from the profile, or none rendered while `HPA_ENABLED` hands the count to the autoscaler; the pod
  sets `automountServiceAccountToken: false` and holds no Role: the process that parses tokens from the internet reaches
  no API server object;
- the volume: the ConfigMap `ratelimit-config` mounted as a whole directory at `/etc/ratelimit/config` with
  `optional: true`, so the pod starts before the operator has written;
- on the `..data` symlink swap the process decodes the manifest strictly, compiles every domain with the engine module,
  and swaps the snapshot atomically; a change reaches the replicas within the kubelet sync period, one minute by
  default;
- args: the bind addresses `--rls-bind-address=:9000` (the contract constant), `--health-probe-bind-address=:8081`,
  `--metrics-bind-address=:8080` (and `--management-bind-address=:8082` when `management.enabled`); the configuration
  flags stay at their defaults, `--config-dir=/etc/ratelimit/config` (the contract constant, the mount point of the
  volume above) and `--config-resync=10s` (the timer that re-reads the directory when the watch missed a swap, or when
  the directory did not exist at start) and `--rls-drain-timeout=10s` (how long in-flight checks may delay the
  shutdown before the gRPC listener is closed; it fits inside the `terminationGracePeriodSeconds: 30` below); no
  `--service-name`: the service reads no EndpointSlice;
- env: `LOGGING_LEVEL_ROOT` (not `--zap-log-level`), `CLOUD_NAMESPACE` and `POD_NAME` from fieldRefs (the Downward API;
  the namespace is the installation scope and the namespace segment in counter keys), `SERVICE_VERSION` (the image tag,
  reported as `ratelimit_build_info`; the pipeline passes no build argument to the image, so without it every scrape
  would say `dev`), `METRICS_NEAR_LIMIT_RATIO`, `RESPONSE_HEADERS_IETF`, plus `MANAGEMENT_CALLERS`,
  `MANAGEMENT_M2M_AUDIENCE`, and `MANAGEMENT_GATEWAY_DOMAINS` behind `management.enabled`; with it, also the volume
  `serviceaccount`, the pod's projected ServiceAccount token at `/var/run/secrets/kubernetes.io/serviceaccount` (see
  "Management API port");
- the `maxSurge: 1 / maxUnavailable: 0` strategy unless `DEPLOYMENT_STRATEGY_TYPE` says otherwise: the gateways must
  not lose all RLS endpoints at once;
- `lifecycle.preStop.sleep: 7s` (the native handler, needs k8s >= 1.30): on deletion the pod leaves Endpoints
  immediately, but xDS takes seconds to reach the gateways; the pause keeps the process serving through that window, so
  a rolling restart drops nothing and lets nothing slip through; the SIGTERM drain picks up the tail, and
  `terminationGracePeriodSeconds: 30` covers everything with margin;
- probes on 8081: liveness is HTTP `healthz`, readiness is HTTP `readyz`, which keeps a replica out of Endpoints until
  the first manifest is applied, without a timeout; an explicitly empty manifest counts as applied, and after the first
  apply the replica stays Ready on its in-memory snapshot when the files vanish or a later manifest is refused; the
  probes do not use the gRPC health service, which serves direct consumers;
- metrics on 8080, plain HTTP and cluster-internal, where `/debug/applied` reports the applied generation per domain,
  the format versions the replica reads, and a refusal with its reason, and `/debug/snapshot` renders what the replica
  enforces; `/debug/*` is read-only diagnostics, not the management API (see "Management API port");
- resources come from the profile; `ephemeral-storage` is limited in the template itself (the process writes no files).

### Observability: PodMonitor and Dashboard

Each chart ships a PodMonitor and a PrometheusRule (see "Alerts") behind `MONITORING_ENABLED`; the dashboard ships
with the service chart, behind the same flag. Both PodMonitors scrape the `metrics` port of their pods (30s, HTTP)
and carry the label `app.kubernetes.io/processed-by-operator: victoriametrics-operator`. The dashboard ships as a
`GrafanaDashboard` CR (grafana-operator); its uid is the namespace with a hash suffix (uniqueness under truncation,
the Grafana limit is 40 characters); auto-refresh is deliberately off, since a dashboard that redraws itself during an
incident tampers with the evidence.

### The counter store from DBaaS

The counters live in a Redis database that DBaaS provisions for the release. `InternalDatabase.yaml` and
`DatabaseSecretClaim.yaml` render one object of dbaas-operator each, with the same classifier,
`{microserviceName: <SERVICE_NAME>, scope: service, namespace: <NAMESPACE>}` and type `redis`:

- the `InternalDatabase` asks dbaas-aggregator to provision the database through the DBaaS Redis adapter. The adapter
  runs each database as a single Redis instance: a Deployment and a Service `<database>.<adapter namespace>`, no
  Cluster and no Sentinel. It builds the database's `redis.conf` from its own installation and accepts no settings per
  database, so the chart passes none;
- the `DatabaseSecretClaim` asks dbaas-operator to look the database up and write its connection properties into the
  Secret `<SERVICE_NAME>-redis` as `connectionProperties.json` (`host`, `port`, `password`, `url`, `role`) beside a
  `metadata.json` that names the classifier, and to rewrite it when they change. Its
  `app.kubernetes.io/name` label is the `originService` of the lookup, and it equals the classifier's
  `microserviceName`, so the service is the owner of the database it reads.

The Deployment mounts the Secret at `/etc/secrets/dbaas-secrets/<SERVICE_NAME>-redis` without `optional`, the platform's
path for DBaaS Secrets, and passes `--redis-dbaas-microservice=<SERVICE_NAME>` with `MICROSERVICE_NAMESPACE` from
the pod's namespace. The service resolves its database through the platform's Go DBaaS client
(`qubership-core-lib-go-dbaas-base-client`), which matches the mounted `metadata.json` to that classifier and type
`redis`. Until dbaas-operator has written the Secret, the pod waits in `ContainerCreating`; a replica never starts
counting on its own. The client falls back to REST only on a miss and holds no credentials for it, so a Secret that
does not match fails the start within 5 s with the classifier in the error, before the liveness probe fires. The
service reads host and port once: an address that changes in the Secret ends the process and the container restarts
onto the new database. It resolves the connection again every 30 s and uses the password the Secret holds from the
next connection on, without a restart. DBaaS itself never changes this password: the Redis adapter does not manage
users, and the aggregator refuses a password change for such adapters. Connection properties with `tls: true`, which
the aggregator adds when the adapter is installed with TLS, fail the start: the service connects in plain text.

Both objects carry `spec.operatorNamespace`: a dbaas-operator reconciles only the objects that name its own namespace.
It is `redis.dbaas.operatorNamespace` when that is set, and otherwise the namespace in the host of `API_DBAAS_ADDRESS`
(the platform parameter, `http://dbaas-aggregator.dbaas:8080` by default), since the operator runs beside its
aggregator. Read from the address, the host has to be `<aggregator>.<namespace>`, optionally followed by `.svc` or
`.svc.cluster.local`; `dbaas` is the namespace of the default. A host of one label fails the schema with
`at '/API_DBAAS_ADDRESS': '<address>' does not match pattern '^https?://[^.:/]+\\.[^.:/]+'`, and a host of any
other form, an IP address or an external name, fails the render with
`API_DBAAS_ADDRESS "<address>" does not name the namespace of dbaas-operator: its host is not
<aggregator>.<namespace>[.svc[.cluster.local]]. Set redis.dbaas.operatorNamespace.` Set
`redis.dbaas.operatorNamespace` to the namespace dbaas-operator runs in when the address has such a host.

The chart needs, and does not install:

- dbaas-operator, installed and enabled: its chart ships with `DBAAS_OPERATOR_ENABLED: false`, and it needs
  Kubernetes 1.32 or later for its CEL rules. Without its CRDs, `helm install` of this chart fails on the
  `InternalDatabase` kind;
- a `Role` and a `RoleBinding` in the namespace that grant dbaas-operator's service account `get`, `create`,
  `update`, and `patch` on `secrets`, since the operator holds no cluster-wide Secret access (dbaas-operator documents
  the bundle);
- the DBaaS Redis adapter registered with dbaas-aggregator, installed with `redis.conf.maxmemory-policy: noeviction`
  and without `redis.tls.enabled`. The adapter's default policy, `allkeys-lru`, lets Redis drop counters and
  management records under memory pressure without an error, which the
  [management API's store requirements](management-api.md) forbid. The policy applies to the databases the adapter
  creates afterwards; a database that already exists keeps the one it was created with. The service reads the policy
  at startup and logs a warning when it is not `noeviction`.

`spec.operatorNamespace` is immutable on both objects, so a corrected `API_DBAAS_ADDRESS` fails the next
`helm upgrade` until both are deleted. `helm uninstall` leaves the database: the `InternalDatabase` carries no
finalizer, so its deletion drops nothing, and the adapter's Redis Deployment stays in its namespace for a reinstall to
attach to.

`redis.dbaas.enabled=false` renders neither object for a cluster without DBaaS: the Deployment still mounts
`<SERVICE_NAME>-redis`, and whoever sets up the cluster writes it in the same format, as the e2e workflow does for its
own Redis:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ratelimit-service-redis        # <SERVICE_NAME>-redis
  namespace: <NAMESPACE>
stringData:
  connectionProperties.json: |
    {"host": "<redis host>", "port": 6379, "password": "<password>"}
  metadata.json: |
    {"classifier": {"microserviceName": "ratelimit-service", "namespace": "<NAMESPACE>", "scope": "service"},
     "type": "redis"}
```

The DBaaS client picks the Secret by its `metadata.json`: `classifier` has to equal the service's own,
`{microserviceName: <SERVICE_NAME>, namespace: <NAMESPACE>, scope: service}`, `type` has to be `redis`, and `userRole`
stays absent or empty, since the service requests no role; `name`, `namespace`, and `id` are optional and take no
part in the match. Of
`connectionProperties.json` the service reads `host` and `port` (a number or a string), or `url`, a `redis://` URL,
where either is missing; `password`, and `username` for a database that has one (the databases of the DBaaS Redis
adapter authenticate by password alone); and `tls`, which has to be absent or `false`. A Secret that does not match
fails the start as above, and one without an address fails it with
`the connection properties carry neither a host and a port nor a url`.

## Metrics: the naming contract

The actual names and labels (the source is `internal/metrics`); use this table when writing alerts. Registration is
split per binary, so each scrape carries only its own half: the service registers the data plane (the checks, the
decisions, the extraction detector, the store, the snapshot swaps, and the domain view), the operator registers the
control plane (the policy status, the fleet, and the ConfigMap writer's errors), and both register
`ratelimit_build_info`. A scrape of the operator therefore carries no check counter sitting at zero for a query to
exclude.

| Metric | Labels | What it counts |
| --- | --- | --- |
| `ratelimit_checks_total` | `domain`, `verdict: ok\|over_limit\|unavailable\|exempt` | checks; unavailable = store unavailable, the checks the gateway's failure mode decided; exempt = requests to the management API, admitted without a decision |
| `ratelimit_check_duration_seconds` | `domain` | decision histogram; the bucket bounds are laid on the 10ms budget and the filter timeout |
| `ratelimit_decisions_total` | `domain`, `rule` (limit block/rule), `outcome: ok\|over_limit\|shadow_over_limit` | per-rule outcomes |
| `ratelimit_near_limit_total` | `domain`, `rule` | allowed requests within the margin of the window's capacity, the burst of a GCRA window or the requests of a fixed one (the threshold is `metrics.nearLimitRatio`); shadow is excluded |
| `ratelimit_refusals_total` | `domain`, `cause: too_many_buckets\|too_many_descriptors\|invalid_cost` | hard refusals for configuration or protocol violations, not limits |
| `ratelimit_unknown_domain_checks_total` | none | deliberately without a domain label: the caller controls the name; the name itself is in the sampled log |
| `ratelimit_unmatched_checks_total` | `domain` | checks that applied no rule |
| `ratelimit_extraction_skips_total` | `domain`, `key`, `reason: decode_failed\|bad_type\|too_long\|too_many_items` | extraction anomalies; `domain` because mappings live on the policy, and two domains of one namespace may declare the same key |
| `ratelimit_extractions_total` | `domain`, `key` | decisions whose request carried a value for the declared key; the series are SEEDED with zero from the extraction plan at snapshot swap, so "zero" is observable |
| `ratelimit_tokens_seen_total` | `domain` | decisions with a token on a known domain that a block targeted, the requests whose token the engine reads; the detector's denominator, per domain so that an idle domain's declared keys are not judged by another domain's traffic |
| `ratelimit_store_roundtrip_seconds` | `domain` | store round-trip histogram (a domain = one shard) |
| `ratelimit_store_errors_total` | `domain`, `reason: timeout\|server\|other` | store errors: `timeout` is no answer within the check's deadline, `server` the store answering an error, `other` a connection that failed outright, a refused connection or a name that does not resolve; a decision is never retried |
| `ratelimit_snapshot_rebuilds_total` | `result: ok\|refused` | applies and swaps of the in-memory snapshot on a service replica; `refused` is a reading the replica would not apply (a format it does not read, an unknown field, a payload that fails the decoder or decompresses past 8 MiB), the snapshot stays and the reason is on `/debug/applied` |
| `ratelimit_snapshot_timestamp_seconds` | none | when the enforced rules last changed while the replica ran ("did the rules change before the incident"); 0 until the first change after a start, since a restart is not one |
| `ratelimit_config_absent` | none | 1 while the replica's mounted directory holds no manifest: the ConfigMap is gone, and nothing will change what the replica enforces |
| `ratelimit_policy_applied_generation` | `domain` | the generation THIS replica executes, for Prometheus; the operator computes the strict `Ready` not from this gauge but from the replica's `/debug/applied` on the metrics port (the applied generation per domain, the format versions the replica reads, and a refusal with its reason) |
| `ratelimit_token_cache_hits_total` / `_misses_total` | none | the token cache |
| `ratelimit_build_info` | `component: operator\|service`, `version` | the version of the binary serving this scrape, a const gauge always at 1; the chart passes the image tag as `SERVICE_VERSION` / `OPERATOR_VERSION`, and the operator stamps the same value into the manifest as `operatorVersion` |
| `ratelimit_policy_ready` | `domain`, `reason` | 0/1 of the strict `Ready`; status gauges are const metrics from the operator's scrape, there are never stale series |
| `ratelimit_policy_enforced` | `domain` | 1 while any generation of the policy is enforced, 0 while nothing is (`NotCompiled` on a first generation, `NoReplicas` aside); from the operator's judgement, like the series below |
| `ratelimit_policy_stalled` | `domain`, `reason: Progressing\|ReplicaStale\|NotCompiled\|ConfigMapTooLarge\|ReplicaFormatUnsupported` | 0/1 of the `Stalled` condition; `Progressing` is the reason while it reads 0, so a domain keeps one label set; while `Stalled` is `Unknown` the series keeps its last value and reason |
| `ratelimit_policy_replicas` | `domain`, `state: total\|applied` | the denominator and the numerator of `Ready` |
| `ratelimit_policy_generation_lag` | `domain` | how far activeGeneration lags behind the latest |
| `ratelimit_policy_rule_problems` | `domain`, `severity: blocking\|info` | every problem of the latest generation by weight, past the 64 that `ruleProblems` lists too; alert on `blocking` |
| `ratelimit_domain_blocks` / `ratelimit_domain_rules` / `ratelimit_domain_decision_buckets` | `domain` | domain facts: `decision_buckets` against 128, the headroom before `DomainBudgetExceeded`; `blocks` and `rules` are observed, with no bounds |
| `ratelimit_config_write_errors_total` | `reason: size\|api\|read\|other` | failed writes of `ratelimit-config` by the operator: `size` is a state the object cannot hold even after the fit, `api` an answer of the API server, `read` a reconcile that could not read the policies or the ConfigMap and wrote nothing, `other` the rest; the replicas keep the configuration they mounted and the last-good fallback is not saved; the status reports `ReplicaStale` 90 s later |
| `ratelimit_leader` | none | 1 on the operator pod that holds the Lease, 0 on the other one while two overlap during a rollout; the fleet series exist only on the pod reporting 1 |

## Argo CD: how to read the status

The policy's `Ready` is strict and binary: `True` only when all ready replicas execute the latest generation; `Stalled`
tells "in progress" from "broken". Argo CD does not assess CR health by default, so the platform puts a Lua check into
`argocd-cm` (`resource.customizations.health.ratelimit.netcracker.com_RateLimitPolicy`):

```lua
hs = { status = "Progressing", message = "waiting for status" }
if obj.status ~= nil and obj.status.conditions ~= nil then
  local ready, stalled
  for _, c in ipairs(obj.status.conditions) do
    if c.type == "Ready" then ready = c end
    if c.type == "Stalled" then stalled = c end
  end
  if stalled ~= nil and stalled.status == "True" then
    hs.status = "Degraded"; hs.message = stalled.message
  elseif ready ~= nil and ready.status == "True" then
    hs.status = "Healthy"; hs.message = ready.message
  elseif ready ~= nil then
    hs.status = "Progressing"; hs.message = ready.message
  end
end
return hs
```

The sync wave closes when every pod executes the rule; `Stalled: True` (`ReplicaStale`, `NotCompiled`,
`ConfigMapTooLarge`, `ReplicaFormatUnsupported`) is Degraded, everything else that is not `True` is Progressing,
including `Propagating` while the kubelet projects an update and `Ready: Unknown` on `ProbeFailed`.

## Installation and upgrade

`helm upgrade --install <release> <chart> -f resource-profiles/<profile>.yaml --set NAMESPACE=<namespace>
--set TAG=<tag> --set-string DEPLOYMENT_SESSION_ID=<session> …` is idempotent for either chart; the profile,
`NAMESPACE`, `TAG`, and `DEPLOYMENT_SESSION_ID` are mandatory (the schema); the set of rendered objects is derived from
`BASELINE_ORIGIN`; both charts go into one namespace. An upgrade installs the service chart before the operator chart,
and a rollback reverses the order.
The service reads the current and the previous manifest format version, and the operator writes the current one. In
that order the service reads what the operator writes at either end of the pair's rollout. A fresh installation goes
CRD release, operator chart, service chart: the service stays NotReady until the operator writes, and the service
chart's EnvoyFilters are live from the moment it is installed; the e2e workflow installs in that order. The CRD
release is installed and upgraded before any namespace (see "The CRD chart"). Namespaces can be upgraded in any order.
An upgrade with `--reuse-values` from a release installed before a value existed fails the render on that value
(`nil pointer evaluating`), because Helm then replaces the chart's defaults with the old release's. This applies to
both charts: pass the full values again, or `--reset-then-reuse-values`, which starts from the new defaults and
re-applies what the release set.

`make helm-lint` lints every resource profile of each chart in each of the three modes (single; baseline, with a
variable the charts do not read, so that the pass exists by name; satellite, with `BASELINE_ORIGIN`). CI renders the
satellite case of each chart on its own: from the service chart the filters alone, the authority
`ratelimit.<BASELINE_ORIGIN>.svc.cluster.local`, and `BASELINE_CONTROLLER` taking precedence when set; from the operator
chart an empty render. The service chart is also rendered for the management port never rendered without its
AuthorizationPolicy, for the principal that policy allows, and for the identity values in every mode (see "Management
API port"). The CRD copy of the `ratelimit-crds` chart is checked for drift against `config/crd/bases`, and neither
namespace chart may render a CRD. Beyond the lint, a render test in Go renders both charts and compares the rendered
names and ports (the Service and its ports, the address in the EnvoyFilters, the ConfigMap of the volume) with the
constants of the contract package. A CI step reads the build information of the service binary and fails when client-go
is present; a depguard rule forbids client-go and controller-runtime under `service/` at lint time. Both images are
built on every pull request from the components list of `.github/docker-dev-config*.json`. One e2e workflow installs the
CRD chart, then both charts in the baseline namespace, the operator first, and both in the satellite namespace, where a
spec asserts that the satellite holds the service chart's two filters and no component of either chart.

## Alerts

Each chart ships its alert rules as one `PrometheusRule` in `NAMESPACE`, rendered with `MONITORING_ENABLED` and the
chart's own switch (`policyAlerts.enabled` in the operator chart, `alerts.enabled` in the service chart); a satellite
renders neither. The split follows the series: the service chart alerts on the data plane, the operator chart on the
policy status, and every expression carries `namespace="<NAMESPACE>"`, so a namespace's rules judge its own pods.

The service chart, group `ratelimit-service`:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `RatelimitUnknownDomain` | warning | `increase(ratelimit_unknown_domain_checks_total[5m]) > 0` for `unknownDomainFor`: checks arrive for a domain no policy claims, or for one whose policy enforces no generation (`RatelimitNotEnforced`), and pass unlimited. The domain name is in the service log, not in a label |
| `RatelimitStoreErrors` | critical | `increase(ratelimit_store_errors_total[5m]) > 0` by `reason`, for `storeErrorsFor`: the counter store is failing, and every failed check is decided by the gateway's failure mode |
| `RatelimitDecisionLatencyHigh` | warning | the p99 of `ratelimit_check_duration_seconds` is above `latencyBudgetSeconds` for `latencyFor` |
| `RatelimitKeyDeclaredNotExtracted` | warning | a declared key's `ratelimit_extractions_total` rate is zero over `keyNotExtractedWindow` while the same domain's `ratelimit_tokens_seen_total` grows, for `keyNotExtractedFor`: the mapping names a claim the tokens do not carry |
| `RatelimitDomainBudgetNearLimit` | warning | `ratelimit_domain_decision_buckets` reaches `domainBudgetWarnAt` of the budget of 128, with no hold: the next edit may stop compiling |
| `RatelimitConfigurationAbsent` | warning | `ratelimit_config_absent == 1` on a replica for `configAbsentFor`: the operator's ConfigMap is gone, and the replica keeps what it applied |

The operator chart, group `ratelimit-operator`:

| Alert | Severity | Fires when |
| --- | --- | --- |
| `RatelimitStalled` | critical | `ratelimit_policy_stalled == 1` for `stalledFor`, with the reason in the label: `ReplicaStale`, `ReplicaFormatUnsupported`, or `ConfigMapTooLarge`. `NotCompiled` is left to `RatelimitRuleProblems`, since the last-good generation stays enforced |
| `RatelimitNotEnforced` | critical | `ratelimit_policy_enforced == 0` for `notEnforcedFor`: the policy enforces no generation at all, so its domain passes unlimited |
| `RatelimitNotReadyLong` | warning | `ratelimit_policy_ready == 0` for `notReadyFor`: the latest generation is not the one enforced |
| `RatelimitNoReplicas` | critical | `ratelimit_policy_ready{reason="NoReplicas"} == 0` for `noReplicasFor`: the operator observed no ready service replica, so the gateway's failure mode decides every check of the domain; a fleet it could not observe is `ProbeFailed` and does not fire |
| `RatelimitChecksStopped` | warning | `ratelimit_policy_replicas{state="applied"} > 0` while the domain's `ratelimit_checks_total` has no rate over `checksStoppedWindow`, for `checksStoppedFor`: the filter is off, removed, or on another domain, and traffic passes unlimited with every status Ready; an idle gateway fires too (the composite case is below the table) |
| `RatelimitRuleProblems` | warning | `ratelimit_policy_rule_problems{severity="blocking"} > 0` for `ruleProblemsFor`: the latest generation is not enforced and last-good runs instead |
| `RatelimitConfigWriteErrors` | critical | `increase(ratelimit_config_write_errors_total[configWriteErrorsWindow]) > 0` by `reason`, with no hold, and kept firing for `configWriteErrorsKeepFiring` after the last one: policy changes stop reaching the service |
| `RatelimitOperatorReconcileFailing` | critical | a controller of the operator records reconcile errors and no successful reconcile over `reconcileErrorsWindow`: the leader holds the Lease and does nothing, so no other alert names it |
| `RatelimitNoOperatorLeader` | critical | `absent(ratelimit_leader == 1)` for `noLeaderFor`: no operator pod holds the Lease, so nothing compiles policies or writes `ratelimit-config` |

`RatelimitChecksStopped` sums the domain's checks over every gateway, so in a composite one gateway's disabled
filter does not fire it while the other gateways keep sending.

Every rule carries a `summary` and a `description`; the description names the number, what it means for traffic, and
where to look next, which is the sentence the [runbook](runbook.md) expands.

The thresholds and hold durations are the `policyAlerts.*` values of the operator chart and the `alerts.*` values of the
service chart, listed with their defaults in "Values reference" and bounded by the schema. Two pairings are load-bearing
rather than taste: `unknownDomainFor` and `storeErrorsFor` are each at least the 5 m window of their expression, because
`increase(...[5m]) > 0` stays true for five minutes after a single increment and a shorter hold would fire inside that
window, paging on one stray check or one retried timeout; and both halves of `RatelimitKeyDeclaredNotExtracted` are
summed by `domain`, so a domain with no traffic is never judged by a busy neighbour's tokens. Lower a hold below its
window only where every single event must page.

`tests/charts` replays these rules through `promtool test rules` against the fixtures in
`tests/charts/testdata/*.rules.test.yaml`: the negative cases (a lone store error, a stray unknown-domain check, an
idle domain beside a busy one, a Lease handed over during a rollout) are pinned beside the positive ones, so a
threshold moved without its rationale fails CI rather than a pager.

## Management API port

The [management API](management-api.md) lives in the service and its chart. It is off by default:
`management.enabled` adds the `management` port (8082, plain HTTP) to the container and the Service and passes
`--management-bind-address` to the process; without it the endpoints do not exist. The port is outside the gateways'
data path, and public traffic never reaches it. Its idempotency records and confirmation tokens live in the counter
store, so the service writes nothing to the API server.

The service authenticates every call itself: the bearer token is a Kubernetes ServiceAccount token issued for
`management.m2m.audience` (default `netcracker`), verified against the API server's OIDC discovery, and a caller listed
in `management.callers` holds `operator`; any other verified caller gets 403 (see the [management API's
security](management-api.md#security)). An entry is `<name>` for a ServiceAccount in `NAMESPACE` or `<namespace>/<name>`
for one elsewhere; the schema refuses an empty list while `management.enabled` is true, and the service leaves out an
entry of another shape and logs it. To verify, the pod mounts its own ServiceAccount token in the volume
`serviceaccount` at `/var/run/secrets/kubernetes.io/serviceaccount`: a projected `serviceAccountToken`, the cluster CA
from the ConfigMap `kube-root-ca.crt`, and the namespace from the Downward API, the layout the API server's automount
gives. `automountServiceAccountToken` stays `false`, and the ServiceAccount has no Role, so the token reads the OIDC
discovery and the key set, which every ServiceAccount may read, and nothing else. The discovery runs over TLS against
the system trust store, so the base image has to carry the cluster's ServiceAccount CA there. Until the discovery
answers, the API refuses every call with `503` and `RLS-0504`, retries the discovery without a restart, and the data
path is unaffected. The Deployment renders the values as `MANAGEMENT_CALLERS` and `MANAGEMENT_M2M_AUDIENCE`, read at
start. The e2e install sets a caller and an audience of its own, so the suite proves the values reach the service, not
only the Deployment.

`AuthorizationPolicy.yaml` keeps the port to the callers: a `DENY` on the management port for every source but
`management.authorizationPolicy.allowedServiceAccounts`, where an empty list means the callers. An entry of either list
is `<name>` in `NAMESPACE` or `<namespace>/<name>` in its own namespace, rendered as
`cluster.local/ns/<namespace>/sa/<name>`, and the schema refuses an entry of another shape. When the callers come
through a gateway, the policy sees the gateway's workload rather than theirs; list its ServiceAccount there, which
Istio's automated deployment names after the gateway and its class, `<gateway>-istio`, together with any caller that
reaches the port directly. `DENY` with `notPrincipals` rather than `ALLOW`, because an `ALLOW` policy applies to the
whole workload and would have to enumerate the gRPC and metrics ports as well; a port left out of that list would stop
answering. ztunnel enforces it, so it holds only while the pod is in the mesh: a namespace without ambient redirection
or a sidecar gets a policy that matches nothing and an open port, behind which the token check still holds.
`management.authorizationPolicy.enabled: false` is for a deployment where something outside the mesh already does the
same job, and belongs in a review. A satellite renders none of this: the service chart renders only the gateway filters
there.

`management.gatewayDomains` (a list of rate limit domains, default `[gateway.private]`) names the domains of the
gateways that route to the API. The gateway checks a request to the API like any other request it carries, and the
service admits that check without a decision: for a path that is `/ratelimit/v1` or lies under it by whole segments,
in one of these domains, it reads neither the rules nor the counter store, and counts the check as `verdict="exempt"`
in `ratelimit_checks_total` (in a domain no policy claims, the check passes as an unknown domain's does). Two things
follow. The API stays reachable through a gateway that fails closed while the
counter store is down: the endpoints that read no counters return `200`, and the ones that read them return the
service's own `RLS-0503` instead of the gateway's `503`. And a policy of these domains has no effect on the API's
paths, whatever its targets: requests to the API charge no counter and are never refused with `429`.

Each entry has to equal `gateways.<role>.domain` of the service chart for that gateway; the schema holds an entry to
the pattern of `spec.domain`, and nothing checks that a gateway sends it. An entry that is no gateway's domain exempts
nothing, and the API's requests are then checked like the rest of the gateway's traffic. The same path in a domain
outside the list is always checked. In a composite every gateway sends the same domains, so the exemption holds on the
satellites' gateways of a listed domain too: a request under `/ratelimit/v1` through a satellite's private gateway is
not rate limited either, whatever that gateway routes the path to. Change the list when the private gateway's domain is
not the default, or when a gateway added to `management.authorizationPolicy.allowedServiceAccounts` routes to the API as
well. An empty list exempts nothing, and a caller that reaches the port directly needs no entry, since its requests
pass no gateway's check. The Deployment renders the list as `MANAGEMENT_GATEWAY_DOMAINS`, read at start;
with `management.enabled: false` the variable is not rendered and no path is exempt.

The exemption removes the dependency on the counter store, not on the check: the gateway still sends one, and under
`failClosed: true` a check that gets no answer within `filter.timeout` is a `503` for the API's request as for any
other. A `503` with no `RLS-` code in its body is that case, or a gateway whose domain is missing from the list.

`/debug/*` on the metrics port is not the management API: read-only diagnostics with no mutations and no
authentication, cluster-internal, outside the compatibility promises. `/debug/applied` is the operator's probe, and
the Service publishes the port for it under the name `metrics`; `/debug/snapshot` and `/debug/snapshot/{domain}` render
what one replica enforces, for a human with a port-forward. The management role model does not apply to either.

## What the charts do not install

- **A `DestinationRule` for the Service `ratelimit`.** A dead replica leaves Endpoints through its readiness probe and
  EDS updates the Envoy cluster; a replica that hangs while still passing the probe is cut off by the filter's 50 ms
  timeout and the request is decided by the gateway's failure mode. Outlier detection would only shrink that second
  share, and Istio's defaults make a naive configuration inert anyway: `maxEjectionPercent: 10%` never ejects one of
  two or three replicas, and `consecutive5xxErrors` counts upstream 5xx, while the failure here is a local-origin
  timeout. TLS is not configured in a traffic policy either way; ambient provides mTLS.
- **A redirect when a limit fires.** The filter's local reply is the plain `rateLimitedStatus` (429 by default) with
  `retry-after`, which is what an API client can act on. No `local_reply_config` mapper turns it into a 302.
- **An `AuthorizationPolicy` or a `NetworkPolicy` on the RLS port 9000.** Neither namespace chart renders one; the
  only AuthorizationPolicy of the delivery covers the management port 8082, behind `management.enabled`. Where direct
  callers of the RLS must be restricted, the installation adds the policy ([engine](engine.md), "Token and identity").
