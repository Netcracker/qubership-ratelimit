# Operations runbook

How to read what the rate limit components report and what to do about it. Written against the one-object architecture
with two components per namespace: the operator Deployment `ratelimit-operator`, which reads the policies, writes their
status, and writes the ConfigMap `ratelimit-config`; and the service Deployment `ratelimit-service`, which mounts that
ConfigMap and serves the decisions. One `RateLimitPolicy` per domain; the ConfigMap is the last-good state. The design
is in the [topology](deployment-topology.md), the [resource specification](ratelimitpolicy-cr-spec.md), the
[management API](management-api.md) with its [cookbook](management-api-cookbook.md), and the [charts](helm-chart.md),
which hold the metric names.

Every scenario has the same shape: the signal that starts it, the commands that diagnose it with the output to expect,
the action, and the check that closes it. Commands assume `kubectl` access to the namespace and a platform token with
the `viewer` or `operator` role; Prometheus queries assume the PodMonitors of the two charts. The outputs were taken
from a kind stand running the two charts and the reference policy of the repository; pod names, timestamps, and image
tags are the stand's. Every command below ran there, except where the text says the stand cannot (section 8).

## 0. Setup and the first look

```bash
NS=ratelimit-e2e             # the namespace of the installation
DOMAIN=gateway.public        # the policy is named after its domain
kubectl port-forward -n "$NS" svc/ratelimit 8082:8082 &
BASE=http://127.0.0.1:8082/ratelimit/v1
TOKEN=<platform token with the viewer role>
OPTOKEN=<platform token with the operator role>
api() { curl -sS -H "Authorization: Bearer $TOKEN" "$@"; }
op()  { curl -sS -H "Authorization: Bearer $OPTOKEN" "$@"; }
```

On the platform the same API is routed through the private gateway under the same prefix; the port-forward is the
path for an operator who already holds `kubectl` access. The service never verifies the token signature, the gateway
does, so a port-forward is a shortcut that bypasses that check: use it for diagnosis, not as a habit.

The installation is two Deployments in the namespace. The operator pod reads the policies, writes their status, and
writes the ConfigMap `ratelimit-config`; the service pods mount that ConfigMap and serve the decisions and the
management API. A service pod turns Ready only after it applies its first manifest, without a timeout. A service pod
that stays NotReady has no manifest yet: the operator has not written the ConfigMap, the kubelet has not projected it
into the pod, or the replica refuses it (section 5).

```bash
kubectl get deploy -n "$NS" ratelimit-operator ratelimit-service
kubectl get pods -n "$NS" -l 'app.kubernetes.io/name in (ratelimit-operator, ratelimit-service)'
```

Two logs: the operator's carries the reconciles, the status writes, and the probes of the replicas; the service's
carries the decision path and the management API.

```bash
kubectl logs -n "$NS" deploy/ratelimit-operator --since=10m | tail
kubectl logs -n "$NS" deploy/ratelimit-service --since=10m | tail
```

The one command to start with:

```bash
kubectl get rlp -n "$NS"
```

```text
NAME              READY   REPLICAS   RULES   PROBLEMS   AGE
gateway.private   True    1/1        1                  75m
gateway.public    True    1/1        12                 75m
```

`READY` is strict: `True` only when every ready service replica enforces the latest generation. `REPLICAS` is
`applied/total`: how many of the ready replicas do. `PROBLEMS` counts the `ruleProblems` entries of the latest
generation, blocking and informational alike, and stays blank while there are none. Anything other than `True`, `n/n`,
and a blank `PROBLEMS` has a section below:

| What you see | Meaning | Section |
| --- | --- | --- |
| `Ready: False`, reason `NotCompiled`, `Stalled: True` | the latest generation does not compile; last-good is enforced | 3, or 5 when `ruleProblems` names an unknown field |
| `Ready: False`, reason `ConfigMapTooLarge`, `Stalled: True` | the latest generation does not fit the 1 MiB ConfigMap; last-good is enforced | 3 for what traffic sees; the fix is a smaller spec, about 45000 UUIDs of client lists fill the object |
| `Ready: False`, reason `Propagating` or `Reconciling`, `Stalled: False` | a rollout in progress, nothing to do yet | 4 if it lasts |
| `Ready: False`, reason `ReplicaStale`, `Stalled: True` | a service replica lags past 90 s | 4 |
| `Ready: False`, reason `ReplicaFormatUnsupported`, `Stalled: True` | a service replica refuses the manifest's format version | 4, and 5 for the order of the fix |
| `Ready: False`, reason `NoReplicas` | no ready service replica | 4 |
| `Ready: Unknown`, reason `ProbeFailed` | the operator cannot read the service replicas | 4 |
| `Accepted: False`, reason `CompilationFailed` | the same as `NotCompiled`, seen from the object's side | 3 or 5 |
| `Ready: False`, reason `Reconciling` that lasts, with `ratelimit_config_write_errors_total` growing | the operator cannot write `ratelimit-config` | 9 |
| a fresh service pod NotReady with no other symptom | no ConfigMap in its volume yet | 9 |

The full status, and the three numbers that summarize it:

```bash
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status}' | jq
kubectl get rlp -n "$NS" "$DOMAIN" \
  -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.activeGeneration}{"\n"}'
# 1 1 1
```

```json
{"observedGeneration": 1, "activeGeneration": 1, "rules": 12,
 "replicas": {"applied": 1, "lastCheckTime": "2026-09-21T13:22:45Z", "summary": "1/1", "total": 1},
 "effectiveKeys": ["client", "method", "path", "plan", "roles"],
 "conditions": [
   {"type": "Accepted", "status": "True", "reason": "RulesCompiled", "message": "generation 1 compiles: 2 blocks, 12 rules"},
   {"type": "Ready", "status": "True", "reason": "AllReplicas", "message": "all 1 ready replicas enforce generation 1"},
   {"type": "Stalled", "status": "False", "reason": "Progressing"}]}
```

The service's own view, per replica, through the management API:

```bash
api "$BASE/status" | jq
# {"replica": "ratelimit-service-686d7856bf-jbccp", "snapshotSwappedAt": "2026-09-21T13:20:59Z",
#  "ruleSetVersions": {"gateway.private": "957f8204794e", "gateway.public": "5ff0f5a9e94d"},
#  "counterStore": {"backend": "redis at e2e-redis:6379"}}
api "$BASE/domains" | jq
# {"items": [{"domain": "gateway.public", "ruleSetVersion": "5ff0f5a9e94d", "blocks": 2, "rules": 12,
#             "effectiveKeys": ["client", "method", "path", "plan", "roles"], "listValuedKeys": ["roles"]}, ...]}
```

The channel between the two Deployments is the ConfigMap `ratelimit-config`, one per namespace. The operator writes it
as a whole on every reconcile, even when the namespace holds no policy, and no chart renders it. Under `binaryData` it
holds one `<domain>.json.gz` key per domain, the validated spec of the domain gzip-compressed. Under `data` its
`manifest` key is plain JSON with the integer `formatVersion`, the `operatorVersion`, and the `generation`, `uid`, and
`hash` of every domain. It is the last-good state: the `generation` of a domain in the manifest is the one
`activeGeneration` reports.

```bash
kubectl get cm -n "$NS" ratelimit-config -o json | jq -c '.binaryData | keys'
# ["gateway.private.json.gz","gateway.public.json.gz"]
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq -c
# {"formatVersion": 1, "operatorVersion": "20b5501", "domains": {
#   "gateway.private": {"generation": 3, "uid": "274ac015-...", "hash": "sha256:66aa18f6..."},
#   "gateway.public": {"generation": 1, "uid": "fb3aa99c-...", "hash": "sha256:0f30f38e..."}}}
kubectl get cm -n "$NS" ratelimit-config -o json \
  | jq -r '.binaryData["gateway.public.json.gz"]' | base64 -d | gunzip | jq
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}{"\n"}'
# Deployment/ratelimit-operator
```

`/debug/applied` on the metrics port of a service pod, 8080 by default, reports what the replica applied: the
generation per domain, the manifest format versions the replica reads, and, after a refused manifest, the refusal with
its reason. The operator reads the same endpoint once per probe cycle, and the `REPLICAS` column counts what it read.

```bash
kubectl get pods -n "$NS" -l app.kubernetes.io/name=ratelimit-service -o name
kubectl port-forward -n "$NS" pod/<a service pod> 8080:8080 &
curl -s http://127.0.0.1:8080/debug/applied | jq -c
# {"domains": {"gateway.private": {"generation": 3, "uid": "274ac015-...", "appliedAt": "2026-09-21T13:20:59Z"},
#              "gateway.public": {"generation": 1, "uid": "fb3aa99c-...", "appliedAt": "2026-09-21T13:20:59Z"}},
#  "formatVersions": [1]}
```

`/debug/snapshot` on the same port answers the other half of the question, what the replica enforces rather than which
generation it applied: a summary row per domain with its `ruleSetVersion`, block, rule, and worst-case bucket counts,
and its effective keys, and `/debug/snapshot/{domain}` with the compiled domain in full, every group resolved into the
client list the engine tests and every identity key next to the claim path it reads. Add `?format=yaml` to read it.
Compare two pods this way when a rollout looks skewed.

```bash
curl -s "http://127.0.0.1:8080/debug/snapshot" | jq -c '.domains[] | {domain, generation, ruleSetVersion, rules}'
# {"domain":"gateway.private","generation":3,"ruleSetVersion":"957f8204794e","rules":1}
# {"domain":"gateway.public","generation":1,"ruleSetVersion":"5ff0f5a9e94d","rules":12}
curl -s "http://127.0.0.1:8080/debug/snapshot/gateway.public?format=yaml" | head -40
```

The ConfigMap is owned by the operator Deployment, so it goes with the operator and never with a policy; the operator
recreates it within a second if it is deleted (section 9). `logLevel: debug` on the operator chart turns on the
operator's own debug lines, controller-runtime's, and the lines client-go writes about its lists, watches, and request
retries, and nothing above that verbosity: the client's request and response bodies stay out of the log at every level,
because the bridge in `internal/process/logr_adapter.go` caps the verbosity at 4.

## 1. Store degradation

The counter store is a Redis database from DBaaS, a single Redis instance the DBaaS Redis adapter runs in its own
namespace. Without it the service cannot count, and what it does then is decided by the gateway
filter: with `filter.failClosed: false` of the operator chart, the default, requests pass without limits; with `true`,
the gateway refuses them. Either way the service keeps answering, and the window of unlimited traffic is measurable.

**Signal.** Checks answered as unavailable, and store errors:

```promql
sum by (domain) (rate(ratelimit_checks_total{verdict="unavailable"}[5m]))
sum by (domain, reason) (rate(ratelimit_store_errors_total[5m]))
```

On the stand, 25 requests during the outage, all admitted with `failClosed` off:

```text
ratelimit_checks_total{domain="gateway.public",verdict="unavailable"} 25
ratelimit_store_errors_total{domain="gateway.public",reason="timeout"} 25
```

The management API answers every call that needs the store with `RLS-0503`, and the gateway's clients see no `429` at
all while `failClosed` is off.

**Diagnose.**

```bash
# where the store lives: the host of the Secret the service mounts, <database>.<adapter namespace>
kubectl get secret -n "$NS" ratelimit-service-redis -o jsonpath='{.data.connectionProperties\.json}' \
  | base64 -d | jq -r '.host'
kubectl get pods -n <adapter namespace> -l app=<database>
api "$BASE/domains/$DOMAIN/counters?limited=true" | jq -c '{code, message}'
# {"code": "RLS-0503", "message": "the counter store did not answer the scan"}
kubectl logs -n "$NS" deploy/ratelimit-service --since=10m | grep -E 'store error|failed to scan' | tail
# [ERROR] ... [class=ratelimit] rate limit store error domain=gateway.public path=/api/v1/exports/1
#   error=redis: decision script: context canceled suppressed=0
# [ERROR] ... [class=ratelimit] failed to scan counter keys domain=gateway.public error=redis: scan: EOF
```

The `reason` label tells the class: `timeout` is latency or a partition, `server` is Redis refusing, `other` is the
client giving up. The `ratelimit_store_roundtrip_seconds` histogram shows whether the store was slow before it failed.
The policy status does not move during the outage: it describes rules, not counters, and `Ready` stays `True`.

A replica that does not start at all, stuck in `ContainerCreating` with `secret "ratelimit-service-redis" not found`,
is waiting for DBaaS rather than for Redis: the Secret is written by dbaas-operator once the database exists. The
claim's status says why it is not there yet:

```bash
kubectl get databasesecretclaim,internaldatabase -n "$NS"
kubectl get databasesecretclaim -n "$NS" ratelimit-service-redis \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
```

`DatabaseNotFound` is the database still being provisioned, or the `InternalDatabase` failing (read its conditions);
after ten minutes the reason turns to `DatabaseNotFoundTimeout`, and the claim keeps polling. `Unauthorized` is the
aggregator refusing dbaas-operator's own credentials (401). `AggregatorRejected` is any other 4xx: a request the
aggregator finds invalid (400), a service it refuses (403), or dbaas-operator's access.

The jsonpath prints nothing in two cases that look the same from here: no dbaas-operator watches the namespace that
`spec.operatorNamespace` names, or the operator cannot write the Secret. A refused Secret write sets no condition and
records no event. The next step for both is the dbaas-operator log: `forbidden` there is the missing `Role` that lets
the operator write Secrets in the namespace, and silence is an `operatorNamespace` that no operator watches, so compare
it with the `API_DBAAS_ADDRESS` the release was installed with.

```bash
kubectl logs -n <dbaas namespace> deploy/dbaas-operator --since=10m | grep -E 'ratelimit-service-redis|forbidden'
```

An `InternalDatabase` whose provisioning failed, for example with no Redis adapter registered, stays in
`AggregatorRejected` with `Stalled`, and dbaas-operator does not retry it until its spec changes. Once the cause is
fixed, delete the `InternalDatabase` and run the release's `helm upgrade` again, which renders it anew.

**Act.** Restore the store; the service reconnects on its own, there is nothing to restart. If an unlimited window
is not acceptable for a domain, `filter.failClosed: true` in the operator chart's values turns the window into refusals
instead; that is a deployment decision, not an incident action.

**Verify.** The `unavailable` rate returns to zero and the listing answers again. The counters start from empty: keys
that expired during the outage are gone, and the first window after recovery admits a full budget. On the stand, three
requests after the recovery showed `remaining: 17` on a window of 100 with a burst of 20, a fresh bucket.

## 2. Who is being limited and why

**Signal.** A client reports `429`, or a suspicion that a limit is wider or narrower than intended.

**Who is refused right now.** The listing with `limited=true` shows every counter that would refuse the next request
of cost one; a `shadow` entry means "would have refused" and loses no traffic:

```bash
api "$BASE/domains/$DOMAIN/counters?limited=true" | jq -c '[.items[] | {ruleId, axes, mode, retryAfterSeconds}]'
# [{"ruleId": "api/exports-per-client-trial", "axes": {"client": "bob"}, "mode": "shadow", "retryAfterSeconds": 719.7},
#  {"ruleId": "api/per-client", "axes": {"client": "alice"}, "mode": "enforce", "retryAfterSeconds": 0.04}]
```

**One client across the domain.** A partial identity is legal in a read; one entry per window of every rule that
counts by the axis:

```bash
api "$BASE/domains/$DOMAIN/counters?axis.client=alice" | jq -c '[.items[] | {ruleId, axes, limit, remaining}]'
# [{"ruleId": "api/per-client", "axes": {"client": "alice"}, "limit": 20000, "remaining": 19976},
#  {"ruleId": "api/per-client", "axes": {"client": "alice"}, "limit": 100, "remaining": 0}]
```

**Which rules apply to a client.** The rule listing scoped by a partial identity annotates every rule with its
applicability, and the engine accounts for the cascade and `replacedRules`, which `jq` over the bare view cannot:

```bash
api "$BASE/domains/$DOMAIN/rules?axis.client=alice" \
  | jq '{always: [.blocks[].rules[] | select(.applicability == "always") | .id],
         conditional: [.blocks[].rules[] | select(.applicability == "conditional") | .id]}'
# {"always": ["api/per-path", "api/total"],
#  "conditional": ["api/per-client", "api/enterprise-per-client", "api/role-crawler", "api/exports-per-client-trial",
#                  "orders/items-per-order", "orders/orders-per-client"]}
api "$BASE/domains/$DOMAIN/rules?axis.client=alice" \
  | jq -c '[.blocks[].rules[] | select(.applicability == "conditional") | {id, conditionalOn}]'
# [{"id": "api/per-client", "conditionalOn": [{"reason": "may_be_preempted", "rule": "api/enterprise-per-client"}]},
#  {"id": "api/enterprise-per-client", "conditionalOn": [{"reason": "undecided_condition", "key": "plan"}]}, ...]
```

`conditionalOn` on each conditional rule says what would decide it: an undecided condition on a key you did not name,
a rule ahead of it in a `FirstMatch` cascade or a `replacedRules` neighbor that may preempt it, a missing counting axis.
Name more of the identity, and the picture narrows:

```bash
api "$BASE/domains/$DOMAIN/rules?axis.client=alice&axis.plan=enterprise&absent=roles"
# {"always": ["api/per-path", "api/enterprise-per-client", "api/total"],
#  "conditional": ["orders/items-per-order", "orders/orders-per-client"]}
```

**Which rules guard a path.** The engine's own matcher, with segment-based `Prefix` and `Template`:

```bash
api "$BASE/domains/$DOMAIN/rules?path=/api/v1/orders/42/items&method=GET" | jq -c '[.blocks[].rules[].id]'
# ["api/per-path", "api/per-client", ..., "orders/create-bulk-client", "orders/items-per-order", ...]
```

**Replay one request.** The simulation charges nothing and answers what the gateway would have answered, with every
rule that applied and the binding window in `headers`:

```bash
api -X POST "$BASE/simulations" -H 'Content-Type: application/json' -d '{
  "domain": "'"$DOMAIN"'", "path": "/api/v1/exports/1", "method": "GET",
  "keys": {"client": ["alice"], "plan": ["free"]}
}' | jq -c '{allowed, refusalReason, headers, rules: [.rules[] | {id, mode, allowed, remaining}]}'
# {"allowed": true, "refusalReason": null,
#  "headers": {"algorithm": "gcra", "periodSeconds": 60, "limit": 100, "remaining": 1, "resetAfterSeconds": 11.2},
#  "rules": [{"id": "api/per-path", "mode": "enforce", "allowed": true, "remaining": 100},
#            {"id": "api/per-client", "mode": "enforce", "allowed": true, "remaining": 1},
#            {"id": "api/total", "mode": "enforce", "allowed": true, "remaining": 571}]}
```

With the client's own token instead of keys, `identitySource: token`, the response also carries `skips`: a token the
mapping cannot read collapses the client into anonymous, and `skips[].reason` says why:

```bash
api -X POST "$BASE/simulations" -H 'Content-Type: application/json' -d '{
  "domain": "'"$DOMAIN"'", "path": "/api/v1/exports/1", "method": "GET",
  "identitySource": "token", "token": "garbage"
}' | jq -c '{allowed, extractedKeys, skips}'
# {"allowed": true, "extractedKeys": null,
#  "skips": [{"key": "client", "reason": "decode_failed"}, {"key": "roles", "reason": "decode_failed"},
#            {"key": "plan", "reason": "decode_failed"}]}
```

**The limit fires for nobody.** Two counters say whether the domain is wired at all:

```promql
rate(ratelimit_unknown_domain_checks_total[5m]) > 0      # the gateway sends a domain no policy declares
sum by (domain) (rate(ratelimit_unmatched_checks_total[5m]))   # checks that applied no rule
```

An unknown domain is a typo between the gateway filter and `spec.domain`; the name itself is in the sampled log of the
service, not in a label. And the extraction detector: a declared key that never arrives in a token. The extraction
counters carry the domain and the declared key, and so does the token counter they are judged against, so two
domains of one namespace keep separate series and an idle domain is never judged by a busy one's traffic:

```promql
sum by (domain, key) (rate(ratelimit_extractions_total{key="plan"}[15m])) == 0
  and on (domain) sum by (domain) (rate(ratelimit_tokens_seen_total[15m])) > 0
```

```text
ratelimit_extractions_total{domain="gateway.public",key="client"} 44
ratelimit_extractions_total{domain="gateway.public",key="plan"} 44
ratelimit_extractions_total{domain="gateway.public",key="roles"} 44
ratelimit_tokens_seen_total{domain="gateway.public"} 69
```

The gap between the tokens seen and the extractions is the warm-up probes without a token and the simulations.

## 3. A rejected edit

An edit that passes the schema but not the compiler lands in etcd and is refused as a whole: none of its rules is
enforced, the previous good generation keeps serving. The author has to read the status to know. An edit that fails
the schema never gets that far: `kubectl apply` refuses it on the spot, for example `burst: 0` answers
`spec.limits[0].rules[0].rates[0].burst in body should be greater than or equal to 1`, and nothing changes.

**Signal.** `READY False`, `PROBLEMS` above zero, the gauges, and one `Warning` event per generation that does not
compile:

```promql
max by (domain) (ratelimit_policy_rule_problems{severity="blocking"}) > 0
max by (domain) (ratelimit_policy_generation_lag) > 0
```

```text
ratelimit_policy_enforced{domain="gateway.public"} 1
ratelimit_policy_generation_lag{domain="gateway.public"} 1
ratelimit_policy_ready{domain="gateway.public",reason="NotCompiled"} 0
ratelimit_policy_rule_problems{domain="gateway.public",severity="blocking"} 2
ratelimit_policy_rule_problems{domain="gateway.public",severity="info"} 0
ratelimit_policy_stalled{domain="gateway.public",reason="NotCompiled"} 1
```

```bash
kubectl get events.events.k8s.io -n "$NS" --field-selector reason=NotCompiled \
  -o custom-columns=TYPE:.type,REASON:.reason,OBJECT:.regarding.name,NOTE:.note
# TYPE      REASON        OBJECT           NOTE
# Warning   NotCompiled   gateway.public   generation 2 does not compile: 2 blocking problems (UnresolvedKeyReference, UnresolvedReplacedRules)
```

The event is written by the operator when a new generation fails, not on every reconcile: the same broken generation
applied again 20 s later added nothing, and the next broken generation adds one line. The events API is
`events.k8s.io`; `kubectl get events` lists them too.

**Diagnose.** On the stand, an edit that referenced a key `plann` and a replaced rule `per-clint`:

```bash
kubectl get rlp -n "$NS"
# NAME              READY   REPLICAS   RULES   PROBLEMS   AGE
# gateway.public    False   1/1        12      2          78m
kubectl get rlp -n "$NS" "$DOMAIN" \
  -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.activeGeneration}{"\n"}'
# 2 2 1      -> the operator observed generation 2, generation 1 is enforced
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.conditions}' | jq -c '.[] | {type, status, reason, message}'
# {"type": "Accepted", "status": "False", "reason": "CompilationFailed",
#  "message": "generation 2 does not compile: 2 blocking problems (UnresolvedKeyReference, UnresolvedReplacedRules)"}
# {"type": "Ready", "status": "False", "reason": "NotCompiled",
#  "message": "generation 2 does not compile; generation 1 remains enforced"}
# {"type": "Stalled", "status": "True", "reason": "NotCompiled"}
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.ruleProblems}' | jq
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq '.domains["gateway.public"].generation'
# 1      -> the ConfigMap never carries a generation that does not compile
```

```json
[{"block": "api", "rule": "enterprise-per-client", "reason": "UnresolvedKeyReference",
  "message": "key \"plann\" is not in the effective set of the domain"},
 {"block": "api", "rule": "enterprise-per-client", "reason": "UnresolvedReplacedRules",
  "message": "replacedRules names \"per-clint\", which is not another rule of this block"}]
```

`block` and `rule` are the address; a problem with an empty address is about the policy as a whole, such as
`DomainBudgetExceeded`. Every reason except `CaptureShadowsMappedKey` is blocking:

| Reason | What it means |
| --- | --- |
| `UnresolvedKeyReference` | a `matches` key or a counter axis that no mapping and no capture of the domain produces |
| `UnresolvedGroupReference` | `InGroup` names a group the object does not declare |
| `UnresolvedReplacedRules` | `replacedRules` names a rule outside its own block |
| `IncompatibleOperator`, `InvalidCounterAxis` | the key's type does not suit the operator or the axis |
| `InvalidSpec` | a structural defect the schema cannot see: predicate arity, `Bypass` without `replacedRules` in an `All` block, a repeated placeholder, a template segment that is neither a literal nor a single placeholder (a brace outside a placeholder, or an empty segment from a slash at the end or two in a row), an unknown field or enum value (section 5) |
| `InvalidWindow` | a window the algorithm cannot enforce |
| `DomainBudgetExceeded` | the worst case of one decision exceeds 128 buckets |
| `CaptureShadowsMappedKey` | informational: inside the block the capture wins over the mapped key of the same name |

**What traffic sees meanwhile.** `activeGeneration` is enforced, and the management API keeps reporting its rule set:
`GET /domains` showed `ruleSetVersion 5ff0f5a9e94d` with 12 rules throughout, and the manifest kept generation 1. If
`activeGeneration` is `0`, the domain has no last-good and enforces nothing; the `Ready` message says
`no generation is enforced: domain is unprotected`. That is the one case to treat as an incident rather than a review
comment.

**Act.** Fix the spec at the address and apply it. The compiler judges the whole generation, so fix every listed problem
in one edit; a second `apply` that fixes one of two does nothing for traffic.

**Verify.** `Accepted: True` with reason `RulesCompiled`, `Ready` back to `True` within the probe interval (10 s on the
stand, after the kubelet's projection), and the three numbers agree:

```bash
kubectl get rlp -n "$NS" "$DOMAIN" \
  -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.activeGeneration}{"\n"}'
# 3 3 3
```

## 4. `Stalled: True` with `ReplicaStale`

The operator reads `/debug/applied` from every ready service replica once per probe cycle, 10 s, in one round shared by
every domain of the namespace. It finds the replicas by pod IP in the EndpointSlice of the Service `ratelimit` and takes
the port number from the slice by the port name `metrics`. A replica that reports another generation for longer than
90 s, or does not respond at all, turns `Ready` to `ReplicaStale` and `Stalled` to `True`, and the message names it. The
threshold sits above the kubelet sync period, one minute by default, so an update the kubelet has not projected yet
reports as `Propagating`, not as a stall.

**Signal.** On the stand, three service replicas, two of them behind a `DENY` on the metrics port, and the operator pod
replaced so that it connects afresh:

```bash
kubectl get rlp -n "$NS"
# NAME              READY   REPLICAS   RULES   PROBLEMS   AGE
# gateway.private   False   1/3        1                  84m
# gateway.public    False   1/3        12                 84m
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}{"\n"}'
# 1 of 3 replicas enforce generation 5; ratelimit-service-686d7856bf-2p2kg, ratelimit-service-686d7856bf-bpqwd did not answer
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.replicas}' | jq -c
# {"applied": 1, "lastCheckTime": "2026-09-21T13:36:21Z", "summary": "1/3", "total": 3}
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.conditions}' | jq -c '.[] | {type, status, reason}'
# {"type": "Accepted", "status": "True", "reason": "RulesCompiled"}
# {"type": "Ready", "status": "False", "reason": "ReplicaStale"}
# {"type": "Stalled", "status": "True", "reason": "ReplicaStale"}
```

A pod that answers with another generation is named the same way, with `report another` in place of `did not answer`.
The first missed probe already shows in the message under reason `Propagating`; the reason turns to `ReplicaStale`, and
`Stalled` to `True`, once the miss has lasted 90 s. On the stand the replacement operator pod named the two pods under
`Propagating` 28 s after the old pod was deleted, most of it the pod's start and the first probe, and `ReplicaStale`
followed 90 s later. Every domain of the namespace stalls together: the probe is one round for all of them.

The operator pod's scrape carries the stall; the service pods carry no status series, only their own
`ratelimit_policy_applied_generation`:

```text
ratelimit_leader 1
ratelimit_policy_stalled{domain="gateway.private",reason="ReplicaStale"} 1
ratelimit_policy_stalled{domain="gateway.public",reason="ReplicaStale"} 1
ratelimit_policy_replicas{domain="gateway.public",state="applied"} 1
ratelimit_policy_replicas{domain="gateway.public",state="total"} 3
```

The alert is the operator chart's `RatelimitStalled`, `ratelimit_policy_stalled == 1` held for `alerts.stalledFor`
([Helm doc](helm-chart.md)); the
generation each service pod enforces stays readable per pod:

```promql
ratelimit_policy_applied_generation{domain="gateway.public"}    # one series per service pod
```

**Diagnose, "report another".** The pod enforces a generation other than the one the manifest carries. Three causes. The
kubelet has not projected the ConfigMap update into the pod yet: that resolves within the sync period and stays
`Propagating` below the threshold. The replica's watch of the mounted directory stopped delivering. Or the validated
spec of that one domain does not compile in the replica's build, a version skew inside the compiler rather than the
format: the replica keeps the last-good engine of the domain and reports the generation it came from, the other domains
of the namespace move on, and the log names the domain in the line `keeping the last-good engine`. A domain the replica
has never applied has nothing to keep; it enforces nothing, at generation 0. A replica that refuses the manifest is the
separate reason `ReplicaFormatUnsupported`, below.

```bash
kubectl get pods -n "$NS" -l app.kubernetes.io/name=ratelimit-service \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image,READY:.status.containerStatuses[0].ready'
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq
kubectl port-forward -n "$NS" pod/<the pod the message names> 8080:8080 &
curl -s http://127.0.0.1:8080/debug/applied | jq
kubectl logs -n "$NS" <the pod the message names> --since=15m | grep -E 'configuration|compile|refused' | tail -20
```

The manifest holds the generation the operator wrote; `/debug/applied` holds the one the replica applied. A gap that
outlasts the sync period, with no `configuration applied` line in the log, is a watch that stopped. A gap on one domain,
with the apply in the log and the `does not compile` line beside it, is the compiler skew. Image version skew during a
rollout of the service shows as a refusal, `ReplicaFormatUnsupported`, as one domain held at its last-good generation,
or not at all: every image reads the same manifest.

**Diagnose, "did not answer".** The operator could not reach the pod's metrics port. The pod is ready, otherwise it
would not be in the denominator, so look at what stands between the operator pod and port 8080 of the service pod: a
NetworkPolicy or an AuthorizationPolicy that admits only Prometheus to the metrics port, or a pod that is ready but not
answering HTTP.

```bash
kubectl get networkpolicies,authorizationpolicies -n "$NS"
# NAME                                                                 ACTION   AGE
# authorizationpolicy.security.istio.io/ratelimit-service-management   DENY     2d23h
# authorizationpolicy.security.istio.io/runbook-block-metrics          DENY     2m
kubectl port-forward -n "$NS" pod/<the pod the message names> 8080:8080 &
curl -s --max-time 5 http://127.0.0.1:8080/debug/applied   # answers here but not to the operator: the path is blocked
```

The port-forward answered on the stand while the operator could not get through: it rides the API server and the
kubelet, not the mesh, so it says nothing about the path from the operator pod. Two facts about a policy on the metrics
port in ambient mode. A fresh connection to the blocked pod is reset at once (`curl: (56) Recv failure: Connection reset
by peer`). The operator's probe, however, reuses its keep-alive connection, and ztunnel enforces a new `DENY` on new
connections only: a policy applied under a running operator changes nothing in the status until the operator connects
afresh, and it bit on the stand the moment the operator pod was replaced. So a blocked port shows up after a restart of
the operator pod or of the service pods, not at the moment the policy is applied. Every probe of the operator crosses
pods, so a `DENY` on the metrics port blocks every replica alike; the operator never probes itself.

When no replica answers, the condition is `Ready: Unknown` with reason `ProbeFailed` instead: the operator reports that
it cannot read the fleet rather than a count it does not have.

**Diagnose, `ReplicaFormatUnsupported`.** A replica refuses the manifest: its `formatVersion` is one the replica does
not read, a field the replica's strict decoder does not define, or a payload of a domain that does not decompress or
decompresses past 8 MiB. The replica keeps its snapshot, stays Ready, and reports the refusal with its reason on
`/debug/applied`. The usual cause is version skew between the two Deployments; a payload that fails is a corrupt or
hand-edited ConfigMap value. The service reads the format versions N and N-1 and the operator writes N. An operator
whose format is newer than the service's, or older by two or more versions, is refused; the usual case is an operator
upgraded before the service. On the stand the manifest was rewritten by hand with `formatVersion: 101` while the
operator was scaled to zero:

```bash
kubectl get deploy -n "$NS" ratelimit-operator ratelimit-service \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image'
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq '{formatVersion, operatorVersion}'
curl -s http://127.0.0.1:8080/debug/applied | jq -c '{gen: .domains["gateway.public"].generation, formatVersions, refusal}'
# {"gen": 5, "formatVersions": [1],
#  "refusal": {"formatVersion": 101, "reason": "manifest: unsupported format version: 101 (this reader accepts [1])"}}
```

Every replica reported the refusal, stayed Ready, and kept serving generation 5: three requests through the gateway
answered `200`. The status noticed nothing yet, and that is right: a replica that refuses a manifest and still enforces
the latest generation is whole. The operator turns the refusal into a condition only for a replica that is behind. On
the stand the policy moved a generation while the operator was off, and the operator back compiled it, wrote the object
in its own format, and judged the replicas from their reports: `Ready: False` with reason `ReplicaFormatUnsupported` and
`Stalled: True` 21 s after the operator's start, at once and without a deadline, with the message:

```text
0 of 3 ready replicas enforce generation 6; ratelimit-service-686d7856bf-2p2kg, ratelimit-service-686d7856bf-bpqwd,
ratelimit-service-686d7856bf-jbccp refused the manifest's format and keep an earlier snapshot: upgrade the service
before the operator
```

Then the kubelet projected the rewritten object, the replicas applied generation 6, the refusals cleared, and
`Ready: True` with `AllReplicas` followed 9 s later. In a real skew the rewrite is in the same unreadable format, so the
condition stays until the versions match.

**Act.** A watch that stopped: delete the pod; the replacement mounts the ConfigMap, applies the current manifest, and
joins the denominator once Ready. A blocked metrics port: admit the operator's ServiceAccount to the metrics port of the
service pods; the probe is same-namespace traffic from the operator pod. On the stand, deleting the blocking policy
brought `Ready: True` back within 6 s, and the stalled series went back to `reason="Progressing"` at `0`.
`ReplicaFormatUnsupported`, and a domain held at its last-good generation because its spec does not compile in the
replica's build: upgrade the service to the operator's version, or roll the operator back to the service's; section 5
has the order. The replicas apply the next manifest they read, and the condition clears on the next probe.

**Verify.** `Ready: True` with reason `AllReplicas` and `replicas.applied == replicas.total`.

## 5. Schema version skew after a partial upgrade of a composite

Two versions can skew after a partial upgrade. The CRD is one per cluster, the operator is one per namespace, and
applications upgrade on their own releases, so a namespace can run an operator older than the schema an object was
written for. The operator does not enforce such an object partially: it decodes the spec strictly, reports every field
it does not define as an `InvalidSpec` problem with the field path, and keeps last-good. The second skew is between the
two Deployments of one namespace: the manifest in `ratelimit-config` carries an integer `formatVersion`, the operator
writes the current version N, and the service reads N and N-1. Any change of what the operator writes, a field added to
the spec included, increments the version. On the stand the CRD was patched to define a field `spec.futureField` the
image does not know, and the field was added to the reference policy.

**Signal.** `Accepted: False`, `Stalled: True` with `NotCompiled`, a problem that names a field rather than a rule, and
the same `Warning` event as in section 3:

```bash
kubectl get rlp -n "$NS"
# NAME              READY   REPLICAS   RULES   PROBLEMS   AGE
# gateway.public    False   1/1        12      1          92m
kubectl get rlp -n "$NS" "$DOMAIN" \
  -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.activeGeneration}{"\n"}'
# 10 10 9
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.conditions}' | jq -c '.[] | {type, status, reason, message}'
# {"type": "Accepted", "status": "False", "reason": "CompilationFailed",
#  "message": "generation 10 does not compile: 1 field this schema does not define (InvalidSpec)"}
# {"type": "Ready", "status": "False", "reason": "NotCompiled",
#  "message": "generation 10 does not compile; generation 9 remains enforced"}
# {"type": "Stalled", "status": "True", "reason": "NotCompiled"}
kubectl get rlp -n "$NS" "$DOMAIN" -o jsonpath='{.status.ruleProblems}' | jq -c
# [{"message": "unknown field \"spec.futureField\"", "reason": "InvalidSpec"}]
```

An unknown enum value takes the same path with a message from the compiler, such as `unknown path type "GlobMatch"`.
A field this build does not define under `status` or `metadata` reports nothing: on the stand a `status.futureField`
patched through the status subresource came back as `patched (no change)`, dropped by the API server, and the conditions
did not move. The status is the operator's own and changes with every release, so a strict read of it would refuse new
generations for the length of every operator rollout.

The manifest skew has its own signal: `Ready: False` with reason `ReplicaFormatUnsupported` and `Stalled: True`, with
`Accepted: True` on the policy and every replica Ready on its previous snapshot. Section 4 has the readout of the
refusal on `/debug/applied`.

**Diagnose.** Compare the versions: the two images, the schema the object uses, the manifest's format version, and the
versions a replica reads:

```bash
kubectl get deploy -n "$NS" ratelimit-operator ratelimit-service \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image'
# NAME                 IMAGE
# ratelimit-operator   ratelimit-operator:20b5501
# ratelimit-service    ratelimit-service:20b5501
kubectl get crd ratelimitpolicies.ratelimit.netcracker.com -o jsonpath='{.spec.versions[*].name}{"\n"}'
# v1
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq -c '{formatVersion, operatorVersion}'
# {"formatVersion": 1, "operatorVersion": "20b5501"}
curl -s http://127.0.0.1:8080/debug/applied | jq      # through the port-forward of section 4
```

The field in the message is the one this build does not define. Old objects under a newer schema need nothing:
additive fields take their defaults. The case that bites is the other direction, a new field in an object served by an
old operator. Between the two Deployments the same direction bites: a manifest written in a format the service does not
read yet.

**What traffic sees meanwhile.** Last-good, as in section 3: `/debug/applied` stayed at generation 9 and the domain
listing kept its 12 rules and its rule set version throughout. A policy whose only generation carries the field has
no last-good and enforces nothing: on the stand such a policy reported `no generation is enforced: domain is
unprotected` and listed zero rules. Under `ReplicaFormatUnsupported` traffic sees the previous snapshot: a replica that
refuses a manifest stays Ready on the last configuration it applied. A replica that starts after the refusal has no
snapshot to keep, so it stays NotReady and out of Endpoints until a manifest it reads arrives.

**Act.** The CRD skew: either upgrade the operator in that namespace to the version the schema belongs to, or take the
new field out of the object until the upgrade. Do not downgrade the CRD: schema changes are additive, and an older CRD
would refuse every object that already uses the field. The manifest skew: bring the two Deployments to one version, in
the order the format versions allow. An upgrade installs the service first, then the operator. The new service reads N
and N-1, so it reads what the old operator writes and the new operator's N once it arrives. A rollback reverses the
order, the operator first, then the service: the old operator's N-1 is read by both service versions. A service rolled
back first refuses the new operator's N and starts its fresh pods NotReady. A fresh installation needs no order: the
service waits NotReady until the operator writes.

A rollback of the operator across a format increment starts it without last-good: the older operator does not read
the newer manifest, writes the namespace again from the live objects, and a domain whose latest generation does not
compile is left at `activeGeneration: 0`, unprotected, until its object is fixed. Fix or remove the objects that do
not compile before rolling the operator back; section 3 shows how to find them.

**Verify.** As in section 3. On the stand, the field removed again: `11 11 11`, `Ready: True` 10 s later. For the
manifest skew, `/debug/applied` lists the manifest's `formatVersion` among the versions the replica reads and no
refusal, and `Ready: True` with reason `AllReplicas` follows on the next probe.

## 6. Introducing a new limit safely, and changing a live rule

The staged procedure for a whole policy, with the observation checklist, the quota validation, and the rollback
paths, is the [rollout procedure](rollout-procedure.md); this section is the short form.

**A new limit.** Add the rule with `behavior: Shadow`. It is evaluated and counted, its would-be refusals are visible,
and it never refuses:

```yaml
rules:
  - name: exports-per-client-trial
    behavior: Shadow
    counters: [client]
    rates: [{requests: 5, periodSeconds: 3600}]
```

Watch it for as long as the traffic pattern takes to repeat, a day for a daily quota:

```promql
sum by (rule) (rate(ratelimit_decisions_total{domain="gateway.public", outcome="shadow_over_limit"}[1h]))
sum by (rule) (rate(ratelimit_near_limit_total{domain="gateway.public"}[1h]))
```

```text
ratelimit_decisions_total{domain="gateway.public",outcome="shadow_over_limit",rule="api/exports-per-client-trial"} 3
```

```bash
api "$BASE/domains/$DOMAIN/counters?limited=true&ruleId=api/exports-per-client-trial" \
  | jq -c '[.items[] | {axes, mode, remaining}]'
# [{"axes": {"client": "bob"}, "mode": "shadow", "remaining": 0}]
```

`mode: shadow` with `limited: true` is a client that would have been refused; on the stand, eight requests against a
shadow limit of five all answered `200` and left three `shadow_over_limit` decisions. When the numbers match the
intent, switch `behavior` to `Enforce`; the counters carry over, the keys do not depend on the behavior.

**The emergency brakes on the gateway.** Two values of the operator chart on the filter, independent of any policy:
`runtime.enforcedPercent` at `0` turns every limit of the gateway into a dry run, `runtime.enabledPercent` at `0` takes
the filter out of the request path. They are Envoy runtime fractions `ratelimit.<gateway>.enabled` and `.enforced`, so
a runtime override flips them without a redeploy; a values change on the operator release is the durable form.

**Switching an algorithm or a window.** The counter key carries the algorithm and the period:

```text
rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:gcra:60:alice:
rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:fixedwindow:86400:alice:
```

A rule that changes either starts on fresh buckets, so the first window after the change admits a full budget, and the
old buckets expire on their own TTL. On the stand, `periodSeconds: 60` changed to `120` on `api/per-client`, three
requests later:

```bash
api "$BASE/domains/$DOMAIN/counters?ruleId=api/per-client&axis.client=alice" \
  | jq -c '{scanned, items: [.items[] | {key, periodSeconds, limit, remaining}]}'
# {"scanned": 3, "items": [
#   {"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:fixedwindow:86400:alice:", ...},
#   {"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:gcra:120:alice:",
#    "periodSeconds": 120, "limit": 100, "remaining": 17}]}
```

Three keys scanned, two listed: the `gcra:60` key is still in the store but belongs to no window of the rule any more,
and 75 s later the listing scanned two, its TTL had run out. No reset is needed and none would help. Renaming a block
or a rule has the same effect, because the ids are in the key too.

## 7. Counter reset

Both forms need an `Idempotency-Key` and the `operator` role. The addressed form deletes the keys it can compute from
the snapshot, one full `block/rule` id and one value for every axis of the rule; the bulk form sweeps a selection and
needs a preview's confirmation token to execute.

```bash
alias opk='op -H "Idempotency-Key: $(uuidgen)"'
```

**One client of one rule.**

```bash
opk -X DELETE "$BASE/domains/$DOMAIN/counters?ruleId=api/per-client&axis.client=alice&dryRun=true"
# {"domain": "gateway.public", "ruleId": "api/per-client", "ruleSetVersion": "5ff0f5a9e94d",
#  "axes": {"client": "alice"}, "dryRun": true, "matchedCount": 1,
#  "keys": ["rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:fixedwindow:86400:alice:",
#           "rl:v1:{ratelimit-e2e/gateway.public}:api/per-client:gcra:60:alice:"]}
opk -X DELETE "$BASE/domains/$DOMAIN/counters?ruleId=api/per-client&axis.client=alice"
# the same body with "dryRun": false, "resetCount": 2
```

`keys` is the complete list of the rule's windows for that identity; `matchedCount` and `resetCount` say how many of
them existed. One window only, `&period=24h`; only if refusing right now, `&limited=true`; pinned to the rule set you
looked at, `&expectedRuleSetVersion=<from GET /rules>`, which answers `409` if a rollout swapped the snapshot in
between. Refusals do not widen the command silently:

```bash
opk -X DELETE "...counters?ruleId=api/per-client&axis.client=alice&dryrun=true"
# {"code": "RLS-0400", "message": "the query carries parameters this endpoint does not define: dryrun",
#  "meta": {"fields": ["dryrun"]}}
opk -X DELETE "...counters?ruleId=api/per-client&axis.client=alice&period=7h"
# {"code": "RLS-0404", "message": "rule api/per-client has no window matching the algorithm and period given"}
```

**A selection.**

```bash
KEY=$(uuidgen)
PREVIEW=$(op -X POST "$BASE/domains/$DOMAIN/counter-resets" -H "Idempotency-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"selector": {"ruleIds": ["api"]}, "dryRun": true}')
echo "$PREVIEW" | jq -c '{matchedCount, scanned, rules, confirmationToken, confirmationExpiresAt}'
# {"matchedCount": 8, "scanned": 8,
#  "rules": [{"ruleId": "api/exports-per-client-trial", "matchedCount": 1}, {"ruleId": "api/per-client", "matchedCount": 4},
#            {"ruleId": "api/per-path", "matchedCount": 2}, {"ruleId": "api/total", "matchedCount": 1}],
#  "confirmationToken": "ct-4ca707d3c61f", "confirmationExpiresAt": "2026-09-21T13:42:52Z"}
CT=$(echo "$PREVIEW" | jq -r .confirmationToken)
op -X POST "$BASE/domains/$DOMAIN/counter-resets" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' -d '{"selector": {"ruleIds": ["api"]}, "confirmationToken": "'"$CT"'"}'
# {"dryRun": false, "resetCount": 8, "scanned": 8,
#  "rules": [{"ruleId": "api/exports-per-client-trial", "resetCount": 1}, {"ruleId": "api/per-client", "resetCount": 4},
#            {"ruleId": "api/per-path", "resetCount": 2}, {"ruleId": "api/total", "resetCount": 1}]}
```

The token is single-use, bound to the domain, the subject, and the normalized selector, and lives about ten minutes.
A second execution with the same token answers
`RLS-0410 the confirmation token expired or was already used; run a new preview`; a changed selection answers
`RLS-0409`. A whole domain takes `confirmDomain` with the domain's name repeated in the body, and the same two steps.
A domain runs one sweep at a time: a second operator's call gets `409` with `conflictType: sweep_in_flight`; a retry
of your own running command gets `202` with `Retry-After`, and the retry is the poll.

**What a replay answers.** The same `Idempotency-Key` with the same command replays the recorded outcome, the body the
first call returned, even after the rule set moved on. The same key with a different command answers
`RLS-0409 this Idempotency-Key is already bound to a different command; a new command needs a new key`. A preview is
recorded too, so a lost preview repeated returns the same token rather than minting a second one. Records are kept
for at least 24 hours; do not retry across days.

**Who reset what.** Every mutation writes one structured log line on the replica that served it; the addressed form
logs the outcome, the bulk form logs the acceptance with the hash of the selection:

```bash
kubectl logs -n "$NS" deploy/ratelimit-service --since=24h | grep 'management mutation'
# management mutation subject=operator@example.com idempotencyKey=CE81F29B-... domain=gateway.public
#   endpoint=counters ruleId=api/per-client axes=map[client:alice] dryRun=false outcome=reset count=1
# management mutation subject=operator@example.com idempotencyKey=69DA3B84-... domain=gateway.public
#   endpoint=counters ruleId=api/per-client axes=map[client:alice] dryRun=true outcome=previewed count=1
# management mutation accepted subject=operator@example.com idempotencyKey=08439BE2-... domain=gateway.public
#   endpoint=counter-resets command=execute-selector selection=72a94e83cf44e26d dryRun=false
```

The service writes nothing to the API server, so there is no Kubernetes Event per mutation: the log line is the
journal.

## 8. Reading the Argo CD health of a policy

Argo CD does not assess the health of a custom resource by default; the platform's Lua check in `argocd-cm` reads the
two conditions. There are two applications per namespace, one per chart, and the policy health is on the operator's:
the operator writes the status the check reads. The service application shows the health of its own Deployment only; a
replica turns Ready when it applies a manifest, so that application waits on the operator's first write (section 0). The
stand runs no Argo CD, so this table is the mapping the check implements, not an execution:

| `Stalled` | `Ready` | Argo CD health | Meaning |
| --- | --- | --- | --- |
| `True` | any | Degraded | a breakage: `ReplicaStale` or `ReplicaFormatUnsupported` (section 4), `NotCompiled` (sections 3 and 5), or `ConfigMapTooLarge` (section 0) |
| `False` | `True` | Healthy | every ready service replica enforces the latest generation |
| `False` | `False` | Progressing | a rollout in flight, `NoReplicas`, or the operator still catching up |
| `False` | `Unknown` | Progressing | `ProbeFailed`: the operator cannot read the replicas (section 4) |

A sync wave that waits on the policy closes only when every service replica enforces the rule; a Helm release closes on
the Deployments, before a later generation reaches the replicas. A wave that stays Progressing longer than the rollout
and the kubelet sync period take is `NoReplicas` or `ProbeFailed`. A wave that turns Degraded on `NotCompiled` or
`ConfigMapTooLarge` is a review comment for the author of the policy, not a rollback of the release. A wave that turns
Degraded on `ReplicaFormatUnsupported` is the version skew of section 5, a matter of the two releases.

## 9. The ConfigMap channel

Everything the service knows travels through `ratelimit-config`, so the three things that can happen to the object have
a scenario each. All three ran on the stand.

**A deleted object.** The operator owns it and watches it, and recreates it whole on the next reconcile; the replicas
keep the snapshot they applied and never notice.

```bash
kubectl delete cm -n "$NS" ratelimit-config
# recreated 139 ms later under a new uid, with every domain at its active generation
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.data.manifest}' | jq -c '.domains | map_values(.generation)'
# {"gateway.private": 5, "gateway.public": 11}
kubectl logs -n "$NS" deploy/ratelimit-operator --since=1m | grep 'configuration written'
# configuration written domains=2 created=true
```

`Ready` stayed `True` on both policies and three requests through the gateway answered `200`. One caveat, seen on the
stand: the object is also the last-good state, and a domain whose latest generation does not compile has its good spec
nowhere else. Delete the object while such a domain is on last-good and the recreated object has no entry for it: the
domain reads `RULES` empty, `REPLICAS 0/1`, `activeGeneration: 0`, unprotected, until its object compiles again. Fix
the objects of section 3 before touching the ConfigMap.

**A write the operator cannot make.** The Role, the API server, or the size fit refuses the write. The replicas keep
the configuration they mounted, the status keeps reporting the previous generation as enforced, and the counter names
the reason. On the stand the operator's Role lost `update` on the object and a policy was edited:

```bash
kubectl logs -n "$NS" deploy/ratelimit-operator --since=2m | grep 'failed to write the configuration'
# failed to write the configuration controller=ratelimit-config ... update ratelimit-config: ... is forbidden ...
kubectl get cm -n "$NS" ratelimit-config -o jsonpath='{.metadata.resourceVersion}'   # unchanged
kubectl get rlp -n "$NS" gateway.private \
  -o jsonpath='{.metadata.generation} {.status.observedGeneration} {.status.activeGeneration}{"\n"}'
# 6 6 6      -> the operator compiled and accepted generation 6; the replicas still hold the previous one
```

```text
ratelimit_config_write_errors_total{reason="api"} 13
```

Thirteen failures in the 30 s after the edit, the workqueue's retries; `Ready` read `False` with `Reconciling` and would
have turned `ReplicaStale` 90 s later, since the replicas report the old generation. Traffic ran on the previous
configuration throughout. The alert is `RatelimitConfigWriteErrors` in the [Helm doc](helm-chart.md); the reason is
`size` for a state the object cannot hold even after the fit, `api` for an answer of the API server, `other` for the
rest. The action is on the cause: the Role of the operator chart, the API server, the size of the namespace's policies.
After the fix the retry follows the workqueue's exponential backoff: on the stand the write landed within 20 s of the
verb's return, but after a longer outage the backoff runs to minutes. A change of any policy generation, or a restart of
the operator pod, writes at once; on the stand a generation change reached `Ready: True` 11 s later.

**A replica born without the object.** With no operator running and no ConfigMap, a fresh service pod mounts an empty
directory and stays NotReady, without a timeout, and out of the Endpoints; the replicas that had applied a manifest keep
serving.

```bash
kubectl get pods -n "$NS" -l app.kubernetes.io/name=ratelimit-service \
  -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[0].ready'
# NAME                                 READY
# ratelimit-service-566dcc4db8-plxjx   true
# ratelimit-service-6b7bb4858f-vkpqv   false
kubectl logs -n "$NS" ratelimit-service-6b7bb4858f-vkpqv | grep NotReady
# no configuration in the mounted directory yet, the replica stays NotReady dir=/etc/ratelimit/config
kubectl get endpointslice -n "$NS" -l kubernetes.io/service-name=ratelimit \
  -o jsonpath='{.items[0].endpoints[*].conditions.ready}{"\n"}'
# true false
```

A rollout of the service under those conditions stalls on the replacement pod, and traffic stays on the old one. The
operator back, it writes the object, the kubelet projects it into the empty volume on its next sync, and the replica
turns Ready: 33 s on the stand with the kubelet at 5 s, a minute or so at the production default. Nothing else is
needed; the empty volume is `optional: true` by design so that the pod exists before the operator does.

## Appendix: the metrics an operator reads

Each chart ships its own PodMonitor. The RLS, store, and management metrics are scraped from the service pods; the
controller and probe metrics from the operator pod.

| Metric | On | Read it for |
| --- | --- | --- |
| `ratelimit_checks_total{domain, verdict}` | service pods | `unavailable` is the fail-open window (section 1) |
| `ratelimit_decisions_total{domain, rule, outcome}` | service pods | `shadow_over_limit` while introducing a limit (section 6) |
| `ratelimit_near_limit_total{domain, rule}` | service pods | clients close to a limit before it fires; the margin is a share of the window's capacity, `burst` for GCRA |
| `ratelimit_unknown_domain_checks_total` | service pods | a domain typo between the gateway and the policy (section 2) |
| `ratelimit_extractions_total{domain, key}`, `ratelimit_tokens_seen_total{domain}` | service pods | the extraction detector (section 2) |
| `ratelimit_store_errors_total{domain, reason}`, `ratelimit_store_roundtrip_seconds{domain}` | service pods | the store (section 1) |
| `ratelimit_policy_ready{domain, reason}`, `ratelimit_policy_generation_lag{domain}` | operator pod | the status as gauges |
| `ratelimit_policy_stalled{domain, reason}` | operator pod | `1` is a breakage: `ReplicaStale` or `ReplicaFormatUnsupported` (section 4), `NotCompiled` (sections 3 and 5), or `ConfigMapTooLarge`; `Progressing` at `0` |
| `ratelimit_policy_replicas{domain, state}` | operator pod | `applied` against `total`: the numbers behind `REPLICAS` (section 4) |
| `ratelimit_leader` | operator pod | which operator pod holds the Lease during a rollout overlap; the policy gauges exist only on the pod reporting `1` |
| `ratelimit_policy_rule_problems{domain, severity}` | operator pod | `blocking` above zero is a rejected edit (sections 3 and 5) |
| `ratelimit_policy_applied_generation{domain}` | service pods | per pod: the generation each replica enforces (section 4) |
| `ratelimit_domain_decision_buckets{domain}` | service pods | headroom before `DomainBudgetExceeded`, against 128 |
| `ratelimit_config_write_errors_total{reason}` | operator pod | the write of `ratelimit-config` failed (`size`, `api`, `other`; section 9); the replicas keep the configuration they mounted and `ReplicaStale` follows in 90 s |
