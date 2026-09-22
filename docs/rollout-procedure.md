# Rollout procedure: from shadow mode to enforcement

How to turn limits on against live traffic without refusing legitimate clients and without enforcing nothing by
mistake. The procedure has three stages, shadow, validation, and staged enablement, and a rollback path for every
step. It is written against the one-object architecture of the [topology](deployment-topology.md), an operator and a
service per namespace: one `RateLimitPolicy` per domain, the [resource specification](ratelimitpolicy-cr-spec.md) for
the fields, the [management API](management-api.md) for the readouts, the [charts](helm-chart.md) for the metric names
and for the gateway values, which belong to the operator chart. Diagnosis of a component that misbehaves is the
[runbook](runbook.md); this document is about a policy that behaves and has to be introduced.

Every command and every output below was run on a kind stand against
[`ratelimitpolicy-example.yaml`](ratelimitpolicy-example.yaml), the same object the runbook uses. Clients are the
stand's (`bob`, `carol`, `dave`), and the traffic was sent by hand; on the platform the traffic is the clients' own,
and the observations are the same.

## 0. The two dials

A limit is turned on and off in two places, and they do different things:

| Setting | Where | The service counts | The client sees | The metrics say |
| --- | --- | --- | --- | --- |
| `behavior: Shadow` on a rule | the policy | yes, per the rule's own verdict | `200`, no headers from this rule | `ratelimit_decisions_total{outcome="shadow_over_limit"}`; no near-limit |
| `behavior: Enforce` on a rule | the policy | yes | `429` with `x-ratelimit-*` and `retry-after` | `outcome="over_limit"`, `ratelimit_near_limit_total` |
| `runtime.enforcedPercent: 0` | the gateway filter, a value of the operator chart | yes: the service judges and charges | `200` | `ratelimit_checks_total{verdict="over_limit"}` keeps growing |
| `runtime.enabledPercent: 0` | the gateway filter, a value of the operator chart | no: the filter never calls | `200` | nothing moves; the service sees no traffic |

`behavior` is per rule, durable, and travels with the policy through Git and Argo CD. The two fractions are values of
the operator chart, `runtime.enabledPercent` and `runtime.enforcedPercent`; they are per gateway, cover every domain
behind it, and exist as brakes: section 4 shows both forms of pulling them. The whole procedure is edits of `behavior`
on one rule at a time, with the brakes untouched unless something goes wrong.

The commands assume the setup of the runbook: `NS`, `DOMAIN`, `BASE`, a `viewer` token behind `api` and an `operator`
token behind `op`. Traffic on the stand went through a port-forward to the public gateway pod with a token of the
client named; a request is the plain

```bash
curl -s -o /dev/null -w '%{http_code} ' -H "Authorization: Bearer $TOKEN_BOB" "$GW/api/v1/exports/1"
```

## 1. Stage one: everything in shadow

A new rule starts with `behavior: Shadow`; a new domain starts with every rule in shadow. The rule is evaluated,
charged, and reported, and it refuses nobody. What to look at, and where each observation lives:

| Observation | Where | What good looks like |
| --- | --- | --- |
| the domain is wired to the gateway | `ratelimit_unknown_domain_checks_total`, `ratelimit_checks_total{domain}` | the first stays at zero, the second grows at the gateway's request rate |
| the blocks' routes match the traffic | `ratelimit_unmatched_checks_total{domain}` | the share of requests no block targets, and nothing else |
| every declared key arrives | `ratelimit_extractions_total{domain, key}` against `ratelimit_tokens_seen_total{domain}`, `ratelimit_extraction_skips_total` | every key above zero while tokens are seen; skips at zero |
| every rule matched at least once | `ratelimit_decisions_total{rule}` | one `ok` series per rule; a rule with no series never matched |
| who would be refused, and how often | `outcome="shadow_over_limit"` per rule, `GET /counters?limited=true` | the identities and the share the business accepts |
| the generation is the one enforced | `kubectl get rlp`, `Ready: True` | `REPLICAS` reads `n/n`, `PROBLEMS` blank |

The extraction series are seeded with zero when the snapshot is swapped, so a declared key that never arrives is a
visible zero, not a missing series. The extraction counters carry the domain and the declared key, and skips carry the
reason as well: two domains of one namespace that declare the same key keep separate series.

On the stand, the rule under trial is `api/exports-per-client-trial`: five requests per hour per client for holders of
`ROLE_Exporter`, in shadow in the example policy. Two exporters sent traffic, one of them past the limit:

```text
bob(ROLE_Exporter)   x8 GET /api/v1/exports/1: 200 200 200 200 200 200 200 200
carol(ROLE_Exporter) x3 GET /api/v1/exports/1: 200 200 200
```

```text
ratelimit_checks_total{domain="gateway.public",verdict="ok"} 15
ratelimit_decisions_total{domain="gateway.public",outcome="ok",rule="api/exports-per-client-trial"} 8
ratelimit_decisions_total{domain="gateway.public",outcome="shadow_over_limit",rule="api/exports-per-client-trial"} 3
ratelimit_extractions_total{domain="gateway.public",key="client"} 15
ratelimit_extractions_total{domain="gateway.public",key="plan"} 0
ratelimit_extractions_total{domain="gateway.public",key="roles"} 15
ratelimit_tokens_seen_total{domain="gateway.public"} 15
ratelimit_unknown_domain_checks_total 0
```

Every request answered `200`, and the rule reported what it would have done: eight admissions and three would-be
refusals. The `plan` line is the detector at work: the key is declared in the mapping, fifteen tokens were seen, none
carried the claim. On the stand that is deliberate; in production it is the condition the
`RatelimitKeyDeclaredNotExtracted` expression watches for ([chart](helm-chart.md)), and a rule keyed on `plan` never
matches until it is fixed.

Who is behind the three:

```bash
api "$BASE/domains/$DOMAIN/counters?ruleId=api/exports-per-client-trial" \
  | jq -c '[.items[] | {axes, mode, limit, remaining, limited, retryAfterSeconds}]'
# [{"axes": {"client": "bob"}, "mode": "shadow", "limit": 5, "remaining": 0, "limited": true, "retryAfterSeconds": 719.5},
#  {"axes": {"client": "carol"}, "mode": "shadow", "limit": 5, "remaining": 2, "limited": false, "retryAfterSeconds": null}]
api "$BASE/domains/$DOMAIN/counters?limited=true" | jq -c '[.items[] | {ruleId, axes, mode}]'
# [{"ruleId": "api/exports-per-client-trial", "axes": {"client": "bob"}, "mode": "shadow"}]
```

`limited: true` under `mode: shadow` is a client that would be refused right now; `retryAfterSeconds` is how long
the refusal would last. The replay of one request shows the shadow verdict next to the enforcing ones, and that it
does not decide:

```bash
api -X POST "$BASE/simulations" -H 'Content-Type: application/json' -d '{
  "domain": "'"$DOMAIN"'", "path": "/api/v1/exports/1", "method": "GET",
  "keys": {"client": ["bob"], "roles": ["ROLE_Exporter"]}
}' | jq -c '{allowed, headers: {limit: .headers.limit, remaining: .headers.remaining}, rules: [.rules[] | {id, mode, allowed, remaining}]}'
# {"allowed": true, "headers": {"limit": 100, "remaining": 12},
#  "rules": [{"id": "api/per-path", "mode": "enforce", "allowed": true, "remaining": 98},
#            {"id": "api/per-client", "mode": "enforce", "allowed": true, "remaining": 12},
#            {"id": "api/exports-per-client-trial", "mode": "shadow", "allowed": false, "remaining": 0},
#            {"id": "api/total", "mode": "enforce", "allowed": true, "remaining": 585}]}
```

The headers come from `api/per-client`, the strictest enforcing rule; the shadow rule's `allowed: false` is reported
and ignored.

**Near-limit is not a shadow signal.** `ratelimit_near_limit_total` counts admissions of enforcing rules that landed
within the margin of the window's capacity, `metrics.nearLimitRatio` of the chart, `0.9` by default: with a capacity
of 10 the last admission and the one before it. The capacity is what `remaining` counts down from: the burst of a GCRA
window, which defaults to its `requests`, and the `requests` of a `FixedWindow` one. For `api/per-path`, 1000 per
minute with a burst of 100, the margin is the last 10 of the burst, whatever the 1000 says. Shadow rules are excluded
on purpose; their readout is `shadow_over_limit`.

**How long.** At least twice the longest window of the rule, so that one full window is observed from a known start,
and at least one full cycle of the traffic pattern: a working day for clients that run on a schedule, a week when
weekdays and weekends differ, a month for a monthly quota. For the trial rule, an hourly window, that is a working day.
Never decide from a single scrape: a client at `remaining: 0` a minute after a burst is not a client over its hourly
budget.

**The decision point.** Enforce a rule when all of these hold over the whole observation:

1. `ratelimit_unknown_domain_checks_total` stayed at zero, and `ratelimit_checks_total{domain}` followed the gateway.
2. Every key the rule uses was extracted; `ratelimit_extraction_skips_total` stayed at zero.
3. The rule has decision series, so it matched, and its `shadow_over_limit` share is the one the business accepts.
4. `GET /counters?limited=true&ruleId=<rule>` lists only identities that are expected to be refused.
5. `Ready: True` on the latest generation, so the edit lands on a known base.

## 2. Stage two: quota validation

Two numbers per rule say whether the configured value fits the traffic:

- the would-be refusal share, `shadow_over_limit / (ok + shadow_over_limit)` over the observation window, from
  `ratelimit_decisions_total`;
- the consumption per identity, `limit - remaining` from the counter listing, read at the end of a window, and the
  list of identities with `limited=true`.

On the stand the share was three of eleven, all of them `bob`, whose real usage was eight requests in the hour against
a limit of five; `carol` used three. The limit was below a legitimate client's usage, so it was raised to ten while
still in shadow:

```diff
-      - { requests: 5, periodSeconds: 3600 }
+      - { requests: 10, periodSeconds: 3600 }
```

```bash
kubectl apply -f policy.yaml
# ready after 10s: generation 6 observed 6 active 6 Ready True/AllReplicas
api "$BASE/domains/$DOMAIN/counters?ruleId=api/exports-per-client-trial" \
  | jq -c '[.items[] | {key, axes, limit, remaining, limited, retryAfterSeconds}]'
# [{"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client-trial:gcra:3600:bob:",
#   "axes": {"client": "bob"}, "limit": 10, "remaining": 0, "limited": true, "retryAfterSeconds": 299.5},
#  {"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client-trial:gcra:3600:carol:",
#   "axes": {"client": "carol"}, "limit": 10, "remaining": 4, "limited": false, "retryAfterSeconds": null}]
```

**A changed limit keeps the bucket.** The counter key carries the algorithm and the period, not the limit, so the same
buckets continue under the new value. A bucket that was at its limit keeps its debt and pays it off at the new rate:
`bob` is still `limited`, with a shorter `retryAfterSeconds`, and three more requests from him were three more
`shadow_over_limit` decisions, six in total. A lowered limit works the same way in reverse: identities above the new
value are limited at their next request. When the intent is a fresh start under the new value, reset the rule's
buckets; the bulk form takes every identity of the rule in one command:

```bash
KEY=$(uuidgen)
PREVIEW=$(op -X POST "$BASE/domains/$DOMAIN/counter-resets" -H "Idempotency-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"selector": {"ruleIds": ["api/exports-per-client-trial"]}, "dryRun": true}')
echo "$PREVIEW" | jq -c '{matchedCount, rules: [.rules[] | {ruleId, matchedCount}], confirmationToken}'
# {"matchedCount": 2, "rules": [{"ruleId": "api/exports-per-client-trial", "matchedCount": 2}],
#  "confirmationToken": "ct-8463b9d49d57"}
CT=$(echo "$PREVIEW" | jq -r .confirmationToken)
op -X POST "$BASE/domains/$DOMAIN/counter-resets" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' \
  -d '{"selector": {"ruleIds": ["api/exports-per-client-trial"]}, "confirmationToken": "'"$CT"'"}' \
  | jq -c '{resetCount, rules: [.rules[] | {ruleId, resetCount}]}'
# {"resetCount": 2, "rules": [{"ruleId": "api/exports-per-client-trial", "resetCount": 2}]}
```

Three requests later `bob` had `remaining: 7` of ten. The preview, the confirmation token, and the `Idempotency-Key`
are the same mechanics as in the runbook's counter reset section.

## 3. Stage three: staged enablement

One rule per edit, `Ready: True` between edits, and a hold of at least one window of the rule before the next one. A
whole block in one edit is acceptable only for an `All` block whose rules are all of the first kind below; a block
that mixes kinds is enabled rule by rule. A `kubectl apply` or an Argo CD sync carries an edit the same way; with
Argo CD the sync wave closes on `Ready`, which is the same signal as `kubectl get rlp`.

**The order.** Rules differ in how much they change when they start refusing:

1. Unconditional ceilings with empty `counters`, such as `api/total` and `api/per-path`: they protect the backend,
   refuse no client in particular, and occupy one bucket per window.
2. Per-identity rules of `All` blocks, such as `api/per-client`: a refusal now names a client.
3. Overrides together with the rule they override: `api/enterprise-per-client` with its `replacedRules: [per-client]`,
   `api/internal-scraper` with its `Bypass`. Enforcing the wide rule before its override refuses exactly the clients
   the override exists to free.
4. `FirstMatch` cascades last, top-down, one rule at a time.

**Why cascades go last.** In a `FirstMatch` block a shadow rule counts and lets the cascade continue, so the next
matching rule decides. Enforcing it makes it decide and end the cascade: two things change in one edit, a new limit
starts refusing and the rule below it stops seeing that traffic. On the stand a trial rule was added at the top of the
`orders` cascade, three per minute per client for holders of `ROLE_Importer`, first in shadow:

```yaml
    mode: FirstMatch
    rules:
    - name: importers-trial
      matches:
      - { key: roles, operator: Contains, value: ROLE_Importer }
      counters: [client]
      behavior: Shadow
      rates:
      - { requests: 3, periodSeconds: 60 }
    - name: create-bulk-client
      ...
```

```bash
api -X POST "$BASE/simulations" -H 'Content-Type: application/json' -d '{
  "domain": "'"$DOMAIN"'", "path": "/api/v1/orders", "method": "POST",
  "keys": {"client": ["dave"], "roles": ["ROLE_Importer"]}
}' | jq -c '{allowed, rules: [.rules[] | select(.id | startswith("orders/")) | {id, mode, allowed, remaining}]}'
# {"allowed": true, "rules": [{"id": "orders/importers-trial", "mode": "shadow", "allowed": true, "remaining": 3},
#                             {"id": "orders/orders-per-client", "mode": "enforce", "allowed": true, "remaining": 50}]}
```

Both rules apply: the trial counts, `orders/orders-per-client` decides. Five requests from `dave` answered `200`, left
two `shadow_over_limit` decisions on the trial, and charged `orders/orders-per-client` five times:

```text
ratelimit_decisions_total{domain="gateway.public",outcome="ok",rule="orders/importers-trial"} 3
ratelimit_decisions_total{domain="gateway.public",outcome="shadow_over_limit",rule="orders/importers-trial"} 2
ratelimit_decisions_total{domain="gateway.public",outcome="ok",rule="orders/orders-per-client"} 5
```

After `behavior: Enforce` on the trial, the same replay applies one rule, and five more requests answered
`200 200 200 429 429`; the `orders/orders-per-client` series stayed at five, the traffic left it:

```text
# {"allowed": false, "rules": [{"id": "orders/importers-trial", "mode": "enforce", "allowed": false, "remaining": 0}]}
ratelimit_decisions_total{domain="gateway.public",outcome="ok",rule="orders/importers-trial"} 6
ratelimit_decisions_total{domain="gateway.public",outcome="over_limit",rule="orders/importers-trial"} 2
ratelimit_decisions_total{domain="gateway.public",outcome="ok",rule="orders/orders-per-client"} 5
```

So before enforcing a cascade rule, know which rule below it loses traffic, and check that its own limit and its
counters are ready for the change. Two readings answer it. The rule listing scoped by the request and the identity,
`GET /rules?path=/api/v1/orders&method=POST&axis.client=dave`, marks the rule that decides `always` and the ones it
preempts `never`; a capture such as `{orderId}` is decided from the route the request matches, so the same query for
`/api/v1/orders/42/items` names `orders/items-per-order` instead, and without a path the capture stays open and the
rule keyed on it is `conditional`. The simulation of one request is the second reading, and the two agree.

**What to watch after each enablement.** The rule's own `over_limit` and `near_limit`, the domain's
`ratelimit_checks_total{verdict="over_limit"}`, the gateway's `429` rate, and the listing with `limited=true` for the
rule. On the stand, enforcing the exporters' trial at ten per hour after the reset of stage two:

```text
bob(ROLE_Exporter) x9 GET /api/v1/exports/1: 200 200 200 200 200 200 200 429 429
```

```text
HTTP/1.1 429 Too Many Requests
x-ratelimit-limit: 10
x-ratelimit-remaining: 0
x-ratelimit-reset: 3589
retry-after: 349
```

```text
ratelimit_checks_total{domain="gateway.public",verdict="over_limit"} 3
ratelimit_decisions_total{domain="gateway.public",outcome="over_limit",rule="api/exports-per-client-trial"} 3
ratelimit_near_limit_total{domain="gateway.public",rule="api/exports-per-client-trial"} 2
```

Seven of the ten were left after the reset and the three requests of stage two; the last two admissions were the
near-limit ones; the refusals carry the window's headers. `mode` in the counter listing turned to `enforce` on the
same key, with the same `remaining`.

**Percent enforcement as a canary.** `runtime.enforcedPercent` between `0` and `100` enforces a random share of the
requests of the whole gateway, every domain and every rule behind it. It is a coarse canary: a client over its limit
gets `429` on that share of its requests and `200` on the rest, at random. It has a place when the first enforcement
on a gateway is itself the risk; it is not a substitute for enabling rules one at a time.

## 4. Rollback

**Back to shadow.** One edit, `behavior: Enforce` to `Shadow`, effective on `Ready`. The counters carry over on the
same key; the client is admitted at its next request, and the rule keeps reporting what it would have done:

```text
bob back in shadow x2 GET /api/v1/exports/1: 200 200
# [{"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client-trial:gcra:3600:bob:",
#   "mode": "shadow", "remaining": 0, "limited": true}]
```

**A wrong limit.** Fix the value, then reset: the addressed form for one identity, the bulk form for every bucket of
the rule (stage two). Without the reset the fixed limit takes effect only as the bucket drains, which is the
`retryAfterSeconds` of the listing. A rule switched back to shadow needs no reset: nothing is refused while the
bucket drains.

**The brakes.** When the policy edit is slower than the incident, the gateway fractions stop the refusals for the whole
gateway. The runtime override takes effect at once and lives only as long as the gateway pod; the values change on the
operator release is the durable form and needs no pod restart. On the stand, with `bob` over his limit:

```bash
GW=$(kubectl get pod -n "$NS" -l gateway.networking.k8s.io/gateway-name=public-gateway \
  -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n "$NS" "$GW" -c istio-proxy -- pilot-agent request POST \
  'runtime_modify?ratelimit.public-gateway.enforced=0'
kubectl exec -n "$NS" "$GW" -c istio-proxy -- pilot-agent request GET runtime \
  | jq -c '.entries["ratelimit.public-gateway.enforced"], .layers'
# {"layer_values": ["", "0"], "final_value": "0"}
# ["global config", "admin"]
```

```text
bob x2 GET /api/v1/exports/1:                    429 429     before the override
bob with enforced=0 x3 GET /api/v1/exports/1:    200 200 200
ratelimit_checks_total{domain="gateway.public",verdict="over_limit"} 10   grew by the three
bob with enabled=0 x3 GET /api/v1/exports/1:     200 200 200
ratelimit_checks_total{domain="gateway.public",verdict="over_limit"} 10   did not move
bob with the overrides removed x2:               429 429
```

With `enforced=0` the service still judged the three requests over the limit and the gateway withheld the refusal,
so the metrics kept telling the truth; with `enabled=0` the filter never called, and the service saw nothing. Prefer
`enforced`; `enabled` is for a service that itself is the problem. An empty value removes an override:
`runtime_modify?ratelimit.public-gateway.enforced=`.

The durable form is the value in the operator chart, through Helm or the operator's Argo CD application; the service
release is not touched:

```bash
helm upgrade ratelimit-operator <operator chart> -n "$NS" --reuse-values --set runtime.enforcedPercent=0
kubectl get envoyfilter -n "$NS" ratelimit-public-gateway -o json \
  | jq -c '[.. | objects | select(has("runtime_key")) | {runtime_key, numerator: .default_value.numerator}]'
# [{"runtime_key": "ratelimit.public-gateway.enabled", "numerator": 100},
#  {"runtime_key": "ratelimit.public-gateway.enforced", "numerator": 0}]
```

Three requests from `bob` answered `200` a few seconds after the upgrade, and `429` again after the value went back
to `100`; the component pod was the same before and after (the operator pod, after the split), the change is an
`EnvoyFilter` that istiod pushes to the gateway. A runtime override wins over the rendered value while it exists, so
remove it before relying on the value.

**A dial change is a change of the operator release only.** The values edit above, or a rollback of that release to the
revision before the edit, renders the EnvoyFilters again and touches no other object. The service release, its pods,
and the policy stay as they are, and no order applies between the two releases.

**A version rollback of the pair.** Where the two versions differ in the manifest format version, the order matters:
roll the operator back first, then the service. The service reads the format versions N and N-1 and the operator writes
N, so the older operator's N-1 is read by both service versions. A service rolled back first refuses the newer
operator's N, and its fresh pods stay NotReady until the operator follows (runbook, section 5). An upgrade runs in the
opposite order, the service first, then the operator.

**A rename.** The block and rule names are in the counter key, so a renamed rule starts on fresh buckets: every
identity gets a full budget once, the old buckets stay in the store until their TTL, and the metric series of the old
name are dropped within seconds of the swap. On the stand, `exports-per-client-trial` renamed to `exports-per-client`:

```bash
api "$BASE/domains/$DOMAIN/counters?ruleId=api/exports-per-client-trial" | jq -c '{scanned, items}'
# {"scanned": 1, "items": []}          the old bucket is seen by the scan and skipped as an orphan
api "$BASE/domains/$DOMAIN/counters?ruleId=api/exports-per-client" | jq -c '{scanned, items}'
# {"scanned": 0, "items": []}
```

```text
bob after the rename x2 GET /api/v1/exports/1: 200 200
# [{"key": "rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client:gcra:3600:bob:", "limit": 10, "remaining": 8}]
rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client-trial:gcra:3600:bob:   TTL 3460
rl:v1:{ratelimit-e2e/gateway.public}:api/exports-per-client:gcra:3600:bob:
```

Do not rename during a rollout: a rename in the same edit as an enablement resets every client of the rule and
takes the shadow history with it. Rename while the rule is in shadow, then observe again. Removing a rule has the same
effect without the new name. Renaming a block renames every rule in it.

## 5. The run in one table

| Step | Edit | Generation | Result on the stand |
| --- | --- | --- | --- |
| 1 | the example policy, trial rule in shadow | 5 | 8 + 3 requests, all `200`; `shadow_over_limit` 3, all `bob` |
| 2 | `requests: 5` to `10`, still shadow | 6 | same keys, `bob` still limited, debt paid at the new rate |
| 2 | reset the rule's buckets | 6 | `resetCount: 2`; `bob` at `remaining: 7` after three requests |
| 3 | `Shadow` to `Enforce` on the trial | 7 | `200` x7, then `429` with headers; `over_limit` 3, `near_limit` 2 |
| 3 | a shadow rule on top of the `orders` cascade | 8 | the rule below still decides; 5 x `200` |
| 3 | `Enforce` on the cascade rule | 9 | the rule decides alone; `200 200 200 429 429`; the rule below stops growing |
| 4 | `enforced=0`, `enabled=0` at runtime, then removed | 9 | `200` under both; the service counts only under the first |
| 4 | `runtime.enforcedPercent` 0 and back through Helm on the operator release | 9 | `200`, then `429`; no pod restart |
| 4 | the trial back to `Shadow` | 10 | `200`, same key and `remaining` |
| 4 | the trial renamed | 11 | fresh bucket, old key left with its TTL, old series gone |
| end | the example policy again | 12 | `Ready: True`, 12 rules, the original rule set version |

## Appendix: observation to metric or status field

The metrics of the decision path are scraped from the service pods; the policy gauges from the operator pod, which
writes the status.

| Observation | Metric or field | Today |
| --- | --- | --- |
| the domain is wired | `ratelimit_unknown_domain_checks_total`, `ratelimit_checks_total{domain, verdict}` | as named |
| routes match | `ratelimit_unmatched_checks_total{domain}` | as named |
| keys arrive | `ratelimit_extractions_total{domain, key}`, `ratelimit_extraction_skips_total{domain, key, reason}`, `ratelimit_tokens_seen_total{domain}` | as named |
| a rule matched | `ratelimit_decisions_total{domain, rule, outcome="ok"}` | as named |
| would-be refusals | `ratelimit_decisions_total{outcome="shadow_over_limit"}`, `GET /counters?limited=true` | as named |
| refusals after enablement | `ratelimit_decisions_total{outcome="over_limit"}`, `ratelimit_checks_total{verdict="over_limit"}` | as named |
| clients close to an enforced limit | `ratelimit_near_limit_total{domain, rule}` | shadow excluded; the margin is a share of the window's capacity, `burst` for GCRA |
| consumption per identity | `GET /counters`: `limit`, `remaining`, `retryAfterSeconds`, `mode` | as named |
| which rules a request applies | `POST /simulations`: `rules[].mode`, `rules[].allowed`; `GET /rules?path=&method=&axis.<name>=`: `applicability` | as named |
| the generation enforced | `status.activeGeneration`, `Ready`, `ratelimit_policy_ready` | the gauge is on the operator pod, labelled `domain` and `reason` |
| the brakes' state | `EnvoyFilter` `default_value.numerator`, the gateway's `/runtime` entries | as named; the `EnvoyFilter` is rendered by the operator chart |
