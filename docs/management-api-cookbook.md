# Management API: complete scenario reference

A companion to the [management API reference](management-api.md); every call conforms to the OpenAPI document the
service serves at `GET /openapi.yaml`. The document is built around ONE end-to-end configuration (section 1): every
example refers to its rules, and all the numbers in the responses are consistent with each other.

## 0. Setup

```bash
kubectl port-forward -n core svc/ratelimit 8082:8082 &
BASE=http://127.0.0.1:8082/ratelimit/v1

# Tokens are issued by your IdP; the gateway's auth extension validates them, and
# the service itself checks the roles from the claim: reading and simulating take
# viewer, mutating takes operator (canonical names; the mapping to IdP roles is in
# the deployment values).
TOKEN=<idp-token-with-viewer-role>
OPTOKEN=<idp-token-with-operator-role>
api() { curl -sS -H "Authorization: Bearer $TOKEN" "$@"; }
op()  { curl -sS -H "Authorization: Bearer $OPTOKEN" "$@"; }
```

## 1. End-to-end configuration

Constructed to exercise every mechanism: both block modes (All / FirstMatch), every behavior (Enforce / Shadow /
Bypass), every operator (Equals / In / InGroup / Contains / Exists / DoesNotExist), every route type (Exact / Prefix /
Template) and the method filter, replacedRules, burst, both algorithms (GCRA / FixedWindow), window pairs, every axis
shape (no axes / client / client+path / capture / tenant), groups and claim mapping inside the same object. The domain
has one policy: the object name == the domain.

```yaml
apiVersion: ratelimit.netcracker.com/v1
kind: RateLimitPolicy
metadata:
  name: gateway.public         # name == domain: one object per domain
  namespace: core
spec:
  domain: gateway.public
  mappings:
    - key: tenant            # axis from the org_id claim
      claim: org_id
    - key: plan              # axis from the plan claim (for the In operator)
      claim: plan
    - key: roles             # LIST-VALUED claim, for the Contains operator
      claim: roles
      type: StringArray
  groups:
    - name: partners
      clients: [p-1, p-2]
    - name: trial
      clients: [trial-1, trial-2]
  limits:
    # -- FirstMatch cascade: the first match decides; Bypass cuts off,
    #    Shadow counts without deciding
    - name: cascade
      mode: FirstMatch
      target:
        routes:
          - path: {type: Prefix, value: /api/invoices/}
            methods: [GET, POST]
      rules:
        - name: internal          # Bypass + Equals
          behavior: Bypass
          matches: [{key: client, operator: Equals, value: prometheus}]
        - name: trial             # Shadow + InGroup
          behavior: Shadow
          counters: [client]
          matches: [{key: client, operator: InGroup, value: trial}]
          rates: [{requests: 10, periodSeconds: 60}]
        - name: premium           # In on the mapped axis plan
          counters: [client]
          matches: [{key: plan, operator: In, values: [gold, platinum]}]
          rates: [{requests: 300, periodSeconds: 60, burst: 50}]
        - name: everyone          # unconditional tail of the cascade, burst
          counters: [client]
          rates: [{requests: 100, periodSeconds: 60, burst: 20}]

    # -- window pair: a gcra minute + a FixedWindow daily quota
    - name: quota
      target:
        routes: [{path: {type: Prefix, value: /api/invoices/}}]
      rules:
        - name: daily
          counters: [client]
          rates:
            - {requests: 100, periodSeconds: 60}
            - {requests: 10000, periodSeconds: 86400, algorithm: FixedWindow}

    # -- two axes [client, path] + replacedRules (a narrow rule silences a wide one)
    - name: reports
      target:
        routes:
          - path: {type: Prefix, value: /api/reports/}
            methods: [POST]
      rules:
        - name: heavy
          counters: [client, path]
          rates: [{requests: 5, periodSeconds: 60}]
        - name: gold              # In + replacedRules: the narrow one silences heavy
          counters: [client, path]
          matches: [{key: plan, operator: In, values: [gold, platinum]}]
          replacedRules: [heavy]
          rates: [{requests: 20, periodSeconds: 60}]

    # -- Template capture: axis = path segment
    - name: services
      target:
        routes: [{path: {type: Template, value: "/api/{service}/status"}}]
      rules:
        - name: per-service
          counters: [service]
          rates: [{requests: 60, periodSeconds: 60}]

    # -- mapped axis tenant + Bypass by group
    - name: tenants
      target:
        routes: [{path: {type: Prefix, value: /api/}}]
      rules:
        - name: partner-lift      # Bypass + InGroup;
          behavior: Bypass          # in an All block, Bypass must name
          matches: [{key: client, operator: InGroup, value: partners}]
          replacedRules: [per-tenant]    # whom it frees (in FirstMatch the cascade
                                    # cuts itself off)
        - name: per-tenant
          counters: [tenant]
          rates: [{requests: 1000, periodSeconds: 60}]

    # -- Exact route + Exists/DoesNotExist
    - name: login
      target:
        routes:
          - path: {type: Exact, value: /api/login}
            methods: [POST]
      rules:
        - name: anonymous         # DoesNotExist: no tenant before the token
          matches: [{key: tenant, operator: DoesNotExist}]
          rates: [{requests: 20, periodSeconds: 60}]
        - name: authenticated     # Exists + the tenant axis
          counters: [tenant]
          matches: [{key: tenant, operator: Exists}]
          rates: [{requests: 100, periodSeconds: 60}]

    # -- shared ceiling with no axes + Shadow with Contains
    - name: total
      target:
        routes: [{path: {type: Prefix, value: /api/}}]
      rules:
        - name: bots              # Shadow + Contains: element membership in
          behavior: Shadow          # the list-valued claim roles (NOT a substring)
          counters: [client]
          matches: [{key: roles, operator: Contains, value: bot}]
          rates: [{requests: 1, periodSeconds: 60}]
        - name: all               # rule with no axes: one bucket per domain
          rates: [{requests: 5000, periodSeconds: 60}]

    # -- set/prefix scenarios
    - name: search
      target:
        routes: [{path: {type: Prefix, value: /api/search}}]
      rules:
        - name: per-client
          counters: [client]
          rates: [{requests: 30, periodSeconds: 60}]
```

The compiled map (what GET /rules returns):

| ruleId | mode | axes | windows |
| --- | --- | --- | --- |
| cascade/internal | bypass | - | - |
| cascade/trial | shadow | [client] | gcra 10/1m |
| cascade/premium | enforce | [client] | gcra 300/1m burst 50 |
| cascade/everyone | enforce | [client] | gcra 100/1m burst 20 |
| quota/daily | enforce | [client] | gcra 100/1m + fixedwindow 10000/24h |
| reports/heavy | enforce | [client, path] | gcra 5/1m |
| reports/gold | enforce | [client, path] | gcra 20/1m (replacedRules: heavy; matches plan In) |
| services/per-service | enforce | [service] | gcra 60/1m |
| tenants/partner-lift | bypass | - | (replacedRules: per-tenant) |
| tenants/per-tenant | enforce | [tenant] | gcra 1000/1m |
| login/anonymous | enforce | - | gcra 20/1m |
| login/authenticated | enforce | [tenant] | gcra 100/1m |
| total/bots | shadow | [client] | gcra 1/1m |
| total/all | enforce | - | gcra 5000/1m |
| search/per-client | enforce | [client] | gcra 30/1m |

The cast of the examples: client alice (tenant acme, plan gold), bob (tenant acme, no plan), trial-1 (the trial group),
p-1 (a partner), prometheus (monitoring), scanner-bot-7 (roles: [bot]).

## 2. Domain overview

The domain list:

```bash
api "$BASE/domains"
```

```json
{"items": [{"domain": "gateway.public", "ruleSetVersion": "7c31a9f4e0d2",
  "blocks": 8, "rules": 15,
  "effectiveKeys": ["client", "method", "path", "plan", "roles", "tenant"],
  "listValuedKeys": ["roles"]}]}
```

The full rule set (the axis order is the contract for the addressed DELETE):

```bash
api "$BASE/domains/gateway.public/rules" | jq '.blocks[] | {block, mode, rules: [.rules[].id]}'
```

Which rules guard a specific API: the engine's matcher, with segment-based Prefix and Template exactly as on traffic:

```bash
api "$BASE/domains/gateway.public/rules?path=/api/invoices/42&method=GET" \
  | jq '[.blocks[].rules[].id]'
```

```json
["cascade/internal", "cascade/trial",
 "cascade/premium", "cascade/everyone",
 "quota/daily",
 "tenants/partner-lift", "tenants/per-tenant",
 "total/bots", "total/all"]
```

Template matching: /api/billing/status lands in services, with the capture service=billing:

```bash
api "$BASE/domains/gateway.public/rules?path=/api/billing/status&method=GET" \
  | jq '[.blocks[].block]'
# -> ["services", "tenants", "total"]
```

The method filter: reports accepts only POST, so a GET request does not see the block:

```bash
api "$BASE/domains/gateway.public/rules?path=/api/reports/2026&method=GET" \
  | jq '[.blocks[].block]'
# -> ["tenants", "total"]   # reports filtered out by method
```

A client calls in (knows only its name): scope the rules by a partial identity: every rule is annotated with its
applicability, and the engine accounts for the cascade (FirstMatch/bypass) and replacedRules, which jq over the bare
view cannot do:

```bash
api "$BASE/domains/gateway.public/rules?axis.client=alice" \
  | jq '{tochno:        [.blocks[].rules[] | select(.applicability == "always") | .id],
         teoreticheski: [.blocks[].rules[] | select(.applicability == "conditional") | .id]}'
```

```json
{"tochno": ["quota/daily", "services/per-service",
            "total/all", "search/per-client"],
 "teoreticheski": ["cascade/premium", "cascade/everyone",
                   "reports/heavy", "reports/gold",
                   "tenants/per-tenant", "login/anonymous",
                   "login/authenticated", "total/bots"]}
```

conditionalOn explains each "teoreticheski" entry: premium waits for plan (undecided_condition), everyone may be
preempted by premium (may_be_preempted, FirstMatch), heavy may be silenced by gold (replacedRules), per-tenant lacks the
tenant axis (missing_axis). Once you learn the tenant, the refinement narrows monotonically:

```bash
api ".../rules?axis.client=alice&axis.tenant=acme"
# per-tenant: conditional -> always; authenticated -> always; anonymous -> never
```

List-valued keys (roles) are repeatable and define the complete set of values:

```bash
api ".../rules?axis.client=alice&axis.roles=support&axis.roles=operator"
# total/bots: conditional -> never (roles are fully known, and bot is not among them)
```

Known absence: the absent parameter (the key's empty set):

```bash
api ".../rules?axis.client=bob&absent=tenant"
# login/anonymous:     conditional -> always  (DoesNotExist tenant decided)
# login/authenticated: conditional -> never   (Exists failed)
# tenants/per-tenant:  conditional -> never   (the counting axis is empty forever)
```

Next comes the reset ladder (sections 5 and 6): an exact counter through DELETE, partial levels through counter-resets
with a preview.

## 3. Simulations: the request debugger

Peek semantics: it charges nothing, so call it as often as you like. The response is a best-effort evaluation as of
evaluatedAt: nothing is reserved, and counters move between the evaluation and the real request.

The merge form (the default) works like the gateway: extraction from the token, keys on top:

```bash
api -X POST "$BASE/simulations" -H 'Content-Type: application/json' -d '{
  "domain": "gateway.public", "path": "/api/invoices/42", "method": "GET",
  "keys": {"client": ["alice"], "tenant": ["acme"], "plan": ["gold"]}
}'
```

```json
{
  "allowed": true,
  "evaluatedAt": "2026-08-24T14:02:09Z",
  "headers": {"algorithm": "gcra", "periodSeconds": 60,
              "limit": 100, "remaining": 61, "resetAfterSeconds": 23.4},
  "rules": [
    {"id": "cascade/premium", "mode": "enforce", "allowed": true,
     "algorithm": "gcra", "periodSeconds": 60, "limit": 300, "remaining": 254},
    {"id": "quota/daily", "mode": "enforce", "allowed": true,
     "algorithm": "gcra", "periodSeconds": 60, "limit": 100, "remaining": 61},
    {"id": "tenants/per-tenant", "mode": "enforce", "allowed": true,
     "algorithm": "gcra", "periodSeconds": 60, "limit": 1000, "remaining": 902},
    {"id": "total/all", "mode": "enforce", "allowed": true,
     "algorithm": "gcra", "periodSeconds": 60, "limit": 5000, "remaining": 4310}
  ],
  "extractedKeys": ["client", "plan", "tenant"]
}
```

Reading it: alice with plan=gold goes down the premium branch of the cascade (300/1m), not everyone; headers is the
binding window: on an admission, the enforcing window with the smallest remaining (here the minute window of
quota/daily, 61 of 100), not premium.

The cascade for a client without a plan: everyone decides:

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/invoices/42", "method": "GET",
  "keys": {"client": ["bob"], "tenant": ["acme"]}
}' | jq '[.rules[] | {id, allowed, remaining}]'
```

```json
[{"id": "cascade/everyone", "allowed": true, "remaining": 17},
 {"id": "quota/daily", "allowed": true, "remaining": 40},
 {"id": "tenants/per-tenant", "allowed": true, "remaining": 902},
 {"id": "total/all", "allowed": true, "remaining": 4309}]
```

Bypass cuts the cascade off: prometheus spends nobody's limits in cascade, but Bypass is block-local, so quota/daily
(the same prefix, no matches) counts it like any other client (the tenants block is likewise lifted by partner-lift
only for p-1/p-2; prometheus goes through per-tenant without a tenant axis, so the rule does not apply):

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/invoices/1", "method": "GET",
  "keys": {"client": ["prometheus"]}
}' | jq '[.rules[].id]'
# -> ["quota/daily", "total/all"]
```

Shadow is visible in rules[] but does not affect allowed: trial-1 is past its shadow limit:

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/invoices/1", "method": "GET",
  "keys": {"client": ["trial-1"]}
}' | jq '{allowed, evaluatedAt, trial: [.rules[] | select(.mode == "shadow")]}'
```

```json
{"allowed": true, "evaluatedAt": "2026-08-24T14:02:33Z",
 "trial": [{"id": "cascade/trial", "mode": "shadow", "allowed": false,
   "refusalReason": "rate_limited",
   "algorithm": "gcra", "periodSeconds": 60, "limit": 10, "remaining": 0,
   "retryAfterSeconds": 42.1}]}
```

replacedRules: for the gold plan the narrow rule gold silences heavy, so in rules[] the reports block has only it (bob
without a plan would go through heavy):

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/reports/2026-08", "method": "POST",
  "keys": {"client": ["alice"], "tenant": ["acme"], "plan": ["gold"]}
}' | jq '[.rules[] | select(.id | startswith("reports")) | .id]'
# -> ["reports/gold"]
```

An expensive request: cost from hits_addend:

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/invoices/1", "method": "GET",
  "keys": {"client": ["bob"]}, "cost": 5
}' | jq '{allowed, refusalReason, headers}'
# with remaining=3 and cost=5 -> {"allowed": false, "refusalReason": "rate_limited",
#    "headers": {"algorithm": "gcra", "periodSeconds": 60, "limit": 100,
#                "remaining": 3, "retryAfterSeconds": 1.2}}, which is what
# limited=true (cost=1) in the listing will not show
```

The pure forms: token (keys is inexpressible by the schema) and keys (token is inexpressible); anonymous is merge
without either:

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/login", "method": "POST",
  "identitySource": "token", "token": "eyJhbGciOi..."}' | jq .extractedKeys
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/login", "method": "POST"
}' | jq '[.rules[].id]'
# -> ["login/anonymous", "total/all"]  # DoesNotExist fired
```

A broken token: the diagnosis is in skips, and clients collapse into anonymous:

```bash
api -X POST "$BASE/simulations" -d '{
  "domain": "gateway.public", "path": "/api/invoices/1", "method": "GET",
  "identitySource": "token", "token": "garbage"
}' | jq .skips
```

```json
[{"key": "client", "reason": "decode_failed"},
 {"key": "plan", "reason": "decode_failed"},
 {"key": "roles", "reason": "decode_failed"},
 {"key": "tenant", "reason": "decode_failed"}]
```

## 4. Viewing counters

A rule's counters:

```bash
api "$BASE/domains/gateway.public/counters?ruleId=cascade/everyone"
```

```json
{"items": [
  {"key": "rl:v1:{core/gateway.public}:cascade/everyone:gcra:60:bob:",
   "ruleId": "cascade/everyone",
   "block": "cascade", "rule": "everyone", "mode": "enforce",
   "algorithm": "gcra", "periodSeconds": 60,
   "axes": {"client": "bob"},
   "limit": 100, "remaining": 17, "limited": false},
  {"key": "rl:v1:{core/gateway.public}:cascade/everyone:gcra:60:crawler:",
   "axes": {"client": "crawler"},
   "limit": 100, "remaining": 0, "limited": true,
   "retryAfterSeconds": 12.4, "resetAfterSeconds": 60,
   "ruleId": "cascade/everyone", "mode": "enforce",
   "algorithm": "gcra", "periodSeconds": 60,
   "block": "cascade", "rule": "everyone"}
], "scanned": 2}
```

The listing skips counters of rules already removed from the enforced set (scanned counts them): they cannot be rendered
against the snapshot. A bulk reset reaches them through the key-parsing selectors (ruleIds/algorithm/period/the whole
domain), because those parse the key, not the snapshot (axes and limited need the rule and do not see orphans); the TTL
finishes them off by itself. A stale ruleId in a bulk selector is not 404 but 200 with the actual (possibly zero) count;
a 404 from bulk is only about the domain.

Everything alice has accumulated across the domain (partial axes are legal in a READ; only the addressed DELETE requires
completeness):

```bash
api "$BASE/domains/gateway.public/counters?axis.client=alice" \
  | jq '[.items[] | {ruleId, axes, remaining}]'
```

```json
[{"ruleId": "cascade/premium", "axes": {"client": "alice"}, "remaining": 254},
 {"ruleId": "quota/daily", "axes": {"client": "alice"}, "remaining": 61},
 {"ruleId": "quota/daily", "axes": {"client": "alice"}, "remaining": 8734},
 {"ruleId": "reports/gold", "axes": {"client": "alice", "path": "/api/reports/2026-08"}, "remaining": 0},
 {"ruleId": "reports/gold", "axes": {"client": "alice", "path": "/api/reports/2026-07"}, "remaining": 14}]
```

(daily appears twice: two windows of one rule; gold gets a counter per actual path.)

Who is blocked right now (cost=1):

```bash
api "$BASE/domains/gateway.public/counters?limited=true" \
  | jq '[.items[] | {ruleId, axes, mode}]'
```

```json
[{"ruleId": "cascade/everyone", "axes": {"client": "crawler"}, "mode": "enforce"},
 {"ruleId": "cascade/trial", "axes": {"client": "trial-1"}, "mode": "shadow"},
 {"ruleId": "reports/gold", "axes": {"client": "alice", "path": "/api/reports/2026-08"}, "mode": "enforce"},
 {"ruleId": "total/bots", "axes": {"client": "scanner-bot-7"}, "mode": "shadow"}]
```

(shadow with limited=true means "would have refused": trial-1 and the bot lose no traffic.)

Slices: daily windows only; a capture axis; a tenant; an exact path; a client within a tenant (AND of axes):

```bash
api "...counters?period=24h" | jq '[.items[] | {axes, remaining}]'
# -> [{"axes": {"client": "alice"}, "remaining": 8734}, {"axes": {"client": "bob"}, ...}]
api "...counters?axis.service=billing"
api "...counters?limited=true&axis.tenant=acme" | jq '[.items[].ruleId] | unique'
api "...counters?ruleId=reports/heavy&axis.path=/api/reports/2026-08"
api "...counters?limited=true&axis.client=alice&axis.tenant=acme"
# AND: only rules that count BY BOTH axes; alice's per-client rules
# do not land here: the client->tenant linkage lives in the IdP, not in the keys
```

An exact count of any selection without walking the pages: dryRun as a counter:

```bash
op -X POST "$BASE/domains/gateway.public/counter-resets" \
  -H "Idempotency-Key: $(uuidgen)" -d '{
  "selector": {"ruleIds": ["reports"]}, "dryRun": true
}' | jq '{matchedCount, scanned}'
# -> {"matchedCount": 5, "scanned": 490}
```

Pagination: a page can be incomplete in the middle of the collection (the scan budget, or the cap of 128 store steps);
the end is only a missing nextCursor; the cursor is bound to the selection (fingerprint + TTL; foreign selectors are
400); a page holds whole store steps, so on Redis it may run a few items over pageSize, and its items are unsorted;
pages are not a snapshot:

```bash
api "...counters?pageSize=100" | jq '{n: (.items|length), nextCursor, scanned}'
# -> {"n": 37, "nextCursor": "eyJmcCI6...", "scanned": 500}
api "...counters?pageSize=100&cursor=eyJmcCI6..."
```

## 5. Addressed reset (DELETE)

The invariant is key computability: one full ruleId plus ALL of the rule's axes with single values. The window is
optional (the window set is known from the snapshot). Idempotency-Key is mandatory here too (scope:
subject+domain+endpoint): on a timeout, a repeat of the same pair returns the original result rather than deleting
counters that are new by then. The addressed form does NOT need a confirmation token: its radius is bounded by
construction.

```bash
alias opk='op -H "Idempotency-Key: $(uuidgen)"'
```

A DELETE preview and execution are different commands (they differ by dryRun on the same selection): each call has its
own key, which is exactly what the alias above provides; reusing the preview's key for the execution is 409, not a
retry.

The key does not lock the counter: a repeated RESET of the same selection is a new command with a new key (the alias
mints one itself); the old key is reused only for a retry of the same call. The record is bound in the same atomic
script that deletes; a preview is recorded just like an execution, and a retry replays the recorded 200 response, BEFORE
expectedRuleSetVersion is checked again (a completed call does not get 409 after the fact). Refusals leave no record: a
corrected repeat is re-evaluated afresh. For DELETE, the record, the deletions of the computed keys, and the outcome
commit in ONE atomic script, so there are no intermediate states: a 5xx means "the script never ran, nothing deleted and
nothing bound", and a clean retry executes again; a lost response is a delay, not an ambiguity: the retry finds the
recorded outcome and replays it. The addressed form has no interrupted state by construction; that is what distinguishes
it from bulk, whose sweep cannot be expressed as one script. Record retention is at least 24 hours.

```bash
# one client of one rule (all windows)
opk -X DELETE "$BASE/domains/gateway.public/counters?ruleId=quota/daily&axis.client=alice"
```

```json
{"dryRun": false, "domain": "gateway.public", "ruleId": "quota/daily",
 "ruleSetVersion": "7c31a9f4e0d2",
 "axes": {"client": "alice"}, "resetCount": 2,
 "keys": ["rl:v1:{core/gateway.public}:quota/daily:gcra:60:alice:",
          "rl:v1:{core/gateway.public}:quota/daily:fixedwindow:86400:alice:"]}
```

```bash
# the daily window only: return the quota, leave the per-minute protection alone
opk -X DELETE "...?ruleId=quota/daily&axis.client=alice&period=24h"
# -> {"resetCount": 1, "keys": ["...fixedwindow:86400:alice:"]}

# a two-axis rule: BOTH axes are mandatory
opk -X DELETE "...?ruleId=reports/heavy&axis.client=alice&axis.path=/api/reports/2026-08"

# a rule with no axes: no axis parameters
opk -X DELETE "...?ruleId=total/all"

# careful: only if blocked right now (gold requires both axes)
opk -X DELETE "...?ruleId=reports/gold&axis.client=alice&axis.path=/api/reports/2026-08&limited=true"

# preview
opk -X DELETE "...?ruleId=quota/daily&axis.client=alice&dryRun=true"
# -> {"dryRun": true, "matchedCount": 2, ...}: matched, not deleted;
#    the addressed preview issues no token: none is needed

# pin the reset to the rule set you looked at (ruleSetVersion from GET /rules):
opk -X DELETE "...?ruleId=quota/daily&axis.client=alice&expectedRuleSetVersion=7c31a9f4e0d2"
# 409 if a rollout swapped the snapshot between the look and the deletion;
# without the parameter the current snapshot applies: the radius is bounded anyway
```

Refusals of the addressed form are RLS-0400, not a silent widening:

```bash
opk -X DELETE "...?ruleId=reports/heavy&axis.client=alice"
# 400: the rule has axes [client, path], and only client is named;
#      "all of alice's paths" requires a scan, which is bulk
opk -X DELETE "...?ruleId=cascade"
# 400: a prefix is rejected in the addressed form
opk -X DELETE "...?ruleId=quota/daily&axis.client=alice&period=7h"
# 404: the rule has no 7h window; a typo does not look like success
```

## 6. Bulk reset (POST /counter-resets)

The two-step mechanism is ENFORCED: execution accepts only a confirmationToken issued by a preview of the same
normalized selector (bound to the domain and the subject, single-use, TTL ~10 minutes). This closes the near-domain-wide
selectors such as {"limited": false} or a bare algorithm: "look, confirm, delete" is now a construction, not a
recommendation. Idempotency-Key is mandatory on every call (scope: subject+domain+endpoint).

```bash
# step 1: the preview: what matched, and the token
KEY=$(uuidgen)
PREVIEW=$(op -X POST "$BASE/domains/gateway.public/counter-resets" \
  -H "Idempotency-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "selector": {"ruleIds": ["cascade"]},
  "dryRun": true
}')
echo "$PREVIEW" | jq '{matchedCount, rules, confirmationToken, confirmationExpiresAt}'
# {"matchedCount": 63,
#  "rules": [{"ruleId": "cascade/trial", "matchedCount": 2},
#            {"ruleId": "cascade/premium", "matchedCount": 20},
#            {"ruleId": "cascade/everyone", "matchedCount": 41}],
#  "confirmationToken": "ct-5b8e2f9d4a10",
#  "confirmationExpiresAt": "2026-08-24T14:15:02Z"}

# step 2: the execution with the same selector + the token
CT=$(echo "$PREVIEW" | jq -r .confirmationToken)
op -X POST "$BASE/domains/gateway.public/counter-resets" \
  -H "Idempotency-Key: $(uuidgen)" -d '{
  "selector": {"ruleIds": ["cascade"]},
  "confirmationToken": "'$CT'"
}'
# -> {"dryRun": false, "resetCount": 63, "rules": [...]}
```

The token lifecycle in codes: the selector/domain/subject did not match, or the rule set changed between the steps:
RLS-0409 (you confirmed a selection over rules that no longer exist); expired or already used: RLS-0410; malformed or
missing: RLS-0400. The preview's matchedCount is as of the preview: traffic drifts the number, and the execution
re-resolves the same selection (the documented non-snapshot semantics). The other selections go through the same flow:

```bash
# a client across the domain / a tenant's list of clients / a tenant: preview, then token
... -d '{"selector": {"axes": {"client": ["alice"]}}, "dryRun": true}'
... -d '{"selector": {"axes": {"client": ["u1", "u2", "u3"]}}, "dryRun": true}'
... -d '{"selector": {"axes": {"tenant": ["acme"]}}, "dryRun": true}'

# the whole domain: the name is repeated in the body AND the execution step needs the preview's token
... -d '{"confirmDomain": "gateway.public", "dryRun": true}'
... -d '{"confirmDomain": "gateway.public", "confirmationToken": "ct-..."}'
```

A wide selection is the same flow and the same synchronous response, just longer: the sweep runs to the end inside the
call (a domain is one store slot: SCAN in batches + UNLINK), and hundreds of thousands of keys take seconds; size the
client timeout for that. A whole-domain reset:

```bash
op -X POST "$BASE/domains/gateway.public/counter-resets" \
  -H "Idempotency-Key: $(uuidgen)" -d '{
  "confirmDomain": "gateway.public", "dryRun": true
}'
# 200 after a couple of seconds:
# {"dryRun": true, "matchedCount": 217432,
#  "confirmationToken": "ct-9d51c2e055a1", ...}

op -X POST "$BASE/domains/gateway.public/counter-resets" \
  -H "Idempotency-Key: $(uuidgen)" -d '{
  "confirmDomain": "gateway.public", "confirmationToken": "ct-9d51c2e055a1"
}'
# 200: {"dryRun": false, "scanned": 218067, "resetCount": 217432}
```

The sweep limits are server-side, not client-side. A domain runs one sweep at a time: a second parallel call gets 409
BEFORE acceptance (conflictType: sweep_in_flight, and Retry-After says when; nothing is bound, so repeat after it
completes), while a retry of YOUR OWN still-running command gets 202 with Retry-After and no body: the record is the
operation, the retry is the poll, come back for the outcome. A sweep that hits the server deadline (a constant on the
order of a minute; real selections fit in seconds) is recorded as a failed outcome RLS-0422: meta.partialReset carries a
mirror of the successful response cut at the stop (scanned, resetCount, the rules breakdown, a keys sample, truncated),
what was deleted stands; from there narrow the selection or reset per rule.

Retry and conflict: the same Idempotency-Key with the same canonical command -> the original outcome; with a different
one -> 409. A preview and its execution are DIFFERENT commands over one selection: each has its own key (in the examples
above a key is generated for every call; that is the contract, not carelessness; reusing the preview's key for the
execution is 409, not a retry).

The record is bound ATOMICALLY at command acceptance, before the first deletion, and acceptance is the point of no
return (the confirmation token is consumed right then, not at the end of execution): ANY error after acceptance, even
with zero deletions, is recorded as the command's failed outcome; only refusals before acceptance leave no record. A
retry replays the recorded outcome: completed, 200 with the same body the original call returned; failed, the recorded
error, where meta.partialReset carries scanned and resetCount up to the stop (zeroes = it failed before the first
deletion; what was deleted stands). Any unforeseen error after acceptance is RLS-0501 (status 500): the live walker
records the failed outcome itself and answers with it. The exception is a failure of the store itself: there is nothing
to record with, the call gets 503, the record stays accepted, and from there the lease takes over: the retry sees 202
while it is live, and after it expires finalizes the same RLS-0501 with partialReset from the recorded progress; a
process that simply died is finalized the same way: every batch commits its counts together with the deletions, so the
disclosure is exact up to the last batch that ran; re-execution is exactly what the point of no return forbids;
finalization is possible only once the sweep lease has expired (a live sweep is what the retry sees as 202 +
Retry-After), and it is done atomically (the outcome appended, the TTL refreshed), after which further retries replay
the terminal outcome. After retention the idempotency guarantee ends: a preview runs again and mints a new token, while
an execution normally gets 410, its token consumed or expired long ago. Do not retry across days. The record is read
BEFORE the token and version checks: a completed call does not get 409/410 after the fact. A preview is recorded too: a
repeat of a lost preview returns THE SAME confirmationToken rather than minting a second one. Record retention is at
least 24 hours after the outcome (for an interrupted one, without an outcome, from acceptance). Finishing the job is a
new preview and a new token. Two operators with different keys do not lock each other out.

## 7. Status, errors, and edge cases

```bash
api "$BASE/status"
# {"replica": "ratelimit-6c9d-x2v", "snapshotSwappedAt": "2026-08-24T13:58:41Z",
#  "ruleSetVersions": {"gateway.public": "7c31a9f4e0d2"},
#  "counterStore": {"backend": "redis at redis:6379"}}
```

Errors are NC.TMFErrorResponse.v1.0: branch on code, and have people quote the id:

```bash
api "$BASE/domains/gateway.typo/rules"
# {"id": "3f9a...", "code": "RLS-0404", "reason": "Unknown resource",
#  "message": "domain \"gateway.typo\" is not in the enforced rule set",
#  "status": "404", "@type": "NC.TMFErrorResponse.v1.0", "meta": {"requestId": "b21c..."}}
```

Edge cases:

- Orphans (a rule was renamed, an axis was removed from the mapping, a domain went away): the listing skips them (there
  is nothing to render them against in the snapshot; scanned counts them), the addressed DELETE answers 404, and bulk
  REACHES them through the key-parsing selectors (ruleIds/algorithm/period/the whole domain parse the key, not the
  snapshot); and in any case the store contract guarantees self-expiry by window.
- Bulk execution resolves the selector once, at the start of the sweep: a snapshot change in the middle of execution
  does not re-read the selector.
- The in-process store is the single-replica test mode: the API behaves as with Redis (the store of the sole replica is
  trivially the installation's shared store). The chart never renders it, and the service warns when it serves the
  management API over it.
- cost=1 is the contract of limited and of the listing; for traffic with hits_addend>1 the exact answer comes from a
  simulation with cost (section 3).
- Do not confuse the two kinds of "path": in the ?path= filter of /rules it is the REQUEST path (matched by the engine:
  segment-based Prefix, Template captures); in axis.path it is the exact axis VALUE (the query string is stripped by the
  engine). "Everything under a prefix" cannot be expressed through an axis: the right answer is a configuration one:
  capture the segment with a Template route (counters: [service]), or select by rule.
