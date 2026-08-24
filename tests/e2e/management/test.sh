#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# The management API.
#
# Two things here cannot be proved anywhere else. The first is that access
# control is real: this API lifts live rate limits, and the checks below run it
# against the cluster's own RBAC rather than a stub. The second is that a reset
# takes effect on traffic — the gateway admits again, immediately, and only for
# the client that was named.
#
# The base path is part of the first claim. Kubernetes grants get on /api/* to
# every authenticated identity through the system:discovery ClusterRole, so an
# API served under /api would be readable by the whole cluster whatever this
# chart's roles say. The unprivileged check below is what would catch a move
# back under that prefix.
# ---------------------------------------------------------------------------
set -eu

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

POLICY="e2e-mgmt-$(date +%s)"
DOMAIN=gateway.public
PROBE_PATH=/e2e-ratelimit
OTHER_PATH=/e2e-ratelimit/other
RULE="${POLICY}/probe/per-path"

# An hour so the window cannot refill under the test, and three requests so the
# budget is spent deliberately rather than by a burst that happened to land.
LIMIT=3
PERIOD=1h

READ_SA="${POLICY}-viewer"
RESET_SA="${POLICY}-operator"
PORT=18082

AUDIT_BEFORE=""

restore_audit() {
  [[ -n "${AUDIT_BEFORE}" ]] || return 0
  api PUT /audit "${TOKEN:-}" "${AUDIT_BEFORE}" >/dev/null 2>&1 || true
  return 0
}

cleanup() {
  restore_audit
  kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete sa "${READ_SA}" "${RESET_SA}" -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete clusterrolebinding "${RESET_SA}" --ignore-not-found >/dev/null 2>&1 || true
  if [[ -n "${PF_PID:-}" ]]; then
    kill "${PF_PID}" 2>/dev/null || true
    wait "${PF_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Is the management API enabled in this release?
# ---------------------------------------------------------------------------
# An install with management.enabled=false is a perfectly good install, so this
# suite skips rather than fails on one.
MANAGEMENT_PORT=$(kubectl get svc "${OPERATOR_SVC}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.ports[?(@.name=="management")].port}' 2>/dev/null || true)

if [[ -z "${MANAGEMENT_PORT}" ]]; then
  echo "SKIP: this release does not expose the management API"
  exit 0
fi
echo "OK: the release exposes the management API on port ${MANAGEMENT_PORT}"

kubectl port-forward -n "${NAMESPACE}" "svc/${OPERATOR_SVC}" \
  "${PORT}:${MANAGEMENT_PORT}" >/dev/null 2>&1 &
PF_PID=$!
sleep 3

BASE="http://127.0.0.1:${PORT}/ratelimit/v1"

# api METHOD PATH [TOKEN] [BODY] — prints the response body.
api() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -X "${method}" -m 20)
  [[ -n "${token}" ]] && args+=(-H "Authorization: Bearer ${token}")
  [[ -n "${body}" ]] && args+=(-H 'Content-Type: application/json' -d "${body}")
  curl "${args[@]}" "${BASE}${path}"
}

# api_code is the same call reporting only the status.
api_code() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o /dev/null -w '%{http_code}' -X "${method}" -m 20)
  [[ -n "${token}" ]] && args+=(-H "Authorization: Bearer ${token}")
  [[ -n "${body}" ]] && args+=(-H 'Content-Type: application/json' -d "${body}")
  curl "${args[@]}" "${BASE}${path}" || echo "000"
}

# field reads one top-level field out of a JSON body.
field() {
  local name="$1"
  python3 -c "import json,sys; print(json.load(sys.stdin).get(sys.argv[1],''))" \
    "${name}" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# 1. Nothing is reachable without a credential the cluster recognizes
# ---------------------------------------------------------------------------
CODE=$(api_code GET /domains)
[[ "${CODE}" = "401" ]] || fail "an unauthenticated read answered ${CODE}, expected 401"

CODE=$(api_code GET /domains "not-a-real-token")
[[ "${CODE}" = "401" ]] || fail "a forged token answered ${CODE}, expected 401"
echo "OK: the API refuses a request without a token the cluster recognizes"

# ---------------------------------------------------------------------------
# 2. A recognized identity still needs RBAC
# ---------------------------------------------------------------------------
# The viewer account is created and deliberately granted nothing. If this
# returns 200, either a role is bound too widely or the base path has moved
# under one of the prefixes Kubernetes grants to system:authenticated.
kubectl create sa "${READ_SA}" -n "${NAMESPACE}" >/dev/null 2>&1 || true
UNGRANTED=$(kubectl create token "${READ_SA}" -n "${NAMESPACE}" --duration=10m)

CODE=$(api_code GET /domains "${UNGRANTED}")
[[ "${CODE}" = "403" ]] \
  || fail "an authenticated account with no grant read the API (got ${CODE}); check the base path against system:discovery"
echo "OK: an authenticated identity without a grant is refused"

# ---------------------------------------------------------------------------
# 3. The granted identity can read what is being enforced
# ---------------------------------------------------------------------------
kubectl create sa "${RESET_SA}" -n "${NAMESPACE}" >/dev/null 2>&1 || true
kubectl create clusterrolebinding "${RESET_SA}" \
  --clusterrole="${OPERATOR_SVC}-operator" \
  --serviceaccount="${NAMESPACE}:${RESET_SA}" >/dev/null 2>&1 || true
TOKEN=$(kubectl create token "${RESET_SA}" -n "${NAMESPACE}" --duration=30m)

# RBAC caches a denial briefly, so the first call after the binding may still
# be refused.
for _ in $(seq 1 15); do
  CODE=$(api_code GET /domains "${TOKEN}")
  [[ "${CODE}" = "200" ]] && break
  sleep 2
done
[[ "${CODE}" = "200" ]] || fail "the granted account was refused (got ${CODE})"
echo "OK: the granted identity reads the domain list"

# ---------------------------------------------------------------------------
# 4. The rule listing describes a rule well enough to reset it
# ---------------------------------------------------------------------------
# The gateway is warmed before the policy exists: wait_for_gateway probes this
# very path, and every probe would come out of the budget counted below.
wait_for_gateway public-gateway "${PROBE_PATH}"

kubectl apply -f - >/dev/null <<EOF
apiVersion: ratelimit.netcracker.com/v1alpha1
kind: RateLimitPolicy
metadata:
  name: ${POLICY}
  namespace: ${NAMESPACE}
spec:
  domain: ${DOMAIN}
  limits:
    - name: probe
      target:
        routes:
          - path:
              type: Prefix
              value: ${PROBE_PATH}
      rules:
        - name: per-path
          counters: [path]
          rates:
            - requests: ${LIMIT}
              period: ${PERIOD}
              algorithm: FixedWindow
EOF
wait_for_domain "${DOMAIN}"

RULES=$(api GET "/domains/${DOMAIN}/rules" "${TOKEN}")
echo "${RULES}" | grep -q "\"id\":\"${RULE}\"" \
  || fail "the rule listing does not carry ${RULE}"
# The axis names, in key order, are what lets a client build a reset without
# knowing the counter key schema.
echo "${RULES}" | grep -q '"axes":\["path"\]' \
  || fail "the rule listing does not report the axis order of ${RULE}"
echo "OK: the rule listing reports ${RULE} and its axes"

CODE=$(api_code GET "/domains/gateway.typo/rules" "${TOKEN}")
[[ "${CODE}" = "404" ]] || fail "an unbound domain answered ${CODE}, expected 404"
echo "OK: an unbound domain is reported as not found"

# ---------------------------------------------------------------------------
# 5. Reading counters reports what the store would do, without charging
# ---------------------------------------------------------------------------
# Two paths, each spending its own budget, so the reset below has something to
# leave alone.
for path in "${PROBE_PATH}" "${OTHER_PATH}"; do
  for _ in $(seq 1 "${LIMIT}"); do
    curl_gw_code public-gateway "${path}" >/dev/null
  done
done

LIMITED=$(api GET "/domains/${DOMAIN}/counters?ruleId=${RULE}&limited=true" "${TOKEN}")
COUNT=$(echo "${LIMITED}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['items']))")
[[ "${COUNT}" = "2" ]] \
  || fail "expected both paths to be limited, the API reports ${COUNT}"
echo "${LIMITED}" | grep -q "\"path\":\"${PROBE_PATH}\"" \
  || fail "the counter listing does not report the axis value of ${PROBE_PATH}"
echo "OK: both spent budgets are reported as limited, by axis value"

# Reading must not charge, or an operator's own investigation becomes the cause
# of the refusal they were investigating.
for _ in $(seq 1 3); do
  api GET "/domains/${DOMAIN}/counters" "${TOKEN}" >/dev/null
done
AFTER=$(api GET "/domains/${DOMAIN}/counters?ruleId=${RULE}&limited=true" "${TOKEN}" \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)['items']))")
[[ "${AFTER}" = "2" ]] || fail "reading the counters changed them"
echo "OK: reading the counters charges nothing"

# ---------------------------------------------------------------------------
# 6. A reset lifts the limit, immediately, and only for the client named
# ---------------------------------------------------------------------------
RESET=$(api POST "/domains/${DOMAIN}/counters/reset" "${TOKEN}" \
  "{\"ruleId\":\"${RULE}\",\"axes\":{\"path\":\"${PROBE_PATH}\"}}")
RESET_COUNT=$(echo "${RESET}" | field resetCount)
[[ "${RESET_COUNT}" = "1" ]] \
  || fail "the reset reports ${RESET_COUNT} counters dropped, expected 1: ${RESET}"

CODE=$(curl_gw_code public-gateway "${PROBE_PATH}")
[[ "${CODE}" != "429" ]] \
  || fail "the reset path is still refused (got ${CODE}); the reset did not reach the counter store"
CODE=$(curl_gw_code public-gateway "${OTHER_PATH}")
[[ "${CODE}" = "429" ]] \
  || fail "the path that was not reset is admitted (got ${CODE}); the reset was too wide"
echo "OK: the reset admits ${PROBE_PATH} again and leaves ${OTHER_PATH} limited"

# ---------------------------------------------------------------------------
# 7. Every mutation names who made it
# ---------------------------------------------------------------------------
# Without this the endpoint is an unattributable way to turn a limit off.
SINCE=$(now_rfc3339)
api POST "/domains/${DOMAIN}/counters/reset" "${TOKEN}" \
  "{\"ruleId\":\"${RULE}\",\"axes\":{\"path\":\"${OTHER_PATH}\"}}" >/dev/null
sleep 2

AUDIT=$(operator_logs_since "${SINCE}" | grep -a "management mutation" | tail -1)
[[ -n "${AUDIT}" ]] || fail "the reset left no audit record in the operator log"
echo "${AUDIT}" | grep -q "system:serviceaccount:${NAMESPACE}:${RESET_SA}" \
  || fail "the audit record does not name the caller: ${AUDIT}"
echo "${AUDIT}" | grep -q "rule=${RULE}" \
  || fail "the audit record does not name the rule: ${AUDIT}"
echo "OK: the reset is audited under the caller's own name"

# ---------------------------------------------------------------------------
# 8. A reset that names a rule nobody is enforcing is refused
# ---------------------------------------------------------------------------
CODE=$(api_code POST "/domains/${DOMAIN}/counters/reset" "${TOKEN}" \
  "{\"ruleId\":\"${POLICY}/probe/typo\"}")
[[ "${CODE}" = "400" ]] || fail "a reset of an unknown rule answered ${CODE}, expected 400"

# An axis the rule does not count by is the other half of the same mistake.
CODE=$(api_code POST "/domains/${DOMAIN}/counters/reset" "${TOKEN}" \
  "{\"ruleId\":\"${RULE}\",\"axes\":{\"tenant\":\"acme\"}}")
[[ "${CODE}" = "400" ]] || fail "a reset naming an undeclared axis answered ${CODE}, expected 400"
echo "OK: a reset naming a rule or axis that does not exist is refused"

# ---------------------------------------------------------------------------
# 9. The decision audit stream is off until a rule is selected
# ---------------------------------------------------------------------------
# At gateway speed a record per decision is a firehose, so nothing streams until
# a rule is selected, and the selection is shared by every replica rather than
# held in one.
#
# That sharing is why the starting state is established rather than assumed: on
# a cluster somebody else is using, a rule may legitimately be streaming already.
# The shipped default is covered by a unit test; what matters here is that the
# switch works against a real API server.
AUDIT_BEFORE=$(api GET /audit "${TOKEN}" \
  | python3 -c "import json,sys; print(json.dumps({'rules': json.load(sys.stdin).get('rules', [])}))")
api PUT /audit "${TOKEN}" '{"rules":[]}' >/dev/null

SELECTED=$(api GET /audit "${TOKEN}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['rules']))")
[[ "${SELECTED}" = "0" ]] || fail "the stream is still on after clearing the selection"

api PUT /audit "${TOKEN}" \
  "{\"rules\":[{\"domain\":\"${DOMAIN}\",\"ruleId\":\"${RULE}\"}]}" >/dev/null
STORED=$(kubectl get configmap ratelimit-decision-audit -n "${NAMESPACE}" \
  -o jsonpath='{.data.selection\.json}' 2>/dev/null || true)
echo "${STORED}" | grep -q "${RULE}" \
  || fail "the selection was not persisted for the other replicas: ${STORED}"
echo "OK: selecting a rule is stored where every replica reads it"

CODE=$(api_code PUT /audit "${TOKEN}" \
  "{\"rules\":[{\"domain\":\"${DOMAIN}\",\"ruleId\":\"${POLICY}/probe/typo\"}]}")
[[ "${CODE}" = "400" ]] || fail "selecting a rule nobody enforces answered ${CODE}, expected 400"

api PUT /audit "${TOKEN}" '{"rules":[]}' >/dev/null
echo "OK: the selection is validated and can be turned back off"

# ---------------------------------------------------------------------------
# 10. Reading is not enough to change anything
# ---------------------------------------------------------------------------
# The split between the viewer and operator roles is the HTTP method, so a
# read-only grant has to fail on the mutation and nowhere else.
kubectl create clusterrolebinding "${READ_SA}" \
  --clusterrole="${OPERATOR_SVC}-viewer" \
  --serviceaccount="${NAMESPACE}:${READ_SA}" >/dev/null 2>&1 || true
VIEW_TOKEN=$(kubectl create token "${READ_SA}" -n "${NAMESPACE}" --duration=10m)

for _ in $(seq 1 15); do
  CODE=$(api_code GET /domains "${VIEW_TOKEN}")
  [[ "${CODE}" = "200" ]] && break
  sleep 2
done
[[ "${CODE}" = "200" ]] || fail "the viewer role cannot read (got ${CODE})"

CODE=$(api_code POST "/domains/${DOMAIN}/counters/reset" "${VIEW_TOKEN}" \
  "{\"ruleId\":\"${RULE}\"}")
[[ "${CODE}" = "403" ]] || fail "the viewer role reset a counter (got ${CODE}), expected 403"
kubectl delete clusterrolebinding "${READ_SA}" --ignore-not-found >/dev/null 2>&1 || true
echo "OK: the viewer role reads but cannot reset"
