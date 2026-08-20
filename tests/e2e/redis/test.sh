#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# The shared counter store.
#
# Everything here is a property the in-process store cannot have, which is the
# only reason this suite exists: that the operator really selected Redis rather
# than falling back to memory, that the counters live in Redis under the
# documented key shape, and — the one that matters — that a budget already spent
# survives the process that spent it.
#
# The release decides whether this runs. An install without redis.addresses is a
# perfectly good install, so this suite skips rather than fails on one.
# ---------------------------------------------------------------------------
set -eu

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

# The counter key carries the policy name, and a counter outlives the object that
# declared it — that is the property this suite exists to prove. So each run takes
# a name of its own; reusing one would inherit the previous run's spent budget and
# fail on its first request.
POLICY="e2e-redis-$(date +%s)"
DOMAIN=gateway.public
PROBE_PATH=/e2e-ratelimit

# An hour, not a minute: the windows are aligned to the clock, and a restart that
# happened to straddle a minute boundary would reset the budget and make the
# survival check below look like a failure of Redis rather than of arithmetic.
LIMIT=2
PERIOD=1h

cleanup() {
  kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Does this release run on Redis at all?
# ---------------------------------------------------------------------------
REDIS_ADDRESSES=$(kubectl get deployment "${OPERATOR_SVC}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="REDIS_ADDRESSES")].value}' 2>/dev/null || true)

if [[ -z "${REDIS_ADDRESSES}" ]]; then
  echo "SKIP: the release carries no redis.addresses, so it counts in process"
  exit 0
fi
echo "OK: the release is configured for Redis at ${REDIS_ADDRESSES}"

# redis_cli runs a command against the store the operator was pointed at. The pod
# is resolved through the Service the operator dials, so the suite works against
# any Redis the release names rather than one it hardcodes.
redis_cli() {
  local host selector pod
  host="${REDIS_ADDRESSES%%:*}"
  host="${host%%,*}"
  # The braces below are Go template syntax, not shell expansion.
  # shellcheck disable=SC2016
  selector=$(kubectl get svc "${host}" -n "${NAMESPACE}" \
    -o go-template='{{range $k, $v := .spec.selector}}{{$k}}={{$v}},{{end}}' 2>/dev/null || true)
  selector="${selector%,}"
  [[ -n "${selector}" ]] || return 1
  pod=$(kubectl get pods -n "${NAMESPACE}" -l "${selector}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [[ -n "${pod}" ]] || return 1
  kubectl exec -n "${NAMESPACE}" "${pod}" -- redis-cli "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 1. The operator selected Redis rather than falling back
# ---------------------------------------------------------------------------
# A wrong address, an unreachable host or a typo in the values would leave the
# operator counting in memory, and every limit would still look enforced on one
# replica. The startup line is what tells the two apart.
BACKEND=""
for pod in $(kubectl get pods -n "${NAMESPACE}" \
    -l "app.kubernetes.io/name=ratelimit" --field-selector=status.phase=Running -o name); do
  BACKEND=$(kubectl logs -n "${NAMESPACE}" "${pod}" 2>/dev/null \
    | grep -o 'counter store selected backend=.*' | tail -1)
  [[ -n "${BACKEND}" ]] && break
done
[[ "${BACKEND}" == *redis* ]] \
  || fail "the operator did not select the Redis store (startup said: ${BACKEND:-nothing})"
echo "OK: ${BACKEND}"

# ---------------------------------------------------------------------------
# 2. A declared limit is enforced through the shared store
# ---------------------------------------------------------------------------
# The gateway is warmed before the policy exists, not after: wait_for_gateway
# probes this very path, and every probe would come out of the budget this test
# is about to count.
wait_for_gateway public-gateway "${PROBE_PATH}"
apply_policy "${POLICY}" "${DOMAIN}" "${LIMIT}" "${PERIOD}"
wait_for_domain "${DOMAIN}"

# The budget is spent deliberately, one request at a time, so the count in Redis
# is a number this test chose rather than whatever a burst happened to land.
for i in $(seq 1 "${LIMIT}"); do
  CODE=$(curl_gw_code public-gateway "${PROBE_PATH}")
  [[ "${CODE}" != "429" ]] \
    || fail "request ${i} of the budget was refused (got ${CODE}); another policy is limiting this path"
done
CODE=$(curl_gw_code public-gateway "${PROBE_PATH}")
[[ "${CODE}" == "429" ]] \
  || fail "the request after the budget was admitted (got ${CODE}); the limit is not being enforced"
echo "OK: ${LIMIT} admitted, the next refused"

# ---------------------------------------------------------------------------
# 3. The counter is in Redis, under the documented key
# ---------------------------------------------------------------------------
# The key carries the policy, block and rule so two policies naming one block
# cannot share a bucket, and the domain sits in a hash tag so every bucket of one
# decision lands on a single Cluster slot.
KEY=""
if KEYS=$(redis_cli --scan --pattern "rl:*${POLICY}*"); then
  KEY=$(echo "${KEYS}" | grep . | head -1)
  [[ -n "${KEY}" ]] || fail "no counter key for ${POLICY} in Redis"
  echo "${KEY}" | grep -q "{${DOMAIN}}" \
    || fail "the key carries no hash tag for the domain: ${KEY}"
  echo "${KEY}" | grep -q "${POLICY}/everything/total" \
    || fail "the key does not carry the policy, block and rule: ${KEY}"
  echo "OK: ${KEY}"
else
  echo "OK: skipping the key inspection, no redis-cli reachable through ${REDIS_ADDRESSES}"
fi

# ---------------------------------------------------------------------------
# 4. A spent budget outlives the process that spent it
# ---------------------------------------------------------------------------
# This is the whole point of the shared store. An in-process counter is lost with
# its pod, so the budget would come back; with Redis the refusal has to survive a
# restart, and the window is an hour so the clock cannot hand it back either.
kubectl delete pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=ratelimit" --wait=false >/dev/null
kubectl rollout status "deployment/${OPERATOR_SVC}" -n "${NAMESPACE}" --timeout=180s >/dev/null \
  || fail "the operator did not come back after the restart"

# Only the store has to be back, and it is waited for through the rebuild it
# logs. Probing the gateway here would be worse than useless: the budget is spent,
# so every probe answers 429 and a warm-up that insists on 2xx would never finish.
wait_for_domain "${DOMAIN}"

CODE=$(curl_gw_code public-gateway "${PROBE_PATH}")
[[ "${CODE}" == "429" ]] \
  || fail "the budget came back after a restart (got ${CODE}); the counters did not outlive the process"
echo "OK: the spent budget survived an operator restart"
