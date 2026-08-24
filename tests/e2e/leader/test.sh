#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Leader election gates status writes and nothing else.
#
# The store updater and the gRPC endpoint report NeedLeaderElection() false, so
# every replica answers checks whether or not it holds the lease. Killing the
# leader must therefore not interrupt rate limiting — and the new leader must
# pick up status writes.
#
# This is the one property that cannot be seen with a single replica, so unlike
# the rest of the suite this test scales the release. It restores the original
# replica count on exit, through Helm: a kubectl scale would take field-manager
# ownership of .spec.replicas and make every later helm upgrade conflict.
# ---------------------------------------------------------------------------
set -eux

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

POLICY=e2e-leader
DOMAIN=gateway.public
PROBE_PATH=/e2e-leader

RELEASE=$(kubectl get deployment "${OPERATOR_SVC}" -n "${NAMESPACE}" \
  -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}')
[[ -n "${RELEASE}" ]] || fail "cannot determine the Helm release owning ${OPERATOR_SVC}"
CHART="${REPO_ROOT}/helm-templates/ratelimit"
ORIGINAL_REPLICAS=$(kubectl get deployment "${OPERATOR_SVC}" -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}')

cleanup() {
  kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --ignore-not-found
  helm upgrade "${RELEASE}" "${CHART}" -n "${NAMESPACE}" --reuse-values \
    --set "REPLICAS=${ORIGINAL_REPLICAS}" --wait --timeout 3m >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The lease holder is "<pod>_<uuid>"; only the pod part identifies the leader.
lease_holder_pod() {
  kubectl get lease ratelimit.netcracker.com -n "${NAMESPACE}" \
    -o jsonpath='{.spec.holderIdentity}' 2>/dev/null | cut -d_ -f1
}

# What this suite measures is whether every replica answers, not whether a limit
# bites, so its policy declares a limit far above any burst it sends. A clean
# burst is then one the gateway actually admitted: 2xx or 404 from the routed
# probe backend. 429 is a refusal, 000 a transport error, and 5xx a gateway
# answering on its own — none of them count, and a 429 here would mean the limit
# leaked into the measurement rather than the replicas failing. Passing traffic alone still cannot distinguish a healthy
# endpoint from one the gateway failed open around; the log detectors below
# supply that half of the proof.
burst_is_clean() {
  local codes
  codes=$(curl_gw_burst 4 public-gateway "${PROBE_PATH}")
  [[ -n "${codes}" ]] && ! echo "${codes}" | grep -qvE "^(2[0-9][0-9]|404)$"
}

# Greps every replica's log, not just one pod's: the follower is exactly the
# replica an empty-store bug would live in.
unknown_domain_logged() {
  local since="$1" pod
  for pod in $(kubectl get pods -n "${NAMESPACE}" \
      -l "app.kubernetes.io/instance=${RELEASE}" -o name); do
    if kubectl logs -n "${NAMESPACE}" "${pod}" --since-time="${since}" 2>/dev/null \
        | grep -q "unknown rate limit domain"; then
      return 0
    fi
  done
  return 1
}

# Every replica must log its own rebuild: the updater runs outside leader
# election, and a follower without this line is exactly the leader-only-store
# bug. Traffic cannot prove this — the gateway multiplexes checks over one
# gRPC connection, so one replica may legitimately serve them all.
replicas_rebuilt() {
  local pod
  for pod in $(kubectl get pods -n "${NAMESPACE}" \
      -l "app.kubernetes.io/instance=${RELEASE}" -o name); do
    kubectl logs -n "${NAMESPACE}" "${pod}" 2>/dev/null \
      | grep -q "rate limit store rebuilt" || return 1
  done
  return 0
}

# Counts the per-check Debug lines across every replica: direct proof the
# checks reached the operator instead of being failed open around it.
checks_logged_since() {
  local since="$1" total=0 pod count
  for pod in $(kubectl get pods -n "${NAMESPACE}" \
      -l "app.kubernetes.io/instance=${RELEASE}" -o name); do
    count=$(kubectl logs -n "${NAMESPACE}" "${pod}" --since-time="${since}" 2>/dev/null \
      | grep -c "rate limit check") || count=0
    total=$((total + count))
  done
  echo "${total}"
}

# One thousand a minute: far enough above a burst of four that a refusal here is
# a fault rather than the limit doing its job.
apply_policy "${POLICY}" "${DOMAIN}" 1000 1m

# ---------------------------------------------------------------------------
# 1. Two replicas, one leader
# ---------------------------------------------------------------------------
helm upgrade "${RELEASE}" "${CHART}" -n "${NAMESPACE}" --reuse-values \
  --set REPLICAS=2 --wait --timeout 3m >/dev/null
kubectl rollout status "deployment/${OPERATOR_SVC}" -n "${NAMESPACE}" --timeout=120s

READY=$(kubectl get deployment "${OPERATOR_SVC}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}')
[[ "${READY}" = "2" ]] || fail "expected 2 ready replicas, got '${READY}'"
echo "OK: two replicas are ready"

# The burst assertions measure the operator, so the gateway must be past its
# own startup first.
wait_for_gateway public-gateway "${PROBE_PATH}"

REBUILT=""
for _ in $(seq 1 10); do
  if replicas_rebuilt; then
    REBUILT=yes
    break
  fi
  sleep 2
done
[[ -n "${REBUILT}" ]] || fail "a replica never rebuilt its rule store; the updater is leader-gated"
echo "OK: every replica rebuilt its rule store"

LEADER=""
for _ in $(seq 1 20); do
  LEADER=$(lease_holder_pod)
  [[ -n "${LEADER}" ]] && break
  sleep 3
done
[[ -n "${LEADER}" ]] || fail "no leader acquired the lease"
kubectl get pod "${LEADER}" -n "${NAMESPACE}" >/dev/null \
  || fail "the lease names a pod that does not exist: ${LEADER}"
echo "OK: one replica holds the lease (${LEADER})"

# ---------------------------------------------------------------------------
# 2. Both replicas answer checks, not just the leader
# ---------------------------------------------------------------------------
# Every pod serves the Service. A store filled only on the leader betrays
# itself in the follower's log: a replica with an empty store reports
# "unknown rate limit domain" on every check it serves.
SINCE=$(now_rfc3339)
sleep 1
for attempt in $(seq 1 4); do
  burst_is_clean || fail "burst ${attempt} was refused or failed under a limit far above it"
  sleep 1.2
done
CHECKS=$(checks_logged_since "${SINCE}")
[[ "${CHECKS}" -ge 4 ]] || fail "only ${CHECKS} checks reached the operator; the traffic bypassed it"
if unknown_domain_logged "${SINCE}"; then
  fail "a replica answered from an empty store: 'unknown rate limit domain' logged"
fi
echo "OK: every replica answers from a populated store (${CHECKS} checks logged)"

# ---------------------------------------------------------------------------
# 3. Killing the leader does not stop the checks
# ---------------------------------------------------------------------------
SINCE=$(now_rfc3339)
sleep 1
kubectl delete pod "${LEADER}" -n "${NAMESPACE}" --wait=false

CLEAN=0
for _ in $(seq 1 8); do
  if burst_is_clean; then
    CLEAN=$((CLEAN + 1))
  fi
  sleep 1.2
done
# Some requests land on the pod that is going away and are failed open by the
# gateway, so the occasional dirty burst is expected; what must not happen is
# the checks stopping altogether.
if [[ "${CLEAN}" -lt 6 ]]; then
  fail "checks degraded while the leader was replaced (${CLEAN}/8 clean bursts)"
fi
CHECKS=$(checks_logged_since "${SINCE}")
[[ "${CHECKS}" -ge 8 ]] || fail "only ${CHECKS} checks reached the operator during the handover"
if unknown_domain_logged "${SINCE}"; then
  fail "a replica answered from an empty store during the handover"
fi
echo "OK: checks continue while the leader is replaced (${CLEAN}/8 clean bursts, ${CHECKS} checks logged)"

# ---------------------------------------------------------------------------
# 4. The lease moves to the surviving replica
# ---------------------------------------------------------------------------
NEW_LEADER=""
for _ in $(seq 1 30); do
  NEW_LEADER=$(lease_holder_pod)
  [[ -n "${NEW_LEADER}" ]] && [[ "${NEW_LEADER}" != "${LEADER}" ]] && break
  sleep 3
done
if [[ -z "${NEW_LEADER}" ]] || [[ "${NEW_LEADER}" = "${LEADER}" ]]; then
  fail "the lease did not move off the killed leader (still '${NEW_LEADER}')"
fi
echo "OK: the lease moved to ${NEW_LEADER}"

# ---------------------------------------------------------------------------
# 5. The new leader writes status
# ---------------------------------------------------------------------------
# Status is the only leader-gated work, so a handover that leaves nobody writing
# it would strand every policy without an Accepted condition.
kubectl patch ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --type=merge \
  -p "{\"spec\":{\"domain\":\"${DOMAIN}\"}}" >/dev/null
kubectl annotate ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" \
  e2e.ratelimit/rotated="$(date +%s)" --overwrite >/dev/null

ACCEPTED=""
for _ in $(seq 1 24); do
  ACCEPTED=$(policy_condition "${POLICY}")
  [[ "${ACCEPTED}" = "True" ]] && break
  sleep 5
done
[[ "${ACCEPTED}" = "True" ]] || fail "the new leader did not accept a policy after the handover"

GENERATION=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
OBSERVED=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.status.observedGeneration}')
[[ "${OBSERVED}" = "${GENERATION}" ]] \
  || fail "observedGeneration ${OBSERVED} does not match generation ${GENERATION} after the handover"
echo "OK: the new leader writes policy status"
