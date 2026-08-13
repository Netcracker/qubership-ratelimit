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
[ -n "${RELEASE}" ] || fail "cannot determine the Helm release owning ${OPERATOR_SVC}"
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

# A burst that contains a 429 proves the endpoint answered: with failClosed
# false an unreachable operator would let every request through instead, so the
# absence of 429 is exactly how an outage would look here.
burst_has_429() {
  curl_gw_burst 4 public-gateway "${PROBE_PATH}" | grep -q 429
}

apply_policy "${POLICY}" "${DOMAIN}"

# ---------------------------------------------------------------------------
# 1. Two replicas, one leader
# ---------------------------------------------------------------------------
helm upgrade "${RELEASE}" "${CHART}" -n "${NAMESPACE}" --reuse-values \
  --set REPLICAS=2 --wait --timeout 3m >/dev/null
kubectl rollout status "deployment/${OPERATOR_SVC}" -n "${NAMESPACE}" --timeout=120s

READY=$(kubectl get deployment "${OPERATOR_SVC}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}')
[ "${READY}" = "2" ] || fail "expected 2 ready replicas, got '${READY}'"
echo "OK: two replicas are ready"

LEADER=""
for _ in $(seq 1 20); do
  LEADER=$(lease_holder_pod)
  [ -n "${LEADER}" ] && break
  sleep 3
done
[ -n "${LEADER}" ] || fail "no leader acquired the lease"
kubectl get pod "${LEADER}" -n "${NAMESPACE}" >/dev/null \
  || fail "the lease names a pod that does not exist: ${LEADER}"
echo "OK: one replica holds the lease (${LEADER})"

# ---------------------------------------------------------------------------
# 2. Both replicas answer checks, not just the leader
# ---------------------------------------------------------------------------
# Every pod serves the Service, so a burst reaching either of them must still be
# limited. A store filled only on the leader would show up as bursts that pass
# unlimited whenever they land on the follower.
for attempt in $(seq 1 4); do
  burst_has_429 || fail "burst ${attempt} was not limited; a replica is answering from an empty store"
  sleep 1.2
done
echo "OK: bursts are limited regardless of which replica serves them"

# ---------------------------------------------------------------------------
# 3. Killing the leader does not stop rate limiting
# ---------------------------------------------------------------------------
kubectl delete pod "${LEADER}" -n "${NAMESPACE}" --wait=false

LIMITED=0
for _ in $(seq 1 8); do
  if burst_has_429; then
    LIMITED=$((LIMITED + 1))
  fi
  sleep 1.2
done
# Some requests land on the pod that is going away and are failed open by the
# gateway, so not every burst is guaranteed to be limited; what must not happen
# is rate limiting stopping altogether.
if [ "${LIMITED}" -lt 6 ]; then
  fail "rate limiting stopped while the leader was replaced (${LIMITED}/8 bursts limited)"
fi
echo "OK: rate limiting continues while the leader is replaced (${LIMITED}/8 bursts limited)"

# ---------------------------------------------------------------------------
# 4. The lease moves to the surviving replica
# ---------------------------------------------------------------------------
NEW_LEADER=""
for _ in $(seq 1 30); do
  NEW_LEADER=$(lease_holder_pod)
  [ -n "${NEW_LEADER}" ] && [ "${NEW_LEADER}" != "${LEADER}" ] && break
  sleep 3
done
if [ -z "${NEW_LEADER}" ] || [ "${NEW_LEADER}" = "${LEADER}" ]; then
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
  [ "${ACCEPTED}" = "True" ] && break
  sleep 5
done
[ "${ACCEPTED}" = "True" ] || fail "the new leader did not accept a policy after the handover"

GENERATION=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
OBSERVED=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.status.observedGeneration}')
[ "${OBSERVED}" = "${GENERATION}" ] \
  || fail "observedGeneration ${OBSERVED} does not match generation ${GENERATION} after the handover"
echo "OK: the new leader writes policy status"
