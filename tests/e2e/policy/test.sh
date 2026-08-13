#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# The CR contract: what the API server accepts, what the reconciler writes back,
# and what the store does when a policy comes and goes.
#
# The envtest suite covers the reconciler against a real API server already.
# What only a cluster can show is the other half — that a policy event actually
# reaches the store in the running pod.
# ---------------------------------------------------------------------------
set -eux

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

POLICY=e2e-policy
DOMAIN=gateway.e2e

cleanup() {
  kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --ignore-not-found
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. The CRD rejects a policy with no domain
# ---------------------------------------------------------------------------
# spec.domain is required with MinLength=1, so this is refused by the API
# server, not by the operator. A cluster without the CRD's validation would let
# it through and the operator would silently index an empty domain.
if kubectl apply --dry-run=server -f - <<EOF >/dev/null 2>&1
apiVersion: ratelimit.netcracker.com/v1alpha1
kind: RateLimitPolicy
metadata:
  name: ${POLICY}-invalid
  namespace: ${NAMESPACE}
spec:
  domain: ""
EOF
then
  fail "an empty spec.domain was accepted; the CRD validation is missing"
fi
echo "OK: the CRD rejects an empty spec.domain"

# ---------------------------------------------------------------------------
# 2. A valid policy is accepted by the reconciler
# ---------------------------------------------------------------------------
apply_policy "${POLICY}" "${DOMAIN}"

ACCEPTED=""
for i in $(seq 1 24); do
  ACCEPTED=$(policy_condition "${POLICY}")
  [ "${ACCEPTED}" = "True" ] && break
  echo "Waiting for the policy to be accepted (attempt ${i}/24)..."
  sleep 5
done
if [ "${ACCEPTED}" != "True" ]; then
  kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o yaml
  fail "policy not accepted; is a reconciler holding the lease?"
fi
echo "OK: the reconciler accepts a policy"

# observedGeneration proves the status was written for the spec that exists now,
# not left over from an earlier generation.
GENERATION=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
OBSERVED=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.status.observedGeneration}')
if [ "${OBSERVED}" != "${GENERATION}" ]; then
  fail "observedGeneration ${OBSERVED} does not match generation ${GENERATION}"
fi
echo "OK: status tracks the current generation"

# ---------------------------------------------------------------------------
# 3. kubectl shows the binding, which is the point of the print columns
# ---------------------------------------------------------------------------
COLUMNS=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --no-headers)
echo "${COLUMNS}" | grep -q "${DOMAIN}" \
  || fail "kubectl output does not show the domain: ${COLUMNS}"
echo "${COLUMNS}" | grep -q "True" \
  || fail "kubectl output does not show the Accepted status: ${COLUMNS}"
echo "OK: kubectl get shows DOMAIN and ACCEPTED"

# ---------------------------------------------------------------------------
# 4. Deleting a policy rebuilds the store in the running pod
# ---------------------------------------------------------------------------
# This is the half envtest cannot reach: the store updater subscribes to the
# informer directly, so the only proof it saw the event is the pod's own log.
SINCE=$(now_rfc3339)
sleep 1
kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}"

REBUILT=""
for i in $(seq 1 15); do
  REBUILT=$(operator_logs_since "${SINCE}" | grep "rate limit store rebuilt" || true)
  [ -n "${REBUILT}" ] && break
  sleep 2
done
if [ -z "${REBUILT}" ]; then
  fail "no store rebuild logged after the policy was deleted"
fi
echo "OK: deleting a policy rebuilds the store (${REBUILT##*] })"
