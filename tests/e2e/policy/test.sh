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
  kubectl delete ratelimitpolicy "${POLICY}" "${POLICY}-dead-rule" \
    -n "${NAMESPACE}" --ignore-not-found
  kubectl delete ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" --ignore-not-found
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. The CRD validation is installed
# ---------------------------------------------------------------------------
# The envtest suite covers each rule; what a cluster adds is the proof that the
# CRD carrying them is the one installed here. A cluster with an older CRD would
# accept every spec below and the operator would compile nonsense.
reject() {
  local case="$1" spec="$2"
  if kubectl apply --dry-run=server -f - <<EOF >/dev/null 2>&1
apiVersion: ratelimit.netcracker.com/v1alpha1
kind: RateLimitPolicy
metadata:
  name: ${POLICY}-invalid
  namespace: ${NAMESPACE}
spec:
${spec}
EOF
  then
    fail "the installed CRD accepted ${case}"
  fi
  echo "OK: the CRD rejects ${case}"
}

reject "an empty spec.domain" '  domain: ""
  limits:
    - name: api
      rules:
        - name: total
          rates: [{requests: 1, period: 1s}]'

reject "a policy with no blocks" "  domain: ${DOMAIN}"

reject "a path predicate in when" "  domain: ${DOMAIN}
  limits:
    - name: api
      rules:
        - name: total
          when: [{key: path, operator: Exists}]
          rates: [{requests: 1, period: 1s}]"

reject "a period above one day" "  domain: ${DOMAIN}
  limits:
    - name: api
      rules:
        - name: total
          rates: [{requests: 1, period: 2d}]"

reject "burst on a fixed window" "  domain: ${DOMAIN}
  limits:
    - name: api
      rules:
        - name: total
          rates: [{requests: 10, period: 1m, burst: 5, algorithm: FixedWindow}]"

# ---------------------------------------------------------------------------
# 2. A valid policy is accepted by the reconciler
# ---------------------------------------------------------------------------
apply_policy "${POLICY}" "${DOMAIN}"

ACCEPTED=""
for i in $(seq 1 24); do
  ACCEPTED=$(policy_condition "${POLICY}")
  [[ "${ACCEPTED}" = "True" ]] && break
  echo "Waiting for the policy to be accepted (attempt ${i}/24)..."
  sleep 5
done
if [[ "${ACCEPTED}" != "True" ]]; then
  kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o yaml
  fail "policy not accepted; is a reconciler holding the lease?"
fi
echo "OK: the reconciler accepts a policy"

# observedGeneration proves the status was written for the spec that exists now,
# not left over from an earlier generation.
GENERATION=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
OBSERVED=$(kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o jsonpath='{.status.observedGeneration}')
if [[ "${OBSERVED}" != "${GENERATION}" ]]; then
  fail "observedGeneration ${OBSERVED} does not match generation ${GENERATION}"
fi
echo "OK: status tracks the current generation"

READY=$(policy_condition "${POLICY}" Ready)
if [[ "${READY}" != "True" ]]; then
  kubectl get ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" -o yaml
  fail "the policy compiled but is not Ready"
fi
echo "OK: the reconciler reports the snapshot as applied"

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
# 4. A rule nothing can produce a key for is reported, not enforced
# ---------------------------------------------------------------------------
# A typo in a key has to give a rule that does nothing. The status is where that
# becomes visible, and the mapping is what revives it.
kubectl apply -f - <<EOF
apiVersion: ratelimit.netcracker.com/v1alpha1
kind: RateLimitPolicy
metadata:
  name: ${POLICY}-dead-rule
  namespace: ${NAMESPACE}
spec:
  domain: ${DOMAIN}
  limits:
    - name: api
      rules:
        - name: per-tenant
          when: [{key: tenant, operator: Exists}]
          rates: [{requests: 10, period: 1m}]
EOF

PROBLEM=""
for i in $(seq 1 20); do
  PROBLEM=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
    -o jsonpath='{.status.ruleProblems[0].reason}' 2>/dev/null || true)
  [[ -n "${PROBLEM}" ]] && break
  sleep 3
done
if [[ "${PROBLEM}" != "UnresolvedKeyReference" ]]; then
  kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" -o yaml
  fail "expected UnresolvedKeyReference in ruleProblems, got '${PROBLEM}'"
fi
echo "OK: a rule referencing an unknown key is reported as a problem"

# A blocking problem invalidates the whole generation: enforced as written or not
# at all. Ready has to say so, and nothing may be active.
if [[ "$(policy_condition "${POLICY}-dead-rule" Ready)" != "False" ]]; then
  fail "a blocking problem left Ready true; the generation must not be enforced"
fi
ACTIVE=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
  -o jsonpath='{.status.activeGeneration}' 2>/dev/null || true)
if [[ -n "${ACTIVE}" ]] && [[ "${ACTIVE}" != "0" ]]; then
  fail "activeGeneration is ${ACTIVE}; a policy with no valid generation enforces nothing"
fi
echo "OK: a blocking problem keeps the whole generation out"

# ---------------------------------------------------------------------------
# 5. A mapping revives the rule that referenced its key
# ---------------------------------------------------------------------------
apply_mapping "${DOMAIN}"

KEYS=""
for i in $(seq 1 20); do
  KEYS=$(kubectl get ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" \
    -o jsonpath='{.status.effectiveKeys}' 2>/dev/null || true)
  echo "${KEYS}" | grep -q tenant && break
  sleep 3
done
echo "${KEYS}" | grep -q tenant \
  || fail "the mapping did not publish tenant in status.effectiveKeys (got: ${KEYS})"
echo "OK: the mapping publishes its effective keys"

REVIVED=""
for i in $(seq 1 20); do
  REVIVED=$(policy_condition "${POLICY}-dead-rule" Ready)
  [[ "${REVIVED}" = "True" ]] && break
  sleep 3
done
if [[ "${REVIVED}" != "True" ]]; then
  kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" -o yaml
  fail "the policy stayed invalid after the mapping appeared; the mapping watch is not wired"
fi
echo "OK: adding a mapping revives the policy that referenced its key"

# ---------------------------------------------------------------------------
# 6. The last-good generation keeps running when an edit is invalid
# ---------------------------------------------------------------------------
# This is the half a unit test cannot show: the state survives in a ConfigMap, so
# the generation being enforced outlives the edit that broke it.
#
# The wait is the point of the step, not ceremony around it: breaking the policy
# before its good generation reaches the ConfigMap would leave nothing to fall
# back to, and the test would be asserting on a race rather than on the feature.
wait_for_state "${DOMAIN}"
echo "OK: the good generation reached ratelimit-state-${DOMAIN}"

# The ConfigMap existing is not the precondition this step needs. It can be left
# over from an earlier run — the operator only drops the state of a retired
# domain on a replica that persisted it, so a leader handover strands one — and
# waiting on a stale object means breaking the policy before its own good
# generation was ever recorded. The object's status is the precise signal: a
# generation is active once activeGeneration has caught up with observedGeneration.
GOOD=""
for i in $(seq 1 20); do
  GOOD=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
    -o jsonpath='{.status.activeGeneration}' 2>/dev/null || true)
  SEEN=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
    -o jsonpath='{.status.observedGeneration}' 2>/dev/null || true)
  [[ -n "${GOOD}" ]] && [[ "${GOOD}" != "0" ]] && [[ "${GOOD}" = "${SEEN}" ]] && break
  sleep 3
done
[[ -n "${GOOD}" ]] && [[ "${GOOD}" != "0" ]] && [[ "${GOOD}" = "${SEEN}" ]] \
  || fail "the policy never reached an active generation to fall back to (observed=${SEEN}, active=${GOOD})"
echo "OK: generation ${GOOD} is active and can be fallen back to"

kubectl patch ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" --type=merge -p \
  '{"spec":{"limits":[{"name":"api","rules":[{"name":"per-plan","when":[{"key":"plan","operator":"Exists"}],"rates":[{"requests":10,"period":"1m"}]}]}]}}'

STUCK=""
for i in $(seq 1 20); do
  STUCK=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
    -o jsonpath='{.status.activeGeneration}' 2>/dev/null || true)
  OBSERVED=$(kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" \
    -o jsonpath='{.status.observedGeneration}' 2>/dev/null || true)
  [[ -n "${STUCK}" ]] && [[ "${STUCK}" != "0" ]] && [[ "${STUCK}" != "${OBSERVED}" ]] && break
  sleep 3
done
if [[ -z "${STUCK}" ]] || [[ "${STUCK}" = "0" ]] || [[ "${STUCK}" = "${OBSERVED}" ]]; then
  kubectl get ratelimitpolicy "${POLICY}-dead-rule" -n "${NAMESPACE}" -o yaml
  fail "expected an earlier generation to stay active (observed=${OBSERVED}, active=${STUCK})"
fi
echo "OK: generation ${STUCK} keeps running while generation ${OBSERVED} is rejected"

# ---------------------------------------------------------------------------
# 7. A mapping that would stop running rules is vetoed
# ---------------------------------------------------------------------------
# The gate protects policies from the mapping. Dropping the key the running rule
# depends on has to be refused, with the culprit named.
kubectl patch ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" --type=merge -p \
  '{"spec":{"mappings":[{"key":"region","claim":"region"}]}}'

VETOED=""
for i in $(seq 1 20); do
  VETOED=$(kubectl get ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" \
    -o jsonpath='{.status.rejectedBy[0].policy}' 2>/dev/null || true)
  [[ -n "${VETOED}" ]] && break
  sleep 3
done
if [[ -z "${VETOED}" ]]; then
  kubectl get ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" -o yaml
  fail "the mapping change was accepted even though it would stop a running rule"
fi
MAPPING_READY=$(kubectl get ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}')
if [[ "${MAPPING_READY}" != "RejectedByPolicies" ]]; then
  fail "expected Ready reason RejectedByPolicies, got '${MAPPING_READY}'"
fi
kubectl get ratelimitmapping "${DOMAIN}" -n "${NAMESPACE}" \
  -o jsonpath='{.status.effectiveKeys}' | grep -q tenant \
  || fail "effectiveKeys must report the active generation, which still declares tenant"
echo "OK: the gate vetoed the mapping and named ${VETOED}"

# ---------------------------------------------------------------------------
# 8. Deleting a policy rebuilds the store in the running pod
# ---------------------------------------------------------------------------
# This is the half envtest cannot reach: the store updater subscribes to the
# informer directly, so the only proof it saw the event is the pod's own log.
SINCE=$(now_rfc3339)
sleep 1
kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}"

REBUILT=""
for i in $(seq 1 15); do
  REBUILT=$(operator_logs_since "${SINCE}" | grep "rate limit store rebuilt" || true)
  [[ -n "${REBUILT}" ]] && break
  sleep 2
done
if [[ -z "${REBUILT}" ]]; then
  fail "no store rebuild logged after the policy was deleted"
fi
echo "OK: deleting a policy rebuilds the store (${REBUILT##*] })"
