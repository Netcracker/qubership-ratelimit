#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Shared helpers. Sourced — not executed — by each test's test.sh.
#
# The runner (test-suite.sh) exports NAMESPACE, HELM_RELEASE, CHART_PATH and
# the fail() function.
# ---------------------------------------------------------------------------

# Name of the running operator pod. Filtered to Running so a terminating pod
# from a previous rollout is never picked.
operator_pod() {
  kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=ratelimit \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}'
}

# Log lines the operator wrote after the given RFC3339 timestamp. Every
# assertion on logs uses a window opened before the traffic it is about, so a
# line left by an earlier test cannot satisfy it.
operator_logs_since() {
  local since="$1"
  kubectl logs -n "${NAMESPACE}" "$(operator_pod)" --since-time="${since}" 2>/dev/null
}

now_rfc3339() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

# One request through a gateway, printing only the HTTP status code. A fresh
# port-forward per call keeps each request on its own connection.
curl_gw_code() {
  local gateway="${1:-public-gateway}" path="${2:-/e2e}" extra_header="${3:-}"
  local port=18099
  kubectl port-forward -n "${NAMESPACE}" "svc/${gateway}-istio" "${port}:8080" >/dev/null 2>&1 &
  local pf_pid=$!
  sleep 2
  local code
  if [ -n "${extra_header}" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -H "${extra_header}" "http://127.0.0.1:${port}${path}" || echo "000")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://127.0.0.1:${port}${path}" || echo "000")
  fi
  kill "${pf_pid}" 2>/dev/null || true
  wait "${pf_pid}" 2>/dev/null || true
  echo "${code}"
}

# Sends n requests over one port-forward and prints one status code per line.
# Needed for the limit assertions: separate port-forwards add ~2s each, which
# would let a one-second window refill between requests.
#
# The header is passed through verbatim, so a caller asserting on a value it
# sent can match it exactly.
curl_gw_burst() {
  local count="$1" gateway="${2:-public-gateway}" path="${3:-/e2e}" header="${4:-}"
  local port=18099
  kubectl port-forward -n "${NAMESPACE}" "svc/${gateway}-istio" "${port}:8080" >/dev/null 2>&1 &
  local pf_pid=$!
  sleep 3
  local i
  for i in $(seq 1 "${count}"); do
    if [ -n "${header}" ]; then
      curl -s -o /dev/null -w '%{http_code}\n' -m 10 -H "${header}" "http://127.0.0.1:${port}${path}" || echo "000"
    else
      curl -s -o /dev/null -w '%{http_code}\n' -m 10 "http://127.0.0.1:${port}${path}" || echo "000"
    fi
  done
  kill "${pf_pid}" 2>/dev/null || true
  wait "${pf_pid}" 2>/dev/null || true
}

# Waits until the operator has a policy bound to the domain, so traffic
# assertions do not race the store rebuild (debounced ~200ms after the event).
wait_for_domain() {
  local domain="$1" since
  since=$(now_rfc3339)
  local i
  for i in $(seq 1 20); do
    if operator_logs_since "${since}" | grep -q "rate limit store rebuilt"; then
      return 0
    fi
    sleep 2
  done
  # A rebuild may simply have happened before the window opened; fall back to
  # asking the API server whether the policy is there at all.
  kubectl get ratelimitpolicies -n "${NAMESPACE}" -o jsonpath='{.items[*].spec.domain}' \
    | grep -q "${domain}"
}

apply_policy() {
  local name="$1" domain="$2"
  kubectl apply -f - <<EOF
apiVersion: ratelimit.netcracker.com/v1alpha1
kind: RateLimitPolicy
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
spec:
  domain: ${domain}
EOF
}

policy_condition() {
  local name="$1"
  kubectl get ratelimitpolicy "${name}" -n "${NAMESPACE}" \
    -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null
}
