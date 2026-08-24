#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# The Prometheus metrics endpoint.
#
# The series asserted here are the contract the dashboard and the alerts are
# built on: a renamed metric or label would ship a dashboard full of empty
# panels, and this test is where that breaks first. Traffic may land on any
# replica, so every assertion runs against the union of all scrapes.
# ---------------------------------------------------------------------------
set -eu

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

POLICY="e2e-metrics-$(date +%s)"
DOMAIN=gateway.public
PROBE_PATH=/e2e-ratelimit
RULE="${POLICY}/probe/per-path"
LIMIT=2
PORT=18090

cleanup() {
  kubectl delete ratelimitpolicy "${POLICY}" -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1 || true
  if [ -n "${PF_PID:-}" ]; then
    kill "${PF_PID}" 2>/dev/null || true
    wait "${PF_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. A limit, and traffic that spends it
# ---------------------------------------------------------------------------
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
              period: 1h
              algorithm: FixedWindow
EOF
wait_for_domain "${DOMAIN}"

WINDOW=$(now_rfc3339)
CODES=$(curl_gw_burst $((LIMIT + 2)) public-gateway "${PROBE_PATH}")
echo "${CODES}" | grep -q "429" || fail "the burst never hit the limit; codes: ${CODES}"

# ---------------------------------------------------------------------------
# 2. Scrape every replica
# ---------------------------------------------------------------------------
SCRAPE=""
for pod in $(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=ratelimit \
    --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  METRICS_PORT=$(kubectl get pod "${pod}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.containers[0].ports[?(@.name=="metrics")].containerPort}')
  [ -n "${METRICS_PORT}" ] || fail "pod ${pod} exposes no metrics port"

  kubectl port-forward -n "${NAMESPACE}" "pod/${pod}" "${PORT}:${METRICS_PORT}" >/dev/null 2>&1 &
  PF_PID=$!
  sleep 2
  SCRAPE="${SCRAPE}$(curl -s -m 10 "http://127.0.0.1:${PORT}/metrics" || true)"$'\n'
  kill "${PF_PID}" 2>/dev/null || true
  wait "${PF_PID}" 2>/dev/null || true
  PF_PID=""
done
[ -n "${SCRAPE}" ] || fail "no replica answered on /metrics"

expect_series() {
  echo "${SCRAPE}" | grep -q "$1" || fail "the scrape carries no $2: wanted a line matching '$1'"
  echo "OK: $2"
}

# ---------------------------------------------------------------------------
# 3. The series the dashboard and the alerts stand on
# ---------------------------------------------------------------------------
expect_series "ratelimit_checks_total{domain=\"${DOMAIN}\",verdict=\"ok\"}" "admitted checks"
expect_series "ratelimit_checks_total{domain=\"${DOMAIN}\",verdict=\"over_limit\"}" "refused checks"
expect_series "ratelimit_decisions_total{domain=\"${DOMAIN}\",outcome=\"over_limit\",rule=\"${RULE}\"}" \
  "the refusing rule by its triple"
expect_series "ratelimit_near_limit_total{domain=\"${DOMAIN}\",rule=\"${RULE}\"}" "the near-limit precursor"
expect_series "ratelimit_check_duration_seconds_bucket{domain=\"${DOMAIN}\",le=\"0.05\"}" \
  "the check duration histogram with the filter-timeout boundary"
expect_series "ratelimit_snapshot_rebuilds_total{result=\"ok\"}" "snapshot rebuilds"
expect_series "ratelimit_policy_ready{policy=\"${NAMESPACE}/${POLICY}\",reason=\"\"} 1" "the ready policy"
expect_series "ratelimit_domain_decision_buckets{domain=\"${DOMAIN}\"}" "the domain budget gauge"
expect_series "^go_goroutines" "the Go runtime series riding along"

# ---------------------------------------------------------------------------
# 4. A refusal leaves its sampled log line
# ---------------------------------------------------------------------------
FOUND_LOG=""
for pod in $(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=ratelimit \
    --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  if kubectl logs -n "${NAMESPACE}" "${pod}" --since-time="${WINDOW}" 2>/dev/null \
      | grep -q "rate limit refused domain=${DOMAIN}"; then
    FOUND_LOG=1
    break
  fi
done
[ -n "${FOUND_LOG}" ] || fail "no replica logged the sampled refusal line"
echo "OK: the refusal left its sampled log line"
