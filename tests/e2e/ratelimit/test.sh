#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# The thing the operator exists for: a gateway calls it on every request and
# honours the verdict.
#
# Everything here needs a real gateway, a real Envoy, and the operator's own
# gRPC endpoint at once — which is why none of it can be a unit test.
# ---------------------------------------------------------------------------
set -eux

# shellcheck source=../lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

# The chart binds these domains by default; the policies carry them.
PUBLIC_DOMAIN=gateway.public
PUBLIC_POLICY=e2e-public
PRIVATE_DOMAIN=gateway.private
PRIVATE_POLICY=e2e-private

# A path no HTTPRoute serves. The backend status is irrelevant — what matters is
# 429 versus not-429 — and using an unrouted path keeps the test independent of
# whatever else is deployed in the namespace.
PROBE_PATH=/e2e-ratelimit

cleanup() {
  kubectl delete ratelimitpolicy "${PUBLIC_POLICY}" "${PRIVATE_POLICY}" \
    -n "${NAMESPACE}" --ignore-not-found
}
trap cleanup EXIT

apply_policy "${PUBLIC_POLICY}" "${PUBLIC_DOMAIN}"
apply_policy "${PRIVATE_POLICY}" "${PRIVATE_DOMAIN}"
wait_for_domain "${PUBLIC_DOMAIN}"

# ---------------------------------------------------------------------------
# 1. The gateway is configured to call this operator
# ---------------------------------------------------------------------------
# A wrong cluster name fails exactly like an unreachable operator, so assert the
# configuration rather than inferring it from behaviour.
GW_POD=$(kubectl get pod -n "${NAMESPACE}" \
  -l "gateway.networking.k8s.io/gateway-name=public-gateway" \
  -o jsonpath='{.items[0].metadata.name}')

CLUSTER=""
for _ in $(seq 1 12); do
  CLUSTER=$(kubectl exec -n "${NAMESPACE}" "${GW_POD}" -c istio-proxy -- \
    pilot-agent request GET config_dump 2>/dev/null \
    | jq -r '
        [ .configs[]
          | select(.["@type"] | test("ListenersConfigDump"))
          | .dynamic_listeners[]?.active_state.listener.filter_chains[]?.filters[]?
          | select(.name == "envoy.filters.network.http_connection_manager")
          | .typed_config.http_filters[]?
          | select(.name == "envoy.filters.http.ratelimit")
          | .typed_config.rate_limit_service.grpc_service.envoy_grpc.cluster_name ] | .[0] // empty' 2>/dev/null)
  [ -n "${CLUSTER}" ] && break
  sleep 5
done
EXPECTED="outbound|9000||${OPERATOR_SVC}.${NAMESPACE}.svc.cluster.local"
if [ "${CLUSTER}" != "${EXPECTED}" ]; then
  fail "gateway rate limit cluster: expected '${EXPECTED}', got '${CLUSTER}'"
fi
echo "OK: the gateway calls this release's Service"

# The descriptor the gateway sends is the operator's input contract.
DESCRIPTORS=$(kubectl exec -n "${NAMESPACE}" "${GW_POD}" -c istio-proxy -- \
  pilot-agent request GET config_dump 2>/dev/null \
  | jq -r '
      [ .configs[]
        | select(.["@type"] | test("RoutesConfigDump"))
        | .dynamic_route_configs[]?.route_config.virtual_hosts[]?
        | select(.rate_limits != null)
        | .rate_limits[].actions[].request_headers.descriptor_key ] | unique | join(",")')
for key in path method request_id token; do
  echo "${DESCRIPTORS}" | grep -q "${key}" \
    || fail "descriptor '${key}' missing from the gateway config (got: ${DESCRIPTORS})"
done
echo "OK: the gateway sends the path, method, token and request_id descriptors"

# ---------------------------------------------------------------------------
# 2. A policy without rules admits everything
# ---------------------------------------------------------------------------
# The CRD carries only the domain today, which compiles into the documented
# "no rules, everything allowed" snapshot: the whole burst must pass. The
# refusal scenarios return together with the rule schema; until then a 429
# here means the operator invented a limit nobody declared.
CODES=$(curl_gw_burst 6 public-gateway "${PROBE_PATH}")
echo "${CODES}"

if echo "${CODES}" | grep -q "429"; then
  fail "a request was refused although the policy declares no rules"
fi
if echo "${CODES}" | grep -q "000"; then
  fail "a request in the burst failed outright"
fi
echo "OK: the gateway admits the whole burst under a rule-less policy"

# ---------------------------------------------------------------------------
# 3. What the operator logs about a check
# ---------------------------------------------------------------------------
# The per-check line is Debug; the e2e install runs with logLevel=debug
# precisely so this contract stays observable.
SINCE=$(now_rfc3339)
sleep 1
SECRET="e2e-secret-token-should-never-be-logged"
REQUEST_ID="e2e-correlation-$(date +%s)"
sleep 1.5
curl_gw_burst 1 public-gateway "${PROBE_PATH}" "X-Request-Id: ${REQUEST_ID}" >/dev/null
curl_gw_code public-gateway "${PROBE_PATH}" "Authorization: Bearer ${SECRET}" >/dev/null

LOGS=""
for _ in $(seq 1 10); do
  LOGS=$(operator_logs_since "${SINCE}" | grep "rate limit check" || true)
  [ -n "${LOGS}" ] && break
  sleep 2
done
[ -n "${LOGS}" ] || fail "the operator logged no rate limit check for the traffic just sent"

echo "${LOGS}" | grep -q "domain=${PUBLIC_DOMAIN}" \
  || fail "the check was not logged against ${PUBLIC_DOMAIN}"
echo "${LOGS}" | grep -q "path=${PROBE_PATH}" \
  || fail "the request path was not logged"
echo "OK: the operator logs the domain and path of each check"

# The token is a credential and must never reach a log line, in any form.
if operator_logs_since "${SINCE}" | grep -q "${SECRET}"; then
  fail "the Authorization value was written to the log"
fi
echo "OK: the Authorization value never reaches the log"

# The request id is what ties a check to the gateway access log for the same
# request; it belongs in the [request_id=] field, not the message.
echo "${LOGS}" | grep -q "\[request_id=${REQUEST_ID}\]" \
  || fail "the client's X-Request-Id did not reach the [request_id=] field"
echo "OK: the client's X-Request-Id appears in the request_id field"

# The unknown-domain path is deliberately not tested here: proving it means
# removing every policy that claims gateway.public, which in a shared namespace
# would disrupt whatever else is using the gateway. internal/rls covers it.
