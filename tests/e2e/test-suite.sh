#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# End-to-end suite. Runs against a cluster that already has Istio ambient, the
# two gateways (qubership-core-mesh-config with SERVICE_MESH_TYPE=Istio) and
# this chart installed, and drives real traffic through a gateway.
#
#   ./tests/e2e/test-suite.sh [test-filter]
#
# The suite installs nothing and uninstalls nothing. Only one rate limit filter
# can meaningfully sit on a gateway, so a suite that installed a second release
# would either collide with the deployed one or silently test a gateway with two
# filters on it. CI installs the chart first, then runs this — the same split
# qubership-istio uses for its own chart.
#
# Environment:
#   NAMESPACE     business namespace holding the gateways and the release
#                 (default: core)
#
# What is NOT covered here: the Istio distribution's own rate limit wiring
# (filter position, fail-open/fail-closed), which lives in qubership-istio's
# tests/ratelimit and needs no operator image.
# ---------------------------------------------------------------------------
set -e

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SUITE_DIR}/../.." && pwd)"

export RED_COLOR='\033[31m'
export GREEN_COLOR='\033[32m'
export RESET_COLOR='\033[0m'

export NAMESPACE="${NAMESPACE:-core}"
export SUITE_DIR REPO_ROOT

fail() {
  echo -e "${RED_COLOR}Test error: $1${RESET_COLOR}" >&2
  false
}
export -f fail

# ---------------------------------------------------------------------------
# Preflight: the suite drives traffic through real gateways, so it cannot
# meaningfully run without them. Say so plainly instead of failing later inside
# a test with a confusing message.
# ---------------------------------------------------------------------------
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 \
  || fail "namespace ${NAMESPACE} not found"
kubectl api-resources --api-group=networking.istio.io 2>/dev/null | grep -q envoyfilters \
  || fail "Istio is not installed (no EnvoyFilter CRD); this suite needs an ambient mesh"
kubectl get gateways.gateway.networking.k8s.io public-gateway -n "${NAMESPACE}" >/dev/null 2>&1 \
  || fail "Gateway public-gateway not found in ${NAMESPACE}; install qubership-core-mesh-config with SERVICE_MESH_TYPE=Istio"

# The Service name is what the gateways' EnvoyFilter resolves, so the tests read
# it from the cluster instead of assuming a release name.
OPERATOR_SVC=$(kubectl get svc -n "${NAMESPACE}" -l app.kubernetes.io/name=ratelimit \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -n "${OPERATOR_SVC}" ] \
  || fail "no ratelimit Service in ${NAMESPACE}; install the chart before running the suite"
kubectl rollout status "deployment/${OPERATOR_SVC}" -n "${NAMESPACE}" --timeout=120s >/dev/null \
  || fail "the ratelimit deployment is not ready"
export OPERATOR_SVC

echo -e "${GREEN_COLOR}Testing ${OPERATOR_SVC} in ${NAMESPACE}${RESET_COLOR}"

run_test() {
  local test_script="${SUITE_DIR}/$1/test.sh"
  SCRIPT_DIR="${SUITE_DIR}/$1"
  export SCRIPT_DIR

  echo -e "${GREEN_COLOR}Run tests: $1${RESET_COLOR}"
  if "${test_script}"; then
    echo -e "${GREEN_COLOR}Tests passed: $1${RESET_COLOR}"
  else
    echo -e "${RED_COLOR}Tests failed: $1${RESET_COLOR}"
    exit 1
  fi
}

TEST_FILTER=${1:-*}
FOUND=0
while read -r test_name; do
  [ -f "${SUITE_DIR}/${test_name}/test.sh" ] || continue
  FOUND=1
  run_test "${test_name}"
done < <(find "${SUITE_DIR}" -maxdepth 1 -mindepth 1 -name "${TEST_FILTER}" -type d -exec basename {} \; | sort)

[ "${FOUND}" = "1" ] || fail "no tests matched '${TEST_FILTER}'"

echo -e "${GREEN_COLOR}All tests passed${RESET_COLOR}"
