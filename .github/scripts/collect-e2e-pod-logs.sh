#!/usr/bin/env bash
# Copies the Fluent Bit capture off every kind node and splits it into one
# file per pod container. The capture is a stream of JSON records whose
# "file" key is the CRI log file name, <pod>_<namespace>_<container>-<id>.log,
# so the split needs nothing but that name.
set -euo pipefail

OUT_DIR="${OUT_DIR:-pod-logs}"
KIND_CLUSTER="${KIND_CLUSTER:-ratelimit-e2e}"

mkdir -p "${OUT_DIR}"

nodes=$(docker ps --format '{{.Names}}' | grep "^${KIND_CLUSTER}-" || true)
if [[ -z "${nodes}" ]]; then
  echo "No kind nodes found for cluster ${KIND_CLUSTER}" >&2
  exit 1
fi

for node in ${nodes}; do
  if ! docker exec "${node}" sh -c 'test -f /var/log/fluent-bit/e2e-pods.log'; then
    echo "No capture on ${node}"
    continue
  fi

  capture=$(mktemp)
  docker exec "${node}" cat /var/log/fluent-bit/e2e-pods.log > "${capture}"

  jq -Rr 'fromjson? | .file // empty' "${capture}" | sort -u | while read -r file; do
    name=$(basename "${file}" .log)
    # Cut the trailing container id; what remains is pod_namespace_container.
    name="${name%-*}"
    jq -Rr --arg f "${file}" 'fromjson? | select(.file == $f) | .log' \
      "${capture}" >> "${OUT_DIR}/${name}.log"
    echo "  ${OUT_DIR}/${name}.log"
  done

  rm -f "${capture}"
done
