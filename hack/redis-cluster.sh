#!/usr/bin/env bash
# Stands up a disposable Redis Cluster for the engine store suite, and tears
# it down. All nodes share one network namespace and announce 127.0.0.1, so
# the same loopback addresses work for the nodes' own gossip, for a test run
# on a Linux CI runner, and for one on a macOS laptop - the three places the
# suite has to run without edits.
#
# Three masters and no replicas: what the suite needs from a cluster is
# distributed slots, so that a script whose keys hash apart is refused with
# CROSSSLOT. Three is the smallest cluster redis-cli will create; replicas
# would only serve failover, which no test here exercises.
#
#   hack/redis-cluster.sh up      # prints the REDIS_ADDR value to use
#   hack/redis-cluster.sh down
set -euo pipefail

NAME="${CLUSTER_NAME:-ratelimit-redis-cluster}"
IMAGE="${REDIS_IMAGE:-redis:7.2-alpine}"
BASE_PORT="${BASE_PORT:-7101}"
NODES=3

ports() {
  seq "${BASE_PORT}" $((BASE_PORT + NODES - 1))
}

up() {
  local publish=()
  for port in $(ports); do
    publish+=("-p" "127.0.0.1:${port}:${port}")
  done

  # The first container owns the network namespace; the rest join it, which
  # is what lets every node reach its peers on 127.0.0.1 - the address they
  # all announce.
  docker run -d --rm --name "${NAME}-0" "${publish[@]}" "${IMAGE}" \
    redis-server --port "${BASE_PORT}" --cluster-enabled yes \
    --cluster-config-file nodes-0.conf --appendonly no --save '' \
    --cluster-announce-ip 127.0.0.1 >/dev/null
  for i in $(seq 1 $((NODES - 1))); do
    docker run -d --rm --name "${NAME}-${i}" --network "container:${NAME}-0" "${IMAGE}" \
      redis-server --port $((BASE_PORT + i)) --cluster-enabled yes \
      --cluster-config-file "nodes-${i}.conf" --appendonly no --save '' \
      --cluster-announce-ip 127.0.0.1 >/dev/null
  done

  local members=()
  for port in $(ports); do
    members+=("127.0.0.1:${port}")
  done
  docker exec "${NAME}-0" sh -c "
    for i in \$(seq 1 60); do
      redis-cli -p ${BASE_PORT} ping >/dev/null 2>&1 && break
      sleep 1
    done
    redis-cli --cluster create ${members[*]} --cluster-replicas 0 --cluster-yes >/dev/null
    for i in \$(seq 1 60); do
      redis-cli -p ${BASE_PORT} cluster info | grep -q cluster_state:ok && exit 0
      sleep 1
    done
    echo 'the cluster never reached cluster_state:ok' >&2
    exit 1
  "

  local addr=""
  for port in $(ports); do
    addr="${addr}127.0.0.1:${port},"
  done
  echo "${addr%,}"
}

down() {
  for i in $(seq $((NODES - 1)) -1 0); do
    docker stop "${NAME}-${i}" >/dev/null 2>&1 || true
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
