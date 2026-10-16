#!/bin/sh
# Runs one load generator: writes the tokens of its slice of the test users,
# drives the JMeter plan through the gateway, builds the HTML report, and
# checks the results with loadkit verify. Everything lands in RESULTS_DIR.
# Once the run is over, the file done holds its status: the exit status of
# loadkit verify (0 passed, 1 a check failed, 2 the check could not run), or
# 3 when JMeter itself failed and nothing was checked. The container then
# stays up for LT_HOLD_SECONDS, or until a file named release appears in
# RESULTS_DIR, so the results can be copied out with kubectl cp, and exits
# with the same status.
#
# The chart sets the LT_* variables; docs/load-testing.md describes each.
set -eu

: "${LT_HOST:?LT_HOST names the gateway}"
: "${LT_STEPS:?LT_STEPS holds the load steps as rate:seconds pairs}"
LT_PORT="${LT_PORT:-8080}"
LT_SCHEME="${LT_SCHEME:-http}"
LT_PREFIX="${LT_PREFIX:-/ratelimit-loadtest}"
LT_GROUPS="${LT_GROUPS:-customers,orders,incidents,billing,products}"
LT_MIX="${LT_MIX:-60,30,10}"
LT_USERS="${LT_USERS:-2000}"
LT_USER_PREFIX="${LT_USER_PREFIX:-svt-user-}"
LT_HOT_USERS="${LT_HOT_USERS:-0}"
LT_HOT_RATE_PER_MINUTE="${LT_HOT_RATE_PER_MINUTE:-60}"
LT_THREADS="${LT_THREADS:-200}"
LT_HOT_THREADS="${LT_HOT_THREADS:-4}"
LT_GENERATORS="${LT_GENERATORS:-1}"
LT_GENERATOR="${JOB_COMPLETION_INDEX:-0}"
LT_TOKEN_SOURCE="${LT_TOKEN_SOURCE:-keycloak}"
LT_WARMUP_SECONDS="${LT_WARMUP_SECONDS:-30}"
LT_WINDOWS="${LT_WINDOWS:-}"
LT_REQUIRE_DECISIONS="${LT_REQUIRE_DECISIONS:-true}"
LT_VERIFY_ARGS="${LT_VERIFY_ARGS:-}"
LT_HOLD_SECONDS="${LT_HOLD_SECONDS:-3600}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
WORK_DIR="${WORK_DIR:-/tmp/loadtest}"
PLAN_DIR="${PLAN_DIR:-/opt/loadtest}"

mkdir -p "$RESULTS_DIR" "$WORK_DIR"
rm -f "$RESULTS_DIR/done" "$RESULTS_DIR/release"
tokens="$WORK_DIR/tokens.csv"
watcher=""
cleanup() {
	if [ -n "$watcher" ]; then
		kill "$watcher" 2>/dev/null || true
	fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT

# Load steps of the whole run, divided among the generators.
seconds=0
steps=""
for pair in $(echo "$LT_STEPS" | tr ',' ' '); do
	rate="${pair%%:*}"
	duration="${pair#*:}"
	seconds=$((seconds + duration))
	steps="${steps:+$steps,}$(awk -v r="$rate" -v n="$LT_GENERATORS" 'BEGIN { printf "%.4f", r / n }'):$duration"
done

echo "generator $LT_GENERATOR of $LT_GENERATORS: $LT_USERS users, $LT_HOT_USERS hot, steps $steps"
set -- -users "$LT_USERS" -hot "$LT_HOT_USERS" -prefix "$LT_USER_PREFIX" \
	-generator "$LT_GENERATOR" -generators "$LT_GENERATORS" -out "$tokens"
case "$LT_TOKEN_SOURCE" in
self-signed)
	loadkit tokens -source self-signed "$@" -ttl "$((seconds + LT_HOLD_SECONDS + 3600))s"
	;;
keycloak)
	set -- "$@" -source keycloak -watch \
		-keycloak-url "${LT_KEYCLOAK_URL:?LT_KEYCLOAK_URL names the Keycloak server}" \
		-realm "${LT_KEYCLOAK_REALM:?LT_KEYCLOAK_REALM names the realm of the test users}" \
		-client-id "${LT_KEYCLOAK_CLIENT_ID:?LT_KEYCLOAK_CLIENT_ID names the client}" \
		-password-file "${LT_KEYCLOAK_PASSWORD_FILE:?LT_KEYCLOAK_PASSWORD_FILE holds the password of the test users}"
	if [ -n "${LT_KEYCLOAK_CLIENT_SECRET_FILE:-}" ]; then
		set -- "$@" -client-secret-file "$LT_KEYCLOAK_CLIENT_SECRET_FILE"
	fi
	if [ -n "${LT_KEYCLOAK_CA_FILE:-}" ]; then
		set -- "$@" -ca-file "$LT_KEYCLOAK_CA_FILE"
	fi
	if [ "${LT_KEYCLOAK_INSECURE:-false}" = true ]; then
		set -- "$@" -insecure
	fi
	loadkit tokens "$@" >"$RESULTS_DIR/tokens.log" 2>&1 &
	watcher=$!
	waited=0
	until [ -s "$tokens" ]; do
		if ! kill -0 "$watcher" 2>/dev/null; then
			cat "$RESULTS_DIR/tokens.log" >&2
			echo "loadkit tokens exited before it wrote $tokens" >&2
			exit 2
		fi
		if [ "$waited" -ge 600 ]; then
			echo "loadkit tokens wrote no tokens within 600 seconds" >&2
			exit 2
		fi
		sleep 1
		waited=$((waited + 1))
	done
	;;
*)
	echo "LT_TOKEN_SOURCE is $LT_TOKEN_SOURCE; want keycloak or self-signed" >&2
	exit 2
	;;
esac

# Wait until the gateway routes the test paths and the service decides them:
# a response with x-ratelimit-remaining proves both. The probe goes out as a
# user that is not hot, whose few requests stay far from every limit, so
# the one admission the results do not record cannot make a later refusal
# look false. A run with LT_REQUIRE_DECISIONS=false, the baseline with the
# rate limit off, waits for a 200 instead and expects no decision at all.
ready='^ *x-ratelimit-remaining:'
if [ "$LT_REQUIRE_DECISIONS" = false ]; then
	ready='^ *HTTP/[0-9.]+ 200'
	LT_WINDOWS=""
	LT_VERIFY_ARGS="-max-undecided-ratio 1 $LT_VERIFY_ARGS"
fi
probe=$(awk -F, 'NR > 1 && $2 == 0 { print $3; exit }' "$tokens")
if [ -z "$probe" ]; then
	probe=$(awk -F, 'NR == 2 { print $3 }' "$tokens")
fi
probe_url="$LT_SCHEME://$LT_HOST:$LT_PORT$LT_PREFIX/${LT_GROUPS%%,*}/items"
waited=0
until wget -S -q -O /dev/null --header "Authorization: Bearer $probe" "$probe_url" 2>&1 |
	grep -qiE "$ready"; do
	if [ "$waited" -ge "${LT_PREFLIGHT_SECONDS:-300}" ]; then
		echo "no response from $probe_url matched $ready within $waited seconds:" \
			"check the route, the RateLimitPolicy, and the tokens" >&2
		exit 2
	fi
	sleep 5
	waited=$((waited + 5))
done
echo "$probe_url answers as expected"

# Every generator starts its schedule at LT_START_AT, seconds since the epoch,
# so the steps of all generators line up; a generator that reaches this point
# after that moment starts 15 seconds from now instead, and says so.
now=$(date +%s)
start="${LT_START_AT:-0}"
if [ "$start" -le $((now + 5)) ]; then
	if [ "$start" -gt 0 ]; then
		echo "LT_START_AT $start has passed; this generator starts its steps $((now + 15 - start)) seconds after it" >&2
	fi
	start=$((now + 15))
fi
start_ms=$((start * 1000))
echo "the schedule starts at $start_ms ms since the epoch, $((start - now)) seconds from now"

# The hot users of this slice share one schedule at their combined rate.
hot=$(awk -F, 'NR > 1 && $2 == 1 { n++ } END { print n + 0 }' "$tokens")
hot_rate=$(awk -v h="$hot" -v m="$LT_HOT_RATE_PER_MINUTE" 'BEGIN { printf "%.4f", h * m / 60 }')
verify_steps=""
for pair in $(echo "$steps" | tr ',' ' '); do
	verify_steps="${verify_steps:+$verify_steps,}$(awk -v r="${pair%%:*}" -v h="$hot_rate" 'BEGIN { printf "%.4f", r + h }'):${pair#*:}"
done

status=0
jmeter -n -t "$PLAN_DIR/ratelimit-load.jmx" -q "$PLAN_DIR/loadtest.properties" \
	-Jhost="$LT_HOST" -Jport="$LT_PORT" -Jscheme="$LT_SCHEME" -Jprefix="$LT_PREFIX" \
	-Jgroups="$LT_GROUPS" -Jmix="$LT_MIX" -Jtokens="$tokens" \
	-Jstart="$start_ms" -Jsteps="$steps" -JhotSteps="$hot_rate:$seconds" \
	-Jthreads="$LT_THREADS" -JhotThreads="$LT_HOT_THREADS" -Jduration="$((start - $(date +%s) + seconds + 60))" \
	-Jjmeter.reportgenerator.temp_dir="$WORK_DIR/report-temp" \
	-l "$RESULTS_DIR/results.jtl" -j "$RESULTS_DIR/jmeter.log" || status=$?
if [ "$status" -ne 0 ]; then
	echo "JMeter exited with status $status; see jmeter.log" >&2
	status=3
else
	jmeter -g "$RESULTS_DIR/results.jtl" -o "$RESULTS_DIR/report" \
		-Jjmeter.reportgenerator.temp_dir="$WORK_DIR/report-temp" -j "$RESULTS_DIR/report.log" ||
		echo "the HTML report failed; see report.log" >&2
	# LT_VERIFY_ARGS holds extra flags of loadkit verify, split on spaces.
	# shellcheck disable=SC2086
	loadkit verify -jtl "$RESULTS_DIR/results.jtl" -steps "$verify_steps" -start "$start_ms" \
		-warmup "${LT_WARMUP_SECONDS}s" \
		-windows "$LT_WINDOWS" -out "$RESULTS_DIR" $LT_VERIFY_ARGS || status=$?
fi
cleanup
watcher=""

echo "$status" >"$RESULTS_DIR/done"
echo "results are in $RESULTS_DIR; the container waits up to $LT_HOLD_SECONDS seconds for $RESULTS_DIR/release"
waited=0
while [ "$waited" -lt "$LT_HOLD_SECONDS" ] && [ ! -e "$RESULTS_DIR/release" ]; do
	sleep 5
	waited=$((waited + 5))
done
exit "$status"
