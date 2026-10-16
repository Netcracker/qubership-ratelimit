# Load testing

The kit under [`tests/load`](../tests/load) load-tests the rate limit through a gateway on a cluster of your own and
checks its own results. It installs as one Helm chart beside the rate limit charts:

- a backend that answers 200 to every request of the test, and an `HTTPRoute` from the gateway to it;
- the `RateLimitPolicy` of the gateway's domain: one block per API group, each with a per-user rule over the windows
  you set;
- a Job of JMeter generators. Each one sends READ, LIST, and SEARCH requests of test users at the rates of the load
  steps, builds the JMeter HTML report, and checks the results with `loadkit verify`.

The image, `ghcr.io/netcracker/qubership-ratelimit-loadtest`, carries JMeter, the plan
[`ratelimit-load.jmx`](../tests/load/jmeter/ratelimit-load.jmx) with its script `pick.groovy`, and `loadkit`. Its
tags follow the operator and service images built from the same commit. The
[load test workflow](../.github/workflows/load-test.yml) runs the whole kit on kind for every pull request that
changes it.

## What a run does

Each generator pod goes through these steps:

1. It gets a token for every test user of its slice: from Keycloak with the password grant, renewed before each token
   expires, or self-signed for a gateway that checks no token.
2. It sends probe requests until the gateway answers one with `x-ratelimit-remaining`. That header shows the route
   works and the rate limit service decides the test paths. The probe waits 300 seconds at most.
3. It runs the plan. The steps start `load.startDelaySeconds` after the chart was rendered, the same moment for every
   generator; a generator ready later starts 15 seconds after it is ready, says so in its log, and its steps lag the
   others'. Requests arrive as a Poisson process at the rate of each step, from a fixed pool of threads with keep-alive
   connections. Each request carries a randomly picked user, group, and operation. The hot users, if any, send to one
   group each at their own rate on top of the steps.
4. It builds the HTML report and runs `loadkit verify`, which writes `summary.md` and `summary.json`.
5. It writes the status of the run to `/results/done`: 0 when the check passed, 1 when a check failed, 2 when the check
   could not run, and 3 when JMeter failed and nothing was checked. It then waits for `/results/release`, or for
   `load.holdSeconds`, so you can copy the results out, and exits with that status.

A test user is `<tokens.userPrefix><n>`, numbered from 1 to `load.users` and zero-padded to the width of
`load.users`: `svt-user-0001` to `svt-user-2000` by default. The first `load.hotUsers` users are the hot ones.

## Before you start

- **The rate limit is installed.** The namespace runs the operator and the service charts, and the gateway's
  EnvoyFilter sends the domain you name in `gateway.domain`.
- **The test may own the domain's policy.** A domain has one `RateLimitPolicy`, named after it. The chart creates
  it, so the install fails on a namespace whose domain already has one. Install on a stand where the test owns the
  domain, or set `policy.create: false` and add the chart's blocks to the existing policy by hand.
- **The gateway passes the token to the rate limit.** The rule counts per user by the `sub` claim of the bearer
  token. A gateway that drops the `Authorization` header before the rate limit filter, or a Keycloak client that
  issues lightweight access tokens without `sub`, leaves every request undecided, and the probe of step 2 never
  succeeds.
- **The test users exist.** With `tokens.source: keycloak`, the realm needs the test users and a client with Direct
  access grants enabled. [Creating the test users](#creating-the-test-users) shows how.
- **Token introspection is part of the measurement.** A gateway that introspects tokens in Keycloak calls it for every
  request it does not answer from a cache, so Keycloak can saturate before the rate limit does. Measure the same steps
  once with the rate limit off, as the baseline scenario does, and compare.

## Creating the test users

`loadkit keycloak-users` creates the test users in a realm through the admin REST API. Each user gets the given
password and a complete profile (a name and a verified email), since Keycloak refuses the password grant to an
incomplete profile. Rerunning the command resets the password of a user that exists. Run it from the image:

```bash
docker run --rm --user "$(id -u)" --entrypoint loadkit -v "$PWD/secrets:/secrets:ro" \
  ghcr.io/netcracker/qubership-ratelimit-loadtest:<tag> keycloak-users \
  -keycloak-url https://keycloak.example.com -realm <realm> \
  -admin-user <admin> -admin-password-file /secrets/admin-password \
  -users 2000 -password-file /secrets/users-password
```

The `--user` option lets the command read password files that only you can read. The admin user needs the
`manage-users` role of the realm; `-admin-realm` (default `master`) names the realm it logs
in to. Add `-delete` to remove the same users after the test. `-ca-file` trusts a private CA, and `-insecure` skips
the certificate check.

The client the generators log in through needs Direct access grants enabled. A confidential client also needs its
secret in a Secret that `tokens.keycloak.clientSecret` names. Store the users' password for the chart:

```bash
kubectl create secret generic loadtest-users -n <namespace> --from-file=password=secrets/users-password
```

## Running a test

1. Write a values file for the scenario. The [scenarios](#scenarios) list the values that differ between them.

   ```yaml
   image:
     tag: <tag>
   tokens:
     keycloak:
       url: https://keycloak.example.com
       realm: <realm>
       clientId: <client>
       passwordSecret:
         name: loadtest-users
   load:
     steps:
       - rate: 10
         seconds: 3600
   ```

2. Install the chart into the namespace of the rate limit, and check that the policy is `Ready`:

   ```bash
   helm upgrade --install loadtest tests/load/chart -n <namespace> -f values.yaml
   kubectl wait ratelimitpolicies.ratelimit.netcracker.com/gateway.public -n <namespace> --for=condition=Ready
   ```

3. Wait for the run. A generator logs its summary at the end. `kubectl exec <pod> -- cat /results/done` prints the
   status of the run once it is over.

4. Copy the results of every generator out, and release the pods. The chart's notes print the loop:

   ```bash
   kubectl cp -n <namespace> <pod>:/results results/<pod>
   kubectl exec -n <namespace> <pod> -- touch /results/release
   ```

5. Read `results/<pod>/summary.md` for the verdict and `results/<pod>/report/index.html` for the JMeter report.
   Uninstall the chart before the next run: the Job runs once.

The windows count in the counter store across runs. A second run within a day starts from the counters the first one
charged, so the hot users of a rerun are refused early. Wait for the windows to pass, or reset the counters with the
[management API](management-api.md) before a run whose limits are checked.

## Scenarios

The values below differ between the scenarios of a typical test campaign; everything else keeps its default.

| Scenario | Values | What the summary shows |
| --- | --- | --- |
| Baseline without the rate limit | `runtime.enabledPercent: 0` in the ratelimit-service chart; here `load.requireDecisions: false` and the steps of the capacity ladder | The latency and the ceiling of the gateway, the backend, and token introspection alone |
| Nominal load | `load.steps` at the expected rate, such as `rate: 10` for 600 requests a minute, for an hour | The latency the rate limit adds at the expected load, and no refusal of a user who keeps to the limits |
| Limits at work | `load.hotUsers: 20`, `load.hotRatePerMinute: 60`, steps of at least 5 hours to fill a daily window of 5000 | Every window of every hot user filled to its requests and not past them, and no false refusal |
| Capacity ladder | `policy.multiplier: 1000`, `load.checkLimits: false`, rising `load.steps` of 10 minutes each, `load.generators` and `load.threads` sized as below | The rate at which latency, errors, or undecided responses appear: the capacity |

The multiplier keeps the work of the counter store per request the same, three windows charged in one script, while
no limit fires. A run with real limits refuses most of its requests at a high rate, and a refusal charges nothing, so
it would report a capacity above the real one.

## What the check reports

`summary.md` has one row per step, measured without the first `load.warmupSeconds` of the step. The run fails when
any of these holds:

| Check | Failure in the summary | Usual cause |
| --- | --- | --- |
| Errors | `<n> of <m> samples were answered with neither 200 nor 429` | The gateway or the backend failed, or requests timed out |
| Undecided responses | `<n> of <m> samples passed the gateway without a rate limit decision` | The rate limit filter timed out, or the service could not reach the counter store, and the gateway let the request through |
| Limits | `<n> sample sequences break the limits` | An instance of a window admitted more than its requests (`over-admission`), or a 429 arrived while no window could have been full (`false refusal`) |
| Generator lag | `step <n> fell <ms> ms behind its schedule at p99, above 1s: give the generator more threads or add generators` | Every thread of the generator was busy; the step measured the generator, not the rate limit |
| Rate, with `-min-rate-ratio` | `step <n> achieved <rate> requests per second of the <rate> targeted` | The generator could not send the target rate |
| Latency, with `-max-p99` | `step <n> has a p99 of <ms> ms, above <limit>` | The step's response time passed the bound you set |

The limit check needs fixed windows, which start at a multiple of their period since the epoch: a daily window starts
at 00:00 UTC. It allows the generator's clock and the counter store's clock to differ by up to 100 ms (`-skew`). It
reports only what no decision moment within that tolerance explains. `load.checkLimits` passes the windows to the
check only with `policy.algorithm: FixedWindow`. The summary also lists, per window, how many instances reached their
requests, counting only the admissions that cannot fall in a neighboring instance. A hot user that sends more than a
window allows reaches its requests in most instances; the instances cut by the start or the end of the run, and those
a longer window keeps closed, do not. A count of zero means no window was ever seen full, and a run meant to show the
limits at work has not shown them.

`loadkit verify` exits with 1 when a check fails and with 2 when it cannot read its input; `/results/done` and the
pod's exit status carry that value, or 3 when JMeter failed before the check.

A generator that stops before it writes its results logs the reason. When the probe of step 2 never gets a decided
response, it logs:

```text
no response from <url> matched <pattern> within <n> seconds: check the route, the RateLimitPolicy, and the tokens
```

When the password grant fails for a test user, it logs:

```text
loadkit tokens: <n> of <m> users could not log in; first error: user <name>: token endpoint returned <code>: <error> <description>
```

There, `invalid_grant Account is not fully set up` names a user created without a full profile, and
`unauthorized_client` a client without Direct access grants.

## Sizing the generators

- **Threads.** A generator thread holds one request at a time, so a generator needs more than its rate times the
  response time in seconds: 200 threads carry 10000 requests per second at 20 ms. Too few threads show up as generator
  lag, never as a slower rate limit.
- **Generators.** `load.generators` pods share the rate equally, and each takes its own slice of the users, so every
  user's windows are counted by one generator and checked by it. Each generator's summary covers its own share. For
  the whole run, pass the `results.jtl` of every generator to one `loadkit verify` with the summed steps and `-start`
  set to the start every generator logs. Add a generator when more threads no longer remove the lag: the generator
  has run out of CPU.
- **Results.** A sample takes about 250 bytes of `results.jtl`, so a step of 10 minutes at 5000 requests per second
  needs about 750 MB. Raise `load.resultsSizeLimit` with the rate and the length of the steps. The check keeps no
  sample in memory unless it checks the limits, and about 70 bytes per sample when it does: a run of 10 million
  samples with `load.checkLimits` needs about 700 MB of the generator's memory.
- **Backend.** The backend answers every request and must not be the ceiling of the run. A backend pod short of
  CPU fails its readiness probe, and the gateway then answers `503` with the `UH` response flag. The baseline
  scenario shows where the backend's ceiling is; add replicas, or raise `backend.resources` together with
  `backend.workerProcesses`, until the baseline steps run without errors.
- **Placement.** The generators run outside the mesh (`load.podLabels`), the way clients outside the cluster do. Keep
  them off the nodes of the gateway and the rate limit service, or they compete for the CPU they measure.

## Chart values

The [values file](../tests/load/chart/values.yaml) describes every value; the ones a run usually sets:

| Value | Default | What it sets |
| --- | --- | --- |
| `image.tag` | required | The tag of the load test image |
| `gateway.name`, `gateway.namespace` | `public-gateway`, the release namespace | The Gateway the route attaches to |
| `gateway.domain` | `gateway.public` | The rate limit domain of that gateway, and the name of the policy |
| `gateway.host`, `gateway.port` | `<name>-istio.<namespace>.svc.cluster.local`, `8080` | Where the generators connect |
| `route.pathPrefix` | `/ratelimit-loadtest` | The path every request of the test goes under |
| `policy.create` | `true` | Whether the chart creates the domain's policy |
| `policy.groups` | five groups | The API groups: one block of the policy and one path segment each |
| `policy.windows`, `policy.algorithm` | 50 a minute, 1000 an hour, 5000 a day; `FixedWindow` | The windows of the per-user rule |
| `policy.multiplier` | `1` | A factor on the requests of every window |
| `backend.replicas`, `backend.workerProcesses` | `2`, `2` | The backend's pods and the nginx workers of each; keep the workers at the CPU limit |
| `tokens.source` | `keycloak` | `keycloak` or `self-signed` |
| `tokens.keycloak.*` | none | The server, the realm, the client, and the Secrets of the password and the client secret |
| `load.users`, `load.hotUsers`, `load.hotRatePerMinute` | `2000`, `0`, `60` | The test users and the hot ones |
| `load.mix` | READ 60, LIST 30, SEARCH 10 | The shares of the operations |
| `load.steps` | 10 per second for an hour | The load steps, in requests per second summed over the generators |
| `load.warmupSeconds` | `30` | The start of each step left out of its statistics |
| `load.startDelaySeconds` | `120` | How long after the chart is rendered the steps of every generator start |
| `load.generators`, `load.threads` | `1`, `200` | The generator pods and the threads of each |
| `load.checkLimits`, `load.requireDecisions` | `true`, `true` | Whether the check covers the limits and expects every request decided |
| `load.verifyArgs` | none | More flags of `loadkit verify`, such as `-min-rate-ratio 0.95 -max-p99 50ms` |
| `load.holdSeconds` | `3600` | How long a generator keeps its results for `kubectl cp` |

## Running the plan in your own JMeter

The plan runs in JMeter 5.6.3, the version of the image, with `pick.groovy` in the directory of the plan. Give it
the properties file and the properties of the run:

```bash
jmeter -n -t ratelimit-load.jmx -q loadtest.properties \
  -Jhost=<gateway-host> -Jport=8080 -Jtokens=tokens.csv \
  -Jsteps=10:600,50:600 -JhotSteps=0:1200 -Jthreads=200 -Jduration=1260 \
  -l results.jtl
```

| Property | Meaning |
| --- | --- |
| `host`, `port`, `scheme`, `prefix` | The gateway and the path prefix |
| `tokens` | The CSV that `loadkit tokens` writes: `user,hot,token`, hot users first |
| `groups`, `mix` | The groups, comma-separated, and the shares of READ, LIST, and SEARCH |
| `steps`, `hotSteps` | `rate:seconds` pairs, comma-separated, for the other users and for the hot users |
| `threads`, `hotThreads` | The threads of each thread group |
| `start` | The moment the steps start, in milliseconds since the epoch; unset, the start of the run |
| `duration` | A bound on the run in seconds, past the end of the steps |

`loadkit tokens` writes the tokens file, from Keycloak or self-signed, and with `-watch` keeps renewing it while the
plan runs. The plan reads the file again within five seconds of a change. `loadkit verify -jtl results.jtl -steps ...
-windows 50/60,1000/3600,5000/86400` checks the results the same way a generator does; give it `-start` when the
steps did not start with the first request. `-max-lag`, one second by default, bounds the generator lag. Run either
command with `-h` for its flags.
