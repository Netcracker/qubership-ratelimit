# ratelimit documentation

Reference documentation for the rate limit component: what it is made of, what its resource means, what its API
answers, and what to do when it misbehaves. The repository [README](../README.md) is the short introduction; these
pages are the detail behind it.

Rate limiting is delivered as two components per namespace. The operator reads the `RateLimitPolicy` objects of its own
namespace, validates them, writes them into one ConfigMap, and writes the policy status. The service mounts that
ConfigMap, compiles it, and answers `ShouldRateLimit` for the Istio ambient gateways over the Envoy RLS protocol.
Counters live in a shared Redis, so a limit is a limit of the domain rather than of one replica.

## Architecture

| Page | What it covers |
| --- | --- |
| [Deployment topology](deployment-topology.md) | The two components, the single-namespace and composite schemes, the configuration flow, last-good, the status conditions, RBAC, and what is verified end to end. |
| [Interaction diagram](topology-diagram.md) | The same picture drawn: who places what, who processes it, and where a request goes in a composite. |
| [Engine](engine.md) | The protocol, the configuration channel, rule semantics and matching, the counting algorithms, storage, token handling, observability, and the performance envelope. |
| [Counter store contract](store-contract.md) | The `Store` and `Inspector` interfaces, the atomicity rules, the key layout, the algorithm passports, the contract test suite, and the two implementations. |
| [Limits and their origin](limits.md) | Every number that constrains a policy, where it comes from, and which layer enforces it. |

## Authoring policies

| Page | What it covers |
| --- | --- |
| [RateLimitPolicy specification](ratelimitpolicy-cr-spec.md) | The resource: the field reference, matching and evaluation semantics, the compilation model, the counter key, validity and last-good, and the status. |
| [`ratelimitpolicy-example.yaml`](ratelimitpolicy-example.yaml) | A commented policy that exercises the whole spec, plus a minimal one. |
| [Rollout procedure](rollout-procedure.md) | Turning limits on against live traffic: shadow, validation, staged enablement, and the rollback path for each step. |

## Operating the component

| Page | What it covers |
| --- | --- |
| [Operations runbook](runbook.md) | Diagnosing a component that misbehaves: store degradation, a policy that will not compile, a lagging replica, the ConfigMap channel, and the metric-to-scenario map. |
| [Helm charts](helm-chart.md) | The two charts: values, schemas, templates, the metric naming contract, the Argo CD health check, installation and upgrade order, and what the charts deliberately do not install. |

## Management API

| Page | What it covers |
| --- | --- |
| [Management API](management-api.md) | Reading the enforced state, inspecting and resetting live counters, and simulating a request: the surface, the selector grammar, idempotency, errors, security, and how it works inside. |
| [Cookbook](management-api-cookbook.md) | Every scenario end to end, against one worked configuration. |

The canonical specification is the OpenAPI document embedded in the binary,
[`service/internal/management/openapi.yaml`](../service/internal/management/openapi.yaml), which the service serves at
`GET /openapi.yaml`.
