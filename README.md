# ratelimit

Rate limiting for an Istio ambient mesh with two ingress gateways. The gateways call this service over the Envoy
rate limit service (RLS) protocol; the rules arrive as `RateLimitPolicy` custom resources.

| Item                     | Value                                          |
|--------------------------|------------------------------------------------|
| API group                | `ratelimit.netcracker.com`                     |
| Kind / resource          | `RateLimitPolicy` / `ratelimitpolicies`        |
| gRPC RLS port            | 9000                                           |
| Health probes            | 8081                                           |
| Scope                    | namespaced — one installation, one namespace   |

## How it fits together

A policy binds to a gateway through a domain string that has to match on both sides: the gateway's rate limit filter
carries it, and the CR names it. Nothing validates the match. A mismatch surfaces only as an
`unknown rate limit domain` line in the service log, so that line is the one to alert on.

Controller and RLS engine share one binary and one Deployment. `--mode=all|controller|rls` selects the components, so
splitting them later is a Helm change rather than a refactor. Only `all` is exercised today.

| Component      | Runs on        | Leader election | Behavior in the skeleton                      |
|----------------|----------------|-----------------|-----------------------------------------------|
| Store updater  | every replica  | no              | rebuilds the set of bound domains on events |
| gRPC RLS server| every replica  | no              | logs the request, answers `OK`                |
| Reconciler     | leader only    | yes             | sets `Accepted: True`, reason `StubAllowsAll` |

The split is a correctness requirement. `Reconcile` runs on the leader alone, so a store filled there would leave every
other replica answering checks from an empty store — limits that apply on some pods and not others.

## Install

```bash
helm upgrade --install ratelimit helm-templates/ratelimit \
  --namespace <business-namespace> \
  --set image.tag=<tag>
```

The chart installs a `ServiceAccount`, a `Role` and `RoleBinding` pair, a `Deployment`, a `Service`, the CRD, and one
`EnvoyFilter` per enabled gateway. It installs no `ClusterRole` and no `ClusterRoleBinding`.

The gateway names are not this chart's to choose. They are deployment parameters shared with
`qubership-core-mesh-config`, the chart that creates the `Gateway` objects, and the deployer injects the same set into
every chart of the application:

```yaml
ISTIO_PUBLIC_GATEWAY_NAME: public-gateway
ISTIO_PRIVATE_GATEWAY_NAME: private-gateway
```

Override them in one chart and not the other, and the `EnvoyFilter` attaches to a gateway that does not exist — with
no error, because a `targetRefs` pointing at a missing `Gateway` is simply inert.

What this chart owns per gateway is whether to rate limit it and under which domain:

```yaml
gateways:
  public:
    enabled: true
    domain: gateway.public
  private:
    enabled: true
    domain: gateway.private
```

`namespace` is accepted per gateway and defaults to the release namespace. `qubership-core-mesh-config` sets no
`metadata.namespace` on its Gateways, so they land in the business namespace next to this release and the default is
right. Set it only if they move — Istio resolves `targetRefs` within the `EnvoyFilter`'s own namespace, so the filter
has to follow the gateway.

### The CRD is shared

`ratelimitpolicies.ratelimit.netcracker.com` is cluster-scoped, and every namespace installation shares that single
object. With several per-namespace releases, the releases race for its ownership and version. The chart annotates it
with `helm.sh/resource-policy: keep` so that uninstalling one release does not take the CRD — and every other
namespace's policies — with it. Settle CRD upgrade ownership with the platform team: this is a deploy-time concern, and
the service itself never touches the CRD object.

## Develop

```bash
make build              # compile the manager binary
make test-unit          # unit tests only; no envtest, no cluster, no network
make test               # everything, including the envtest controller suite
make manifests generate # regenerate the CRD, the RBAC, and the DeepCopy methods
make sync-helm-crds     # copy the generated CRD into the chart (alias: make helm-crd)
make lint               # golangci-lint
make helm-lint          # helm lint against values.schema.json
```

`make test` runs `internal/controller` against a real API server through envtest, which is where the CRD schema and
the status subresource actually exist — the fake client the other tests use validates nothing. The first run downloads
the envtest binaries into `bin/`, so it needs internet; `make test-unit` never does. Both derive their Kubernetes
version from `go.mod`, so the test control plane cannot drift from the client libraries the service is built against.

`helm-templates/ratelimit/templates/crd-ratelimitpolicies.yaml` is generated. Edit the Go types and
run `make sync-helm-crds` instead of editing it.

Run the service against your current kubeconfig:

```bash
CLOUD_NAMESPACE=<ns> make run
```

`CLOUD_NAMESPACE` has no default. An unset value is a startup error, not a fallback to watching the cluster — it is
what keeps the service's RBAC a `Role`. It is read through `configloader`, so any property source the platform configures can supply it.
