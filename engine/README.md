# Rate limit engine

The decision core of the rate limit service: it turns a set of rules and one request into a verdict. It is a
separate Go module so that the boundary is enforced by the toolchain rather than by review discipline.

```bash
go test ./...
```

The Redis store tests resolve their server in three steps: `REDIS_ADDR` when set, a disposable container the
test binary starts itself when Docker is available, a skip otherwise.

## What lives here

| Package | Responsibility |
| --- | --- |
| `model` | plain rule structures — blocks, routes, predicates, groups, windows |
| `compile` | a set of policies plus one mapping becomes an immutable snapshot, or a list of validity problems |
| `match` | one request becomes the list of counter buckets it must fit into |
| `identity` | token payload becomes descriptor keys, per the extraction mapping |
| `algo` | algorithm registry: the Go-side passport of each counting algorithm |
| `key` | the one place that knows the counter key shape; matching and management both build keys here |
| `store` | the counter contract, its implementations, and the `storetest` suite every implementation must pass |

## What does not live here

Custom resource types, controllers, status reporting, the Envoy gRPC adapter, and the management API belong to
the operator module. The engine never learns that Kubernetes exists: the operator converts its resources into
`model` structures and passes them in.

## Wiring the operator module

The root `go.mod` carries a `replace` of this module to `./engine`, and the Dockerfile copies `engine/go.mod`
before `go mod download`. The first `import` from operator code therefore needs nothing beyond `go mod tidy`:
the replace resolves it to the local directory. No tags and no `go.work` are involved — the directive is
committed and works the same locally, in CI, and in the image build. `make test` and CI run this module's
tests alongside the root module's.

## Two rules

**No Kubernetes, Envoy, or transport (gRPC) imports.** The module declares no such dependencies, so an
accidental import fails to build. `TestNoForbiddenDependencies` states the rule explicitly and reports it as
a test failure rather than a confusing compile error.

**Counting math lives in Lua, not in Go.** A decision reads counter state, computes a verdict, and writes the
new state as one indivisible step inside the store; splitting that across a network round trip would let two
replicas admit the same last request. Go builds the bucket list, dispatches, and interprets the answer. Adding
an algorithm means adding its two functions to the script and its passport to `algo`.
