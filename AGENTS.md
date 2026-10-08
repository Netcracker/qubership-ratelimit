# Agent instructions

## Tests

Tests in `*_test.go` files use three stacks. Unit tests of the root module run on the Go `testing` engine with testify
`assert` and `require`. The `engine/` module has its own `go.mod` without testify, so its tests use Go `testing` alone,
with `t.Errorf("f(%v) = %v, want %v", ...)` messages. The envtest suites under `operator/` and the e2e suite in
`tests/e2e-go` (build tag `e2e`) run on the Ginkgo v2 engine with Gomega assertions. One failed Gomega `Expect` stops
the spec, so a spec that checks several fields of one result uses `gstruct.MatchFields`, which reports every field.
Every Ginkgo `Entry` carries a description, because an entry without one is named by its parameters.

The alert rule tests in `tests/charts/testdata` run through `promtool test rules`, which reports every failing test
group of a file and names the group for an `alert_rule_test` failure but not for a `promql_expr_test` failure, so a
`promql_expr_test` case runs in a promtool call of its own.
