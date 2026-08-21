FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
# Allow Go toolchain auto-download when the image patch (e.g. 1.26.1) is
# older than the minimum declared in go.mod (e.g. 1.26.5).
ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.mod
COPY go.sum go.sum
# The engine module is replace-directed to ./engine; its go.mod must be
# present before go mod download once the operator imports it.
COPY engine/go.mod engine/go.mod
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# The builder stage always runs on the build host platform (BUILDPLATFORM) to avoid QEMU emulation.
# Cross-compilation is handled natively by Go via TARGETOS/TARGETARCH, which BuildKit sets automatically.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -o ratelimit ./cmd/

FROM ghcr.io/netcracker/qubership-core-base:2.3.7
WORKDIR /app
COPY --chown=10001:0 --chmod=555 --from=builder /app/ratelimit /app/ratelimit
COPY --chown=10001:0 --chmod=444 --from=builder /app/application.yaml /app/application.yaml
USER 10001:10001

CMD ["/app/ratelimit"]
