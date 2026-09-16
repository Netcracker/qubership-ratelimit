# The operator image, built from the repository root: the operator's tree
# imports the root module's internal packages and the engine module, so the
# context is the whole repository and the Dockerfile lives here so it is
# found beside the code it builds.
#
#   docker build -f operator/Dockerfile .

FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# Allow Go toolchain auto-download when the image patch (e.g. 1.26.1) is
# older than the minimum declared in go.mod (e.g. 1.26.5).
ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.mod
COPY go.sum go.sum
# The engine module is replace-directed to ./engine; its go.mod must be
# present before go mod download.
COPY engine/go.mod engine/go.mod
RUN go mod download

COPY . .

# The builder stage always runs on the build host platform (BUILDPLATFORM) to
# avoid QEMU emulation; Go cross-compiles through TARGETOS/TARGETARCH.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" \
    go build -ldflags "-X main.version=${VERSION}" -o ratelimit-operator ./operator/cmd/

FROM ghcr.io/netcracker/qubership-core-base:2.3.7
WORKDIR /app
COPY --chown=10001:0 --chmod=555 --from=builder /app/ratelimit-operator /app/ratelimit-operator
COPY --chown=10001:0 --chmod=444 --from=builder /app/operator/application.yaml /app/application.yaml
USER 10001:10001

CMD ["/app/ratelimit-operator"]
