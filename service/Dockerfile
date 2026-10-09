# The service image, built from the repository root: the service's tree
# imports the root module's internal packages and the engine module, so the
# context is the whole repository and the Dockerfile lives here so it is
# found beside the code it builds.
#
#   docker build -f service/Dockerfile .

FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS builder
ARG TARGETOS
ARG TARGETARCH
# The build's own version stamp, and the fallback only: the pipeline passes
# no build arguments, so ratelimit_build_info reports SERVICE_VERSION from
# the container's environment, which the chart sets.
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
    go build -ldflags "-X main.version=${VERSION}" -o ratelimit-service ./service/cmd/

# The binary carries no Kubernetes client, and the image proves it: the same
# check CI runs, so an image that leaks one is never pushed.
RUN go version -m ratelimit-service | grep -E '^\s+dep\s+(k8s.io/client-go|sigs.k8s.io/controller-runtime)\s' \
    && { echo "the service binary depends on a Kubernetes client"; exit 1; } || true

FROM ghcr.io/netcracker/qubership-core-base:alpine-2.5.7@sha256:f0836415633bc2a63c2a0431c4c0701d17bd7b31132176b26651b49927d9ad7e
WORKDIR /app
COPY --chown=10001:0 --chmod=555 --from=builder /app/ratelimit-service /app/ratelimit-service
COPY --chown=10001:0 --chmod=444 --from=builder /app/service/application.yaml /app/application.yaml
USER 10001:10001

CMD ["/app/ratelimit-service"]
