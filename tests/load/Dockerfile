# The load test image: Apache JMeter with the plan of tests/load/jmeter,
# loadkit, which writes the tokens and checks the results, and run.sh, which
# drives one generator. Built from the repository root:
#
#   docker build -f tests/load/Dockerfile .

FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS builder
ARG TARGETOS
ARG TARGETARCH
# Allow Go toolchain auto-download when the image patch is older than the
# minimum declared in go.mod.
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum ./
# The engine module is replace-directed to ./engine, so its go.mod has to be
# present for the module graph to load.
COPY engine/go.mod engine/go.mod
COPY tests/load/loadkit tests/load/loadkit
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" go build -o /loadkit ./tests/load/loadkit

# JMeter is plain Java, so one download serves every platform.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS jmeter
ARG JMETER_VERSION=5.6.3
ARG JMETER_SHA512=5978a1a35edb5a7d428e270564ff49d2b1b257a65e17a759d259a9283fc17093e522fe46f474a043864aea6910683486340706d745fcdf3db1505fd71e689083
WORKDIR /opt
# The CDN carries the current release only, the archive every release; the
# checksum holds the download to the same file either way, and curl follows
# no redirect away from HTTPS.
RUN apk add --no-cache curl \
    && { curl -fsSL --proto '=https' --proto-redir '=https' -O \
           "https://dlcdn.apache.org/jmeter/binaries/apache-jmeter-${JMETER_VERSION}.tgz" \
      || curl -fsSL --proto '=https' --proto-redir '=https' -O \
           "https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-${JMETER_VERSION}.tgz"; } \
    && echo "${JMETER_SHA512}  apache-jmeter-${JMETER_VERSION}.tgz" | sha512sum -c - \
    && tar xzf "apache-jmeter-${JMETER_VERSION}.tgz" \
    && mv "apache-jmeter-${JMETER_VERSION}" jmeter \
    && rm -rf "apache-jmeter-${JMETER_VERSION}.tgz" jmeter/docs jmeter/printable_docs jmeter/bin/examples
# The plan and the driver get their modes here: COPY --chmod would give the
# directory it creates the files' mode too, and a directory without the
# execute bit stops the non-root user from reaching run.sh.
COPY tests/load/jmeter/ratelimit-load.jmx tests/load/jmeter/loadtest.properties tests/load/jmeter/pick.groovy \
    tests/load/run.sh /opt/loadtest/
RUN chmod 755 /opt/loadtest \
    && chmod 444 /opt/loadtest/ratelimit-load.jmx /opt/loadtest/loadtest.properties /opt/loadtest/pick.groovy \
    && chmod 555 /opt/loadtest/run.sh

FROM eclipse-temurin:21-jre-alpine-3.24@sha256:51ab5e3302e7141ce665ca3ea85e8b5cd648eafbc3c0c90dd79d6537684e4555
COPY --from=jmeter /opt/jmeter /opt/jmeter
COPY --chmod=555 --from=builder /loadkit /usr/local/bin/loadkit
COPY --from=jmeter /opt/loadtest /opt/loadtest
ENV PATH=/opt/jmeter/bin:$PATH
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/loadtest/run.sh"]
