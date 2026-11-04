# syntax=docker/dockerfile:1
# The build stage runs natively and cross-compiles for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/ImSingee/mcp-webhook-events/internal/version.Version=${VERSION}" \
      -o /out/mwe-server ./cmd/mwe-server && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/ImSingee/mcp-webhook-events/internal/version.Version=${VERSION}" \
      -o /out/mwe ./cmd/mwe

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 65532 nonroot && useradd --system --uid 65532 --gid nonroot --home /data nonroot && \
    mkdir -p /data && chown nonroot:nonroot /data
COPY --from=build /out/mwe-server /out/mwe /usr/local/bin/
ENV MWE_ADDR=:8080 MWE_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/mwe-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/mwe-server"]
