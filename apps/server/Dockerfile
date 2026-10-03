# syntax=docker/dockerfile:1
# Kleidion server — multi-stage, OCI-compatible (docker build AND podman build),
# runs as non-root (rootless podman safe). No BuildKit-only features in the
# default path.

# Pinned to the patch version so builds are reproducible; go.mod also declares
# `go 1.27.1` (GOTOOLCHAIN=auto would fetch it anyway, but matching the image
# avoids a surprise download at build time).
FROM golang:1.27.1-alpine AS builder
WORKDIR /src
# Dependencies first for layer caching
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary, no cgo
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=builder /out/server ./server
EXPOSE 8080
ENTRYPOINT ["./server"]
