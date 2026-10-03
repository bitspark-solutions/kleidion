# syntax=docker/dockerfile:1
# Kleidion server — multi-stage, OCI-compatible (docker build AND podman build),
# runs as non-root (rootless podman safe). No BuildKit-only features in the
# default path.

FROM golang:1.26-alpine AS builder
WORKDIR /src
# Dependencies first for layer caching
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary, no cgo
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=builder /out/server ./server
EXPOSE 8080
ENTRYPOINT ["./server"]
