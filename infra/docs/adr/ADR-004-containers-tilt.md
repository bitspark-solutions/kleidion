# ADR-004: Docker + Podman dual compatibility, Tilt for dev orchestration

Date: 2026-10-03 · Status: accepted

## Decision
1. One `docker-compose.yml` written in the portable subset supported by `docker compose`,
   `podman compose` and `podman-compose` ≥1.2.
2. All Dockerfiles use only OCI-compatible classic syntax in the default build path (multi-stage,
   non-root users, no BuildKit-only `RUN --mount` unless gated behind a build arg).
3. Tilt (`Tiltfile` at root) drives the same compose file via `docker_compose()` with live update;
   Podman users point `DOCKER_HOST` at the podman socket (npipe on Windows, unix socket elsewhere)
   and Tilt works unchanged.

## Rationale
- Owner requirement: Docker images must run under both Docker and Podman, with Tilt as the
  single dev entry point.
- Compose-file reuse (instead of separate k8s manifests) keeps dev simple; prod deployment
  (Quadlet systemd units or k8s) is Phase 7 and will consume the same images.

## Known pitfalls (documented, verified during Phase 1)
- Podman registry pushes need `registries.insecure = ['localhost']` in
  `/etc/containers/registries.conf` when using a local registry with Tilt.
- `restart_container()` live-update is compose-only; for Go we rebuild (fast with layer cache)
  until air-based hot reload lands.
- Named volumes only; no bind mounts of Windows paths into containers except via Tilt sync
  (NTFS permission semantics differ).
