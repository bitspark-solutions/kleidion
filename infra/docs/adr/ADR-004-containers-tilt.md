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

## Engine coexistence on Windows (Docker Desktop ↔ Podman)

**Only ONE engine may be RUNNING at a time.** Both drive WSL2: Docker Desktop
uses the `docker-desktop` distro, Podman uses `podman-machine-default`. They
coexist fine *on disk* (separate distros, separate image stores), but a live
podman machine blocks Docker Desktop from starting its engine, and vice versa.
Symptom seen: Docker Desktop launched but `docker info` never became ready while
`podman machine list` showed `Currently running`.

This is a **host constraint, not a project incompatibility** — the images and
compose file are engine-agnostic and both were verified. To make switching
painless, `scripts/engine.sh` cleanly stops one before starting the other:

```bash
./scripts/engine.sh status    # show active engine + WSL distro states
./scripts/engine.sh docker    # stop podman machine, start Docker Desktop, wait ready
./scripts/engine.sh podman    # quit Docker Desktop, start podman machine, wait ready
```

Rule: never leave a podman machine running while you expect Docker to work. If
Docker won't start, run `./scripts/engine.sh status` first.

## WinNAT excluded-port ranges (Windows) — do NOT hardcode host ports

Hyper-V/WSL reserves dynamic TCP port ranges at boot (`netsh interface ipv4
show excludedportrange protocol=tcp`). **These ranges shift on every reboot**, so
any port hardcoded in compose can silently become unbindable:

```
Error response from daemon: ports are not available: exposing port TCP
0.0.0.0:13000 -> 127.0.0.1:0: listen tcp 0.0.0.0:13000: bind: An attempt was
made to access a socket in a way forbidden by its access permissions.
```

That message is NOT a permission problem — the port is reserved by WinNAT. It
bites intermittently (worked before a reboot, fails after), and only the affected
container fails while others stay healthy, which is confusing to debug.

**Fix:** `scripts/gen-env.sh` probes the live excluded ranges plus currently
listening ports, then writes bindable assignments to `.env` (compose auto-loads
it). Preferred ports are kept when free; only blocked ones move.

```bash
./scripts/gen-env.sh           # regenerate .env with bindable ports
./scripts/gen-env.sh --check   # report which configured ports are blocked
```

`.env` is gitignored (it also holds the dev DB password and session secret), so
each machine computes its own working ports. Container-side ports stay canonical
(5432/8080/3000/8025/1025) — only host mappings vary.

## Known pitfalls (documented, verified during Phase 1)
- **podman-compose 1.6.0 ignores the `build.dockerfile:` key.** It runs
  `podman build -t <name> <context>` and only auto-discovers a file named
  `Dockerfile`/`Containerfile` at the *context root*. docker compose honors
  `dockerfile:`; podman-compose does not. **Rule adopted: every service's build
  context root contains its own `Dockerfile`, and no service uses a
  `dockerfile:` key.** The web service's context is the repo root (npm
  workspaces need root `package.json`/`package-lock.json` + `packages/*`), so
  the web image's Dockerfile lives at `/Dockerfile`; the server's context is
  `apps/server` with `apps/server/Dockerfile`. Verified: `podman-compose build`
  AND `docker compose build` both succeed on all services.
- Podman registry pushes need `registries.insecure = ['localhost']` in
  `/etc/containers/registries.conf` when using a local registry with Tilt.
- `restart_container()` live-update is compose-only; for Go we rebuild (fast with layer cache)
  until air-based hot reload lands.
- Named volumes only; no bind mounts of Windows paths into containers except via Tilt sync
  (NTFS permission semantics differ).
