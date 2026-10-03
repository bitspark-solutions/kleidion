# Kleidion Tiltfile — dev orchestration over docker compose.
#
# Works with Docker Desktop out of the box. For Podman:
#   export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"   (Linux/mac)
#   $env:DOCKER_HOST = "npipe:////./pipe/podman-machine-default"      (Windows)
# then `tilt up` builds and runs everything through podman's
# Docker-compatible API — no Tiltfile changes needed.
#
# Usage:
#   tilt up            # whole stack (db, server, web, mailpit)
#   tilt up server web # subset

docker_compose("./docker-compose.yml")

# --- Live update: Go server (air hot-reload lands in P1.1; for now rebuild on change) ---
dc_resource(
    "server",
    trigger=["apps/server"],
)

# --- Live update: Next.js web (source synced into the running dev container, HMR picks up) ---
dc_resource(
    "web",
    live_update=[
        sync("./apps/web", "/app/apps/web"),
        sync("./packages", "/app/packages"),
    ],
    trigger=["apps/web", "packages"],
)
