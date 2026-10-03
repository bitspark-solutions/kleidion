# Kleidion Tiltfile — dev orchestration over docker compose.
#
# Works with Docker Desktop out of the box. For Podman, point Tilt at podman's
# Docker-compatible socket (podman machine must be running):
#   Windows PowerShell:  $env:DOCKER_HOST = "npipe:////./pipe/podman-machine-default"
#   Linux/mac:           export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
#
# Usage:
#   tilt up --port=11350      # whole stack (db, server, web, mailpit)
#   tilt up server web        # subset
#
# NOTE (Windows): Tilt's default UI port 10350 falls inside the WinNAT
# excluded-port range reserved by Hyper-V/WSL (check with:
# `netsh interface ipv4 show excludedportrange protocol=tcp`). Use --port=11350.
#
# Resources are auto-created from docker-compose.yml (db, server, web,
# mailpit). Tilt watches each service's compose build context and rebuilds
# on change; the web container runs `next dev` with HMR, so synced source
# changes appear without a rebuild.

docker_compose("./docker-compose.yml")
