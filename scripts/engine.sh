#!/usr/bin/env bash
# engine — switch the active container engine on Windows (Docker Desktop <-> Podman).
#
# WHY THIS EXISTS
#   Docker Desktop and podman-machine BOTH drive WSL2. They can coexist on disk
#   (separate distros: `docker-desktop`, `podman-machine-default`) but only ONE
#   may be RUNNING at a time — a live podman machine blocks Docker Desktop from
#   starting its engine, and vice versa. This script cleanly stops one before
#   starting the other, so `docker compose` and `podman-compose` both work.
#
# USAGE
#   ./scripts/engine.sh status      # show which engine is active
#   ./scripts/engine.sh docker      # stop podman machine, start Docker Desktop
#   ./scripts/engine.sh podman      # quit Docker Desktop, start podman machine
#
# Kleidion's compose files and Dockerfiles are engine-agnostic; this only
# manages which daemon owns the WSL2 backend. See ADR-004.

set -euo pipefail

PODMAN_BIN="/c/Program Files/RedHat/Podman/podman.exe"
DOCKER_DESKTOP="/c/Program Files/Docker/Docker/Docker Desktop.exe"

log()  { printf '[engine] %s\n' "$*"; }
fail() { printf '[engine] ERROR: %s\n' "$*" >&2; exit 1; }

podman_running() {
  command -v "$PODMAN_BIN" >/dev/null 2>&1 || return 1
  "$PODMAN_BIN" machine list --format '{{.Name}} {{.Running}}' 2>/dev/null | grep -qi 'true' 
}

docker_running() {
  docker info >/dev/null 2>&1
}

# Wait for the docker daemon to answer, up to N seconds.
wait_docker() {
  local secs="${1:-120}" waited=0
  while ! docker_running; do
    sleep 5; waited=$((waited + 5))
    [ "$waited" -ge "$secs" ] && return 1
  done
  return 0
}

wait_podman() {
  local secs="${1:-120}" waited=0
  while ! podman_running; do
    sleep 5; waited=$((waited + 5))
    [ "$waited" -ge "$secs" ] && return 1
  done
  return 0
}

cmd_status() {
  echo "WSL distros:"
  wsl.exe -l -v 2>/dev/null | tr -d '\0' | sed 's/^/  /' || true
  echo
  if docker_running; then
    log "ACTIVE ENGINE: docker ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'))"
  else
    log "docker: not running"
  fi
  if podman_running; then
    log "ACTIVE ENGINE: podman ($("$PODMAN_BIN" --version 2>/dev/null | awk '{print $3}'))"
  else
    log "podman machine: not running"
  fi
  if docker_running && podman_running; then
    log "WARNING: both engines report running — stop one to avoid WSL2 contention."
  fi
}

cmd_docker() {
  if podman_running; then
    log "stopping podman machine (frees WSL2 for Docker Desktop)..."
    "$PODMAN_BIN" machine stop >/dev/null 2>&1 || true
  fi
  if docker_running; then
    log "docker already active."
    return 0
  fi
  log "starting Docker Desktop..."
  [ -f "$DOCKER_DESKTOP" ] || fail "Docker Desktop not found at $DOCKER_DESKTOP"
  powershell.exe -NoProfile -Command "Start-Process '$(cygpath -w "$DOCKER_DESKTOP")'" >/dev/null 2>&1 \
    || "$DOCKER_DESKTOP" >/dev/null 2>&1 &
  if wait_docker 180; then
    log "docker READY ($(docker version --format '{{.Server.Version}}'))"
  else
    fail "docker did not become ready in 180s — check Docker Desktop"
  fi
}

cmd_podman() {
  if docker_running; then
    log "quitting Docker Desktop (frees WSL2 for podman machine)..."
    powershell.exe -NoProfile -Command "Get-Process 'Docker Desktop','com.docker.backend' -ErrorAction SilentlyContinue | Stop-Process -Force" >/dev/null 2>&1 || true
    sleep 5
  fi
  [ -x "$PODMAN_BIN" ] || fail "podman not found at $PODMAN_BIN (winget install --id RedHat.Podman)"
  if podman_running; then
    log "podman machine already active."
  else
    log "starting podman machine..."
    "$PODMAN_BIN" machine start >/dev/null 2>&1 || fail "podman machine start failed"
  fi
  wait_podman 180 || fail "podman machine did not become ready"
  log "podman READY ($("$PODMAN_BIN" --version))"
}

case "${1:-status}" in
  status) cmd_status ;;
  docker) cmd_docker ;;
  podman) cmd_podman ;;
  *) fail "usage: engine.sh {status|docker|podman}" ;;
esac
