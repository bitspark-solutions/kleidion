#!/usr/bin/env bash
# verify-stack.sh — prove the Kleidion stack is healthy on the ACTIVE engine.
#
# Boots db+server+web+mailpit, waits for health, asserts every endpoint, then
# (optionally) tears down. Engine-agnostic: uses `docker compose` or
# `podman-compose` depending on $KLEIDION_ENGINE (default: docker).
#
# USAGE
#   ./scripts/verify-stack.sh              # docker
#   KLEIDION_ENGINE=podman ./scripts/verify-stack.sh
#   KEEP_UP=1 ./scripts/verify-stack.sh    # leave the stack running

set -euo pipefail

ENGINE="${KLEIDION_ENGINE:-docker}"

# Load generated port assignments. On Windows these are NOT hardcoded-safe:
# Hyper-V reserves dynamic WinNAT excluded-port ranges that shift every reboot,
# so scripts/gen-env.sh picks ports that are actually bindable right now.
if [ -f "$(dirname "$0")/../.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$(dirname "$0")/../.env"
  set +a
fi

API="http://localhost:${KLEIDION_API_HOST_PORT:-18080}"
WEB="http://localhost:${KLEIDION_WEB_HOST_PORT:-13000}"

case "$ENGINE" in
  docker) COMPOSE=(docker compose) ;;
  podman)
    export PATH="$PATH:/c/Program Files/RedHat/Podman:$HOME/AppData/Roaming/Python/Python311/Scripts"
    COMPOSE=(podman-compose)
    unset DOCKER_HOST CONTAINER_HOST || true   # podman CLI uses its native pipe
    ;;
  *) echo "KLEIDION_ENGINE must be docker|podman" >&2; exit 2 ;;
esac

log()  { printf '[verify:%s] %s\n' "$ENGINE" "$*"; }
# On failure show ONLY recent logs — old container logs otherwise bury the
# real error under stale noise (e.g. auth failures from hours earlier).
fail() { printf '[verify:%s] FAIL: %s\n' "$ENGINE" "$*" >&2; "${COMPOSE[@]}" logs --since 2m --tail=25 || true; exit 1; }

check() { # check <label> <expected-substring> <url>
  local body; body="$(curl -s -m 10 "$3" || true)"
  if [[ "$body" != *"$2"* ]]; then fail "$1: got '$body' (want substring '$2') at $3"; fi
  log "ok $1"
}

# check_retry <label> <expected-substring> <url> <attempts> — for slow starters.
# `next dev` compiles on first request (~30s cold), so a single curl is not enough.
check_retry() {
  local label="$1" want="$2" url="$3" attempts="${4:-12}" i body
  for ((i = 1; i <= attempts; i++)); do
    body="$(curl -s -m 30 "$url" || true)"
    if [[ "$body" == *"$want"* ]]; then log "ok $label (attempt $i)"; return 0; fi
    sleep 5
  done
  fail "$label: never returned '$want' after $attempts attempts (last: '${body:0:200}')"
}

log "validating compose file"
"${COMPOSE[@]}" config >/dev/null || fail "compose config invalid"

log "building"
"${COMPOSE[@]}" build >/dev/null || fail "build failed"

log "starting stack"
"${COMPOSE[@]}" up -d || fail "up failed"

log "waiting for API /healthz (up to 120s)"
for i in $(seq 1 60); do
  if curl -sf -m 3 "$API/healthz" >/dev/null 2>&1; then break; fi
  [ "$i" = 60 ] && fail "API never became healthy"
  sleep 2
done

check "/healthz" '"status":"ok"'      "$API/healthz"
check "/readyz"  '"status":"ready"'   "$API/readyz"
check "/v1/status" '"api":"v1"'       "$API/v1/status"
# Web needs a retry: next dev compiles on first request.
check_retry "web" 'Kleidion'          "$WEB" 12

log "asserting migrations applied (schema_migrations not dirty)"
if [ "$ENGINE" = docker ]; then
  CID=$(docker ps -qf "name=kleidion-db" | head -1)
  docker exec "$CID" psql -U kleidion -d kleidion -tAc "SELECT dirty FROM schema_migrations ORDER BY version DESC LIMIT 1;" | grep -qx 'f' \
    || fail "migrations dirty or missing"
else
  CID=$(podman ps -q --filter "name=kleidion_db" | head -1)
  podman exec "$CID" psql -U kleidion -d kleidion -tAc "SELECT dirty FROM schema_migrations ORDER BY version DESC LIMIT 1;" | grep -qx 'f' \
    || fail "migrations dirty or missing"
fi
log "ok migrations clean"

log "asserting auth routes are wired"
# Gin returns 404 for a METHOD mismatch, so probing with GET is useless. Instead
# POST an empty body: a registered route reaches the handler and fails validation
# with 400, while an unregistered path returns 404.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$API/v1/auth/srp/start" \
  -H 'Content-Type: application/json' -d '{}' || true)
if [ "$code" != "400" ]; then
  fail "auth routes not wired: POST /v1/auth/srp/start -> $code (expected 400 validation error)"
fi
log "ok POST /v1/auth/srp/start -> 400 (handler reached, validation ran)"

code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$API/v1/auth/enroll" \
  -H 'Content-Type: application/json' -d '{}' || true)
if [ "$code" != "400" ]; then
  fail "auth routes not wired: POST /v1/auth/enroll -> $code (expected 400 validation error)"
fi
log "ok POST /v1/auth/enroll -> 400 (handler reached, validation ran)"

# Sanity: an unregistered path must be 404, proving the checks above are meaningful.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$API/v1/definitely-not-a-route" || true)
if [ "$code" != "404" ]; then
  fail "expected 404 for unregistered route, got $code"
fi
log "ok unregistered route -> 404"

log "ALL CHECKS PASSED on $ENGINE"
if [ "${KEEP_UP:-0}" != "1" ]; then
  log "tearing down"
  "${COMPOSE[@]}" down >/dev/null || true
fi
