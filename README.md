# Kleidion

**Your keys, yours alone.** A zero-knowledge, end-to-end-encrypted password manager —
production-grade security with open source (AGPL) code.

> Greek *kleídion* (κλείδιον) — "little key".

## Status

Phase 1 (infrastructure). See the [master plan](.hermes/plans/2026-10-03_1405-kleidion-master-plan.md)
for the full roadmap: auth/SRP crypto core → vaults & sync → browser extension → desktop (Tauri) &
mobile (Expo) → security-health audit/passkeys/travel masking → CLI & teams.

## Monorepo

| Path | What |
|---|---|
| `apps/server` | Go backend (Gin, PostgreSQL, SRP-6a auth, zero-knowledge storage) |
| `apps/web` | Next.js 16 / React 19 web vault |
| `apps/extension` | Browser extension (WXT, MV3) — Phase 4 |
| `apps/desktop` | Tauri 2 desktop shell — Phase 5 |
| `apps/mobile` | Expo (iOS/Android) — Phase 5 |
| `apps/cli` | `kleidion` CLI + SSH agent — Phase 7 |
| `packages/crypto` | Shared client crypto (libsodium): key derivation, SRP, item encryption |
| `packages/core` | Shared zod schemas + API types |

## Development

Prerequisites: Docker Desktop **or** Podman (machine running), Tilt (optional), Node 24+, Go 1.26+.

```bash
cp .env.example .env          # dev-only defaults, fine as-is

# Option A — Tilt (hot reload, web UI at http://localhost:10350)
tilt up

# Option B — plain compose (works with docker compose AND podman-compose)
docker compose up -d --build   # or: podman-compose up -d --build

# Verify
curl http://localhost:8080/healthz   # {"status":"ok"}
open  http://localhost:3000          # web vault
open  http://localhost:8025          # mailpit (dev email)
```

### Podman

```bash
podman machine init && podman machine start
# Windows:  $env:DOCKER_HOST = "npipe:////./pipe/podman-machine-default"
# Linux/mac: export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
podman-compose up -d --build
```

## Security model (summary)

- **Zero knowledge:** all encryption/decryption happens on client devices. The server stores only
  ciphertext, SRP verifiers, and metadata.
- **Two secrets (2SKD):** account password + device-held Secret Key derive the unlock key; a
  stolen server database is useless without the Secret Key.
- **SRP-6a authentication:** the password is never transmitted — client and server prove knowledge
  of secrets to each other (RFC 5054).
- **Key hierarchy:** AUK → user keypair → per-vault keys → items (XChaCha20-Poly1305).

Full design in the master plan; ADRs in `infra/docs/adr/`.

## License

AGPL-3.0-or-later (client and server). See LICENSE.
