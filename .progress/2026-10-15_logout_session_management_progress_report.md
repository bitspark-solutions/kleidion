# Logout & Session Management — kleidion — Progress Report (2026-10-15)

## Landed on main (merge `e64138c`, pushed)
Server (`9546fcd`):
- `POST /v1/auth/logout` now behind `RequireSession`; sets `revoked_at` → token dies immediately (was: no-op returning ok — the audit's P0).
- `GET /v1/sessions` — device name/platform, server-captured User-Agent, created/last-used/expires, `current` flag. `DELETE /v1/sessions/:id` — owner-scoped; foreign/unknown/malformed → uniform 404/400.
- Migration `000005_session_metadata` (`user_agent`, `last_used_at`); throttled ≤1/min touch. Tokens remain SHA-256-hashed; zero-knowledge design unchanged (no plaintext or vault-derived material in session metadata).

Web (`4928dd2`):
- `/vault/settings` → SessionsView: list, per-session Revoke, "Sign out of this device" → real endpoint + `lock()` + `/signin` redirect.

Chore (`04ab93b`): gofmt on pre-existing drift in `vault_handlers.go`.

## Verification (independently re-run by parent after agent report)
- `gofmt -l` clean, `go vet ./...` clean.
- `go test ./... -count=1` with `KLEIDION_TEST_DATABASE_URL` set → api 5.5s **ok** (integration suite actually executed, not skipped), auth ok, srp ok.
- `tsc --noEmit` (web) clean.
- Agent's live walk (server :18082 vs compose DB): enroll → SRP finish → vaults 200 → sessions 200 → logout 200 → vaults/sessions/logout-replay all **401**.

## Ops notes
- `kleidion_db-data` volume had a stale password vs `.env`; fixed in-container via trust-socket `ALTER USER` (no data loss).
- Test-DB procedure captured as skill `kleidion-test-db-bringup`.
- compose `kleidion-db-1` left running (healthy).

## Still open from the digest (next kleidion packages)
README phase-status honesty + landing-page passkeys copy removal; Bitwarden import/encrypted export; trash restore + version rollback; `scripts/verify-all.sh` + committed E2E harness; HIBP k-anonymity; crypto coverage 83.1% → 95% gate.
