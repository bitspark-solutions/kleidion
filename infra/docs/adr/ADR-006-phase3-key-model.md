# ADR-006: Phase 3 key model — single account key in UI, per-vault keys deferred

Date: 2026-10-03 · Status: accepted (interim; supersedes part of ADR-005's vault-key plan for Phase 3)

## Context

The Phase 3 contract specified 1Password-style **per-vault keys**: each vault has a
random 256-bit key, wrapped with every member's X25519 public key (`vault_keys`
table), so sharing a vault means re-wrapping one key rather than re-encrypting items.

The Go backend implements that schema (`vaults`, `vault_keys` with `role`, and role
checks on writes). The **web UI**, however, was built threading a single symmetric
key through React context (`VaultProvider vaultKey=…`), which it uses for both vault
metadata and item ciphertexts.

## Decision

For Phase 3 (personal vaults only, single member), bridge by supplying the
account-wide `symKey` from the unlocked in-memory session
(`apps/web/lib/session.ts` → `KeyMaterial.symKey`) as that single context key.
Wiring lives in `apps/web/app/vault/gate.tsx`.

This is coherent end-to-end: every encrypt/decrypt call still goes through
`@kleidion/crypto` (`encryptItem`/`decryptItem`/`searchHmac`), so nothing bypasses
the reviewed crypto and the zero-knowledge invariant holds. It is a **key-management
simplification, not a crypto weakening**.

## Consequences

- `vault_keys.wrapped_vault_key` is written but not yet consumed by the web client.
- Shared vaults (Phase 4) **cannot** ship until the per-vault map exists — a single
  account key cannot be shared with another user without exposing all their vaults.

## Phase 4 migration (required before shared vaults)

1. On unlock, `GET /v1/vaults` and fetch each vault's `wrapped_vault_key`.
2. Unwrap with `crypto_box_seal_open(wrapped, masterPublicKey, privateKey)` using the
   X25519 keypair already in `KeyMaterial` (`privateKey`/`masterPublicKey`).
3. Replace the single-key context with `{ [vaultId: string]: Uint8Array }` plus a
   `getVaultKey(vaultId)` accessor; update `ItemList`/`ItemDetail`/`ItemEditor`/
   `VaultShell` call sites (mechanical).
4. At enroll, create the personal vault's key client-side and store it wrapped.
5. Keep a migration path for Phase 3 accounts whose personal vault was created with
   `symKey`: store a flag or re-wrap on first Phase 4 login.

## Known gap tracked with this decision

`POST /v1/sync/cursor` requires a `deviceId` that satisfies the FK to `devices`, but
`POST /v1/auth/srp/finish` does not return the device id it just upserted. The web
client therefore sends a random per-tab UUID and swallows the resulting failure, so
**sync cursors are not persisted** (delta sync still works via `since=` polling;
only the saved cursor is lost).

Fix (server + client, small): add `deviceId` to the `SrpFinishResponse`, store it in
`session.ts`, and have `VaultShell` send the real id instead of `DEVICE_ID`.
