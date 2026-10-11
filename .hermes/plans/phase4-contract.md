# Phase 4 contract — Extension + sharing + TOTP

Authoritative API + data contract for Phase 4. Mirrors `phase3-contract.md` format.
Master plan: `2026-10-03_1405-kleidion-master-plan.md` §6 Phase 4.

## Security invariants (non-negotiable)

- Server never sees: vault keys in the clear, item contents, TOTP seeds, share-link
  plaintext. Share links carry the decryption key in the URL **fragment** only.
- All client crypto goes through `@kleidion/crypto`; no ad-hoc sodium calls in apps
  (the ad-hoc keypair gen in `auth-client.ts` moves into the package in Step A).
- Extension holds no keys on disk. `chrome.storage.session` (cleared on browser exit)
  for session material only; auto-lock timer enforced client-side.
- Zero-knowledge role model: server enforces roles (`vault_keys.role`) on writes; it
  cannot read what a member writes but can refuse unauthorized writes.

## Execution order (critical path)

A. Per-vault key model migration (ADR-006 prerequisite) + deviceId gap fix
B. TOTP in `packages/crypto` + live codes in web
C. Share links (1:1, time/view limited) — server + web
D. Shared vaults: member invites, roles, UI — server + web
E. `apps/extension` (WXT MV3): scaffold, popup, autofill — reuses A–D
F. Firefox parity pass + exit-criteria E2E

## Step A — Per-vault key model (required before any sharing)

Implement ADR-006 "Phase 4 migration":

1. `packages/crypto`: export `generateX25519Keypair(seed?)` and
   `sealedBoxOpen(cipher, recipientPub, recipientPriv)` / `sealedBoxSeal` wrappers
   (retire duplicate sodium usage in web).
2. Unlock path: `GET /v1/vaults` must return each vault's `wrapped_vault_key` + role
   for the requesting user (server: join `vault_keys`). Client unwraps per vault with
   its X25519 private key → `Map<vaultId, Uint8Array>` in session context with
   `getVaultKey(vaultId)`.
3. Phase 3 accounts (personal vault encrypted with `symKey`): migration-on-unlock —
   if the vault's `vault_keys` row is missing or its wrapped key fails to unwrap,
   re-wrap `symKey` for the account keypair, upload via new
   `PUT /v1/vaults/:id/keys/:me {wrappedVaultKey}`, then proceed. Personal vault's
   items stay encrypted under the same bytes (symKey == vault key), so no item
   re-encryption is needed for personal vaults.
4. Enroll path: generate per-vault key client-side at personal-vault creation; store
   wrapped. Web + server changes in `auth_handlers.go` / `auth-client.ts`.
5. Mechanical call-site updates: `VaultShell`, `ItemList`, `ItemDetail`, `ItemEditor`
   take per-vault key. `searchHmac` is derived per vault key (already keyed by vault
   key in `packages/crypto`; verify call sites pass the right one).
6. deviceId gap (ADR-006 "known gap"): add `deviceId` to `SrpFinishResponse`, store in
   `session.ts`, use real id in `POST /v1/sync/cursor`.

## Step B — TOTP (RFC 6238)

- `packages/crypto/src/totp.ts`:
  - `parseOtpauthUri(uri) → {secret(b32), issuer, account, digits, period, algo}`
  - `totpNow(secretBase32, at?: Date, opts?) → {code, secondsRemaining}` (HMAC-SHA1
    default; SHA256/SHA512 accepted). Pure TS + sodium `crypto_auth_hmacsha*`.
  - Test vectors: RFC 6238 appendix (SHA1) + comparison vs known Google Authenticator
    vectors. Export from index.
- `packages/core`: Login item field kind `totp` already exists in the enum — add
  `TotpSecretField` zod helper + `totp` handling in `ItemPlain` field validation.
- Web: `ItemDetail.tsx` renders a live-countdown code chip for `totp` fields
  (6/8 digits), copy button with auto-clear, otpauth URI input in `ItemEditor`
  (already accepts it; parse + validate on save).

## Step C — Share links (1:1, time/view limited)

Data model (migration `000004_share_links`):

```sql
CREATE TABLE share_links (
  id uuid PK DEFAULT gen_random_uuid(),
  token_hash bytea NOT NULL UNIQUE,       -- SHA-256 of random 256-bit link token
  creator_id uuid FK users NOT NULL,
  item_id uuid FK items NOT NULL,
  wrapped_item bytea NOT NULL,            -- item JSON re-encrypted w/ linkKey (XChaCha20-Poly1305)
  wrapped_nonce bytea NOT NULL,
  link_key_wrapped bytea,                 -- optional: linkKey sealed for a specific recipient user
  recipient_email text,                   -- if 1:1 (normalized, lowercased)
  view_only bool NOT NULL DEFAULT true,
  expires_at timestamptz NOT NULL,
  max_views int,                          -- NULL = unlimited
  views int NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

API (authed unless noted):

```
POST /v1/share-links        {itemId, wrappedItem, wrappedNonce, expiresAt, maxViews,
                             viewOnly, recipientEmail?, linkKeyWrapped?}
                           → {id, token}              (token returned ONCE, never stored)
GET  /v1/share-links                                  → creator's links (no token)
DELETE /v1/share-links/:id                            → revoke
GET  /public/share-links/:token      (UNAUTHED; hashes token, checks expiry/views,
                                     atomically increments views, returns ciphertext)
```

Client: creator generates random `linkKey`, re-encrypts decrypted item with it, URL =
`{origin}/share/#{token}`. Recipient page (public route in web, no login required)
fetches ciphertext by token, decrypts from fragment key, renders read-only. Server
never sees linkKey or plaintext. Views increment in the same txn as the read.

## Step D — Shared vaults + member invites + roles

- Server (store + handlers), all authed:
  - `POST /v1/vaults` with `kind: shared` (creator gets `vault_keys` row, role admin).
  - `POST /v1/vaults/:id/members {email, role, wrappedVaultKey}` — requester must have
    role `admin`; looks up user by email, inserts `vault_keys` row. Server never sees
    the vault key (sealed-box ciphertext).
  - `GET /v1/vaults/:id/members` → members (email, role, created_at).
  - `PATCH /v1/vaults/:id/members/:userId {role}` (admin only; cannot demote last admin).
  - `DELETE /v1/vaults/:id/members/:userId` (admin or self-leave).
  - Item read/write routes already role-check reads (member of vault) and writes
    (`role in admin|write`); verify + cover with tests.
- Client: invite flow = fetch recipient `master_public_key` (server exposes it on
  member lookup by email — public user directory endpoint `GET /v1/users/lookup?email=`
  returning {userId, email, masterPublicKey} only), seal vault key with it, upload.
- Web UI: vault create (shared), members panel (list/invite/role/remove), shared-vault
  badge in sidebar, read-only mode when `role=read`.

## Step E — apps/extension (WXT, MV3, Chrome + Firefox)

- Scaffold: `apps/extension` via WXT (`wxt` + `@wxt-dev/module-react`), React 19,
  Tailwind (same scale as web), imports `@kleidion/crypto` + `@kleidion/core`
  workspace deps. Add to root `package.json` workspaces. Dev: `wxt dev` loads
  unpacked; add Tiltfile service (build → unzip to `dist/extension` volume, per
  master plan §"extension" hot-reload note); no Docker runtime for the extension itself.
- Popup: signin (SRP via shared `packages/crypto` + core API client pointed at
  `API_BASE` env with dev default `http://localhost:8080`), vault browse, search.
- Session: keys in `chrome.storage.session` only; background (service worker) owns
  the key map + auto-lock timer (default 15 min idle, same as web); content scripts
  request decrypted values from background via messaging only for the matched origin.
- Content script: on `https://*/*`, detect `input[type=password]`/`[type=email]` and
  signin forms; URL → item match via `normalizeTitle`/host matching incl.
  equivalent-domain rules (new pure fn in `packages/core`: `domainsEquivalent(a,b)`);
  inline suggestions menu (shadow DOM), fill on click/Enter; new-item capture prompt
  on submit; badge count of matches for current tab.
- TOTP chip in popup for matched login.

## packages/core additions (build before consumers)

`ShareLink` schemas, `VaultMember` schemas, `users/lookup` types, `SrpFinishResponse.deviceId`,
`domainsEquivalent()`, `api.ts` client methods for all above.

## Testing (required for done)

- crypto: TOTP RFC 6238 vectors; sealed-box round-trip; per-vault unwrap incl.
  Phase-3 re-wrap migration path. Go: share-link lifecycle (create/spend/expire/revoke,
  concurrent view increment), member role matrix (read/write/admin × CRUD),
  vault-keys returned per requesting member only.
- web: vitest for share page decrypt, members panel state machine.
- extension: WXT build green for chrome + firefox; manual E2E script in
  `apps/extension/docs/e2e.md` covering the exit criteria.

## Exit criteria (from master plan)

1. Autofill on gmail.com from a signed-in extension session in <2 clicks.
2. Share a login with a second account (share link AND shared-vault member path).
3. TOTP codes match Google Authenticator (RFC vectors + live app check).

## Conventions (from ADRs / existing code)

- camelCase on the wire; zod-validate at client boundary; Go handlers decode into
  `map[string]any`-free typed structs; migrations via embedded golang-migrate SQL.
- AGPL headers untouched; commit style `feat(phase4): …` / `fix: …`.
- Cargo-culted from ADR-005/006: libsodium WASM only, one crypto implementation.
