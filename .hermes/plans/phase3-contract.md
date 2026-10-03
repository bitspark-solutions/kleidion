# Phase 3 Contract: Vaults, Items, Sync

Authoritative API + data contract. Both backend and frontend implement EXACTLY this.
Do not invent fields. If something is missing, implement what's specified and note the gap.

## Security invariants (non-negotiable)
- Server NEVER sees plaintext. It stores opaque `ciphertext`+`nonce`+`search_hmac` only.
- Vault names are ALSO encrypted client-side (stored as ciphertext in an item-like row
  or in `vaults.encrypted_meta`).
- All crypto uses `packages/crypto` (`@kleidion/crypto`) on the client; never re-implement.
- Zero-knowledge canary test required (see Testing).

## Data model (migration 000003_vaults_items.up.sql)

```sql
CREATE TABLE vaults (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            text NOT NULL DEFAULT 'personal',   -- personal | shared
    encrypted_meta  bytea NOT NULL,                     -- {name,...} encrypted w/ vault key
    nonce           bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE vault_keys (
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_vault_key bytea NOT NULL,                   -- sealed box w/ member X25519 pub
    role            text NOT NULL DEFAULT 'admin',      -- admin | write | read
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE items (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    item_type       smallint NOT NULL,                  -- 1=Login 2=SecureNote 3=Card 4=Identity
    ciphertext      bytea NOT NULL,
    nonce           bytea NOT NULL,
    search_hmac     bytea,                              -- nullable; enables server-side match
    version         bigint NOT NULL DEFAULT 1,          -- monotonic per vault; drives delta sync
    favorite        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz                         -- soft delete (trash)
);
CREATE INDEX idx_items_vault_version ON items(vault_id, version);
CREATE INDEX idx_items_search_hmac ON items(search_hmac);

CREATE TABLE item_versions (                             -- history: keep prior ciphertexts
    item_id         uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    version         bigint NOT NULL,
    ciphertext      bytea NOT NULL,
    nonce           bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, version)
);

CREATE TABLE sync_cursors (
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    last_version    bigint NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, vault_id)
);
```
Provide matching `.down.sql`. Reuse existing migration/embed pattern
(`internal/store/migrations/sql/`). Bump nothing else.

## REST API (all under /v1, JSON, require session auth)

Auth: `Authorization: Bearer <sessionToken>`. Middleware resolves the token
(SHA-256 hash lookup via `store.GetSessionByTokenHash`), rejects expired/revoked,
sets `userID` on gin context. Return 401 on failure. Add
`internal/api/middleware.go` exporting `RequireSession(st *store.Store) gin.HandlerFunc`
and the context key constant. Wire it onto the vault/item/sync route groups only.

```
GET    /v1/vaults                 -> 200 {vaults:[VaultMeta]}
POST   /v1/vaults                 -> 201 {vault:VaultMeta}
GET    /v1/items?vaultId=&since=&searchHmac=   -> 200 {items:[Item], serverVersion:int}
POST   /v1/items                  -> 201 {item:Item}
PUT    /v1/items/:id              -> 200 {item:Item}
DELETE /v1/items/:id              -> 200 {item:Item}          (soft delete; bumps version)
GET    /v1/items/:id/versions     -> 200 {versions:[{version,createdAt}]}
GET    /v1/sync/changes?vaultId=&since=  -> 200 {changes:[Item], latestVersion:int, hasMore:false}
POST   /v1/sync/cursor            -> 200 {ok:true}            (body: {vaultId,lastVersion,deviceId})
```

### JSON shapes (camelCase on the wire)
```ts
VaultMeta = { id:string, kind:"personal"|"shared", encryptedMeta:string/*b64*/,
              nonce:string/*b64*/, role:"admin"|"write"|"read",
              createdAt:string, updatedAt:string }
Item      = { id:string, vaultId:string, itemType:number,
              ciphertext:string/*b64*/, nonce:string/*b64*/,
              searchHmac:string|null/*b64*/, version:number, favorite:boolean,
              createdAt:string, updatedAt:string, deletedAt:string|null }
```
Binary fields are **base64** on the wire. Server stores `bytea`.
Item plaintext JSON (client-side only, server never sees) is:
```ts
ItemPlain = { title:string, notes?:string, tags?:string[],
              fields?: {label:string, value:string, type:"text"|"password"|"url"|"totp"}[] }
```
`itemType` mapping: 1 Login, 2 SecureNote, 3 Card, 4 Identity.

### Versioning / sync rules
- Every create/update/delete on an item bumps the VAULT's max version by 1 and
  assigns it to that item (compute as `COALESCE(MAX(version),0)+1` within the
  vault, inside the same transaction as the write).
- `item_versions` gets the PREVIOUS ciphertext inserted on each update (not on create).
- `GET /v1/items?since=N` returns items with `version > N` (including soft-deleted
  ones, so clients can apply the tombstone). `searchHmac` filter is exact-match AND.
- Last-write-wins. No merge logic server-side.

### Validation (return 400 with `{"error":"..."}`)
- `vaultId` must be a uuid the caller has a `vault_keys` row for.
- `itemType` must be 1..4.
- `ciphertext`/`nonce` must be non-empty base64; nonce must decode to 24 bytes.
- `searchHmac` if present must decode to 32 bytes.
- Enforce max ciphertext size 1 MiB (reject larger).
- Authorization: `role="read"` members may GET but not POST/PUT/DELETE (403).

## packages/core (TS) — build this FIRST, others depend on it
Add real zod schemas + inferred types for `VaultMeta`, `Item`, `ItemPlain`, and all
request/response bodies above, in `packages/core/src/schemas.ts`. Export a tiny API
client in `packages/core/src/api.ts`:
```ts
createApiClient({baseUrl, getToken}): {
  listVaults(), createVault(input), listItems(params), createItem(input),
  updateItem(id,input), deleteItem(id), itemVersions(id), syncChanges(params), postCursor(input)
}
```
Use native `fetch`. Throw on non-2xx with the server's `{"error"}` message.
Add vitest tests for the schemas (valid + invalid cases). Replace the `PHASE` stub.

## Web vault UI (apps/web) — Phase 3 scope
Routes (App Router, `app/`):
- `/vault` — main shell: left sidebar (vaults, categories by itemType, Favorites, Trash),
  center item list with search, right pane item detail.
- `/vault/[itemId]` optional; a detail panel in the same route is fine.
- `/signin`, `/signup` — implement the REAL flows against the Go API using
  `@kleidion/crypto` (derive x via 2SKD → verifier → SRP start/finish; on signup
  generate Secret Key, X25519 keypair, wrap private key with AUK, show Emergency Kit
  with a mandatory "I saved it" gate before finishing).
- Locked/unlocked state machine: session + AUK in memory ONLY (never localStorage).
  Vault keys unwrapped after unlock, held in memory; auto-lock after 15 min idle.

Components to build (Tailwind 4 + existing `@theme` tokens in `app/globals.css`;
match the existing dark theme — do NOT add MUI):
- `VaultShell`, `VaultSidebar`, `ItemList`, `ItemDetail`, `ItemEditor`,
  `PasswordGenerator` (recipe builder: length, char classes, passphrase mode with
  word count+separator; show strength estimate), `EmergencyKit`, `LockScreen`.
- Copy-to-clipboard with 30s auto-clear + visual countdown; reveal toggles for secrets.

State: TanStack Query v5 for server state (install it). Keep the unlocked-key material
in a module-scoped store (plain TS module or zustand — your call, but NOT localStorage).

Item creation flow: build `ItemPlain` → `JSON.stringify` → `encryptItem(vaultKey, json)`
→ POST with base64 fields. Item render: decrypt then display.

## Testing (required for done)
1. **Go**: unit tests for store repos + handlers. Integration tests against real
   Postgres following the existing pattern in
   `apps/server/internal/auth/service_integration_test.go`
   (gated on `KLEIDION_TEST_DATABASE_URL`, `t.Skip` when unset).
   Cover: version bumping, since-delta, soft delete tombstone, read-role 403,
   validation 400s, unauthorized 401.
2. **ZERO-KNOWLEDGE CANARY (critical)**: integration test that creates an item whose
   plaintext contains a unique canary string (e.g. `CANARY-<uuid>`), then asserts the
   canary appears NOWHERE in: the raw `items` row bytes, any API response body, or
   server logs. Query `pg_catalog`/raw bytes to prove it.
3. **TS**: vitest for packages/core schemas + api client (mock fetch).
4. Everything must pass: `go build ./... && go vet ./... && go test ./...`,
   `npm run test --workspace @kleidion/crypto`, `npm run test --workspace @kleidion/core`,
   `npm run web:typecheck`, `npm run web:build`.

## Conventions (from ADRs / existing code)
- One type per file where practical; `internal/` layout; package comments.
- Errors: `store.ErrNotFound` → 404/400; auth errors → 401/403; uniform
  `respondError(c, status, msg)` helper already exists in `internal/api/auth_handlers.go`.
- Postgres via `s.Pool` (pgx/v5); see `internal/store/users.go` for the Scan pattern.
- Do NOT use `build.dockerfile:` in compose (podman-compose ignores it — ADR-004).
- Windows host: use `./scripts/engine.sh status` before docker work; only ONE engine runs.
- Git: `git config --global --add safe.directory D:/projects/kleidion` may be needed.
- DO NOT create commits — leave changes staged-or-unstaged for the parent to review.
