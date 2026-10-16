# ADR-008: Vault key rotation on member removal

Date: 2026-10-17 · Status: accepted · Closes the gap recorded in ADR-007

## Context

ADR-007 shipped shared vaults with per-member sealed wraps of one vault key and
recorded this consequence verbatim:

> Member removal does **not** rotate the vault key yet: the removed member keeps
> a copy of the old key and any ciphertext they already synced.

Deleting a `vault_keys` row only stops *future* distribution. Everything the
vault still stores — every item ciphertext, the vault metadata, and the whole
`item_versions` history — remains decryptable with the key that person walked
out the door with. Any later read path that leaks to them (a re-invite, a
mistake in role checks, a support tool) hands back the entire vault. For a
zero-knowledge product, "we removed them from the ACL" is not revocation.

## Decision

Rotation is **client-driven and atomic with the revocation**, because the server
holds no key and cannot rotate anything by itself.

1. `POST /v1/vaults/:id/rotate-key` (admin only) takes a fresh vault key sealed
   for each surviving member, the re-encrypted vault metadata, and a
   re-encrypted payload for **every** item row — tombstones included — plus an
   optional `revokedUserId`. One transaction deletes the revoked wrap, replaces
   all wraps, rewrites all items with new versions, updates the meta, and bumps
   `vaults.key_epoch`.
2. **Completeness is enforced server-side, not trusted from the client.** The
   submitted item set must equal the vault's rows exactly, and the submitted
   wraps must equal the surviving roster exactly (`SELECT … FOR UPDATE` on the
   vault, roster, and item rows). Anything else is a 400 and a no-op. A rotation
   that missed one row would leave that row readable with the retired key, which
   is the entire thing we are trying to prevent.
3. **Roles are never changed by a rotation.** They are copied from the existing
   roster, so a rotation cannot quietly promote a `read` member to `admin` or
   re-grant someone by including their wrap.
4. **`item_versions` for the vault is purged.** Those archives are encrypted with
   the retiring key; after rotation no remaining member can decrypt them, so
   keeping them would preserve exactly the copy we are trying to invalidate.
5. `vaults.key_epoch` (migration 000006) is the staleness signal. It is returned
   by `GET /v1/vaults`, `GET /v1/items` and `GET /v1/sync/changes`. A client
   whose epoch disagrees re-fetches its own wrap and re-unwraps; the web app
   additionally drops its decrypt cache when the key object's identity changes,
   so failures recorded against the retired key cannot be replayed.
6. The extension validates the epoch immediately before writing a new item
   (`writableKey`), because encrypting a fresh capture with a retired key would
   create an item no remaining member can ever decrypt.
7. `GET /v1/vaults/:id/members` now returns each member's `masterPublicKey`,
   which an admin needs to seal the new key for survivors. It is the same value
   `/v1/users/lookup` already discloses to any authenticated member.

Self-removal ("leave") deliberately does **not** rotate: the departing member
holds the key and cannot retire it on behalf of the others. It stays a plain
`DELETE /v1/vaults/:id/members/:userId`.

## Consequences

- Removal costs a full vault re-encryption on the admin's device: every item is
  decrypted (they must already be readable in the local cache) and re-encrypted.
  Rotation is blocked if any row fails to decrypt, and the UI says so rather
  than half-rotating. Vault size is capped at 5000 rows per request.
- **A removed member keeps whatever they already synced.** Nothing can recall
  bytes from a device they control. Rotation makes that copy *stale*, not gone:
  they cannot read anything added or changed after they left, and they lose all
  server read paths at the same instant. This is the same guarantee every
  E2EE manager gives; claiming more would be dishonest.
- Item history is lost on rotation (see decision 4). If history must survive,
  the client would have to re-encrypt every archived version too, which needs a
  new endpoint that ships all historical ciphertexts to one device.
- Rotation invalidates share links' *source* item content only in the sense that
  existing links keep working: a link's ciphertext is wrapped under its own
  one-time link key (ADR-007 §2), not the vault key, so rotation neither breaks
  nor repairs them. Revoking a link stays a separate action.
- Two concurrent admin rotations serialize on the vault row lock; the loser gets
  a 400 "refresh the roster and retry" rather than a corrupted mix of keys.
- Also fixed on the way in: `lockVaultRow` selected the vault row **without**
  `FOR UPDATE`, so the `MAX(version)+1` counter it claims to serialize was not
  serialized at all. Two concurrent writes to different items in one vault could
  share a version, and a delta-sync client whose cursor had passed it would
  silently miss one of the two changes. Rotation assigns many versions in one
  transaction and depends on that lock.

Deferred, unchanged by this ADR: WebSocket push sync (a rotated vault reaches
idle clients only on their next poll or unlock), and automatic rotation
suggestions after a *leave*.
