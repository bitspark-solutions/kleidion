# ADR-007: Phase 4 sharing model and extension session handling

Date: 2026-10-12 · Status: accepted

## Context

Phase 4 shipped three capabilities that each touch the zero-knowledge boundary:
shared vaults (multi-member key distribution), encrypted share links (sharing with
non-members), and the MV3 browser extension (a second client class with a different
lifecycle from the web app). ADR-006's per-vault key map is the foundation all
three build on; this ADR records how they use it and the trust decisions around
the extension.

## Decision

### 1. Shared vaults — re-wrap, never re-encrypt

`vault_keys` holds one `crypto_box_seal` wrap of the vault key per member
(ADR-006). Inviting a member = client-side lookup of their `masterPublicKey`
(`GET /v1/users/lookup?email=`) + `PUT` of a fresh wrap (`addMember`). Removing =
delete the row; **full key rotation on removal is deferred** (see Consequences).
Roles (`admin|write|read`) are enforced server-side on every mutation; the client
mirrors them for UX only.

Personal vaults created in Phase 3 stored items under the account `symKey`. On
unlock the client tries the sealed wrap first and falls back to `symKey`, then
re-wraps the recovered key via `PUT /v1/vaults/:id/wrapped-key`. Shared vaults
have no fallback — unwrap failure leaves them locked rather than silently
decrypting with the wrong key.

### 2. Share links — key in the fragment, server sees ciphertext only

A new random 256-bit link key encrypts the item plaintext client-side
(`encryptItem` reuse). The server stores only `SHA-256(token)`, the wrapped
ciphertext, expiry, optional view cap, and optional recipient email. The URL
fragment (`/share#token:linkKey`) never reaches the server (fragments are not
sent in HTTP requests), so an operator with full DB + log access cannot decrypt.
Redemption is public and rate-limited; recipient-email binding is enforced
server-side against the authenticated redeemer.

### 3. Extension sessions — storage.session, origin-guarded reveal

- SRP sign-in runs in the **background** service worker (not the popup), so the
  session survives popup close. Key material lives in `chrome.storage.session`
  (memory-backed, cleared on browser exit). Firefox MV2 lacks
  `storage.session`: the extension falls back to module memory, which is
  strictly weaker (no cross-process persistence) — accepted for the MV2 parity
  build.
- 15-minute idle auto-lock via `chrome.alarms` + a `lastActivity` timestamp.
- Content scripts **never** receive key material. They ask the background for a
  match list (titles/usernames only, host-filtered) and reveal a password only
  through `credentials{itemId}`, which the background re-checks against the
  **sender tab's** base domain (`domainsEquivalent`, e.g. `mail.google.com` ↔
  `accounts.google.com`). A malicious page cannot enumerate or exfiltrate items
  from another origin, even by messaging the extension directly.
- Autofill fills via the native value setter + `input`/`change` events so React
  and Angular forms accept the values; the menu lives in a closed shadow root to
  avoid page CSS interference and to keep item data out of the accessible DOM
  for page scripts (closed root + no data attributes).

## Consequences

- Member removal did **not** rotate the vault key when this ADR was written, and
  that was a real hole: the removed member kept a key that still decrypted
  everything on the server. ADR-008 closes it — removal from the members UI is
  now an atomic revoke-and-rotate (`POST /v1/vaults/:id/rotate-key`).
- `users/lookup` leaks account existence by email to any authenticated user —
  acceptable for a personal/small-team product; a rate limit + eventual invite-code
  flow is the mitigation if abused.
- Extension trust is per-origin, not per-item: any page whose base domain matches
  the stored item's URL can receive its credentials. Storing URLs narrowly (exact
  host, not `example.com` everywhere) remains a user-facing best practice.
- Firefox MV2 is a compatibility build; when Firefox MV3 support matures, the
  service-worker session restore path (already written for Chrome MV3) applies
  unchanged.
