# Phase 5 contract — Daily-driver polish (generator + security health), then platforms

Authoritative contract for Phase 5. Master plan: `2026-10-03_1405-kleidion-master-plan.md`
(§Phase 5/6). This contract **re-slices** the master plan: the master plan's Phase 6
trust features move here as 5b (a password manager without a generator/audit is not
daily-drivable), and desktop/mobile become 5c/5d.

## Security invariants (unchanged, non-negotiable)

- Generated passwords never leave the client except as item ciphertext.
- Audit runs **client-side** on decrypted items only: the server never learns which
  passwords are weak/reused. HIBP checks (5b.3) use k-anonymity range queries —
  5-byte prefix only, never the full hash, no account identifiers.
- All new crypto (generator, scoring inputs) lives in `@kleidion/crypto`; apps call
  the package.

## Execution order

- **A. Password generator** — `packages/crypto` + web `ItemEditor` + extension save-form
- **B. Security health (Watchtower-lite)** — scoring + reuse + Security page in web
- **C. Exit criteria + E2E** — screenshots flow, tests green, ADR-008 if design forks
- **D. (deferred, gated on C) Desktop Tauri shell** — master-plan Phase 5 original
- **E. (deferred) Mobile Expo** — master-plan Phase 5 original

## Step A — Password generator

1. `packages/crypto/src/generate.ts`:
   - `generatePassword(opts: {length?, digits?, symbols?, avoidAmbiguous?}) → string`
     using `sodium.randombytes_buf` (rejection sampling — no modulo bias).
   - `generatePassphrase(opts: {words?, separator?, capitalize?, addNumber?}) → string`
     with an embedded EFF-Short-style wordlist (~1k words, lowercase, ASCII).
   - Charset/entropy helpers exported for the strength meter: `poolEntropyBits(length, pool)`.
   - Tests: distribution sanity (χ² light), no-bias property test, passphrase length.
2. Web `ItemEditor`: Password field gains a toolbar — Generate (dice icon),
   length slider (8–64), toggles digits/symbols/ambiguous, Passphrase mode
   (word count 3–8), Regenerate, Copy. Default on new Login = 20-char class password.
3. Extension save-form (`autofill.content.ts` offerSave + popup): same generator,
   minimal UI (length + mode).
4. `packages/core`: no schema change (password stays a plain field value).

## Step B — Security health

1. `packages/core/src/audit.ts` (pure functions, no crypto):
   - `scorePassword(pw, {entropyBits}) → {score: 0–4, reasons: string[]}` —
     zxcvbn-lite heuristics: length bands, class variety, sequences/repeats,
     common-password list (~500 entries embedded), entropy from pool math.
   - `findReuse(items: ItemPlain[]) → Map<password, itemId[]>` — client-side only;
     compare via the **already-decrypted** values (never searchHmac: that is keyed
     per vault and title-normalized, wrong tool).
   - Tests: known weak/strong fixtures, reuse across two items, unicode safety.
2. Web: sidebar category **"Security"** (shield icon) → page listing:
   - Reused passwords (grouped, cross-vault), weak (score ≤ 1), missing-TOTP logins
     (informational), oldest-unchanged (v1 items > 180 d).
   - Per-row: open item, Regenerate (jumps into editor with new value).
   - Summary cards: counts + "health" ring (share of logins score ≥ 3).
3. HIBP k-anonymity check: **out of scope for this phase** (network dependency +
   privacy ADR needed); Security page reserves the row and shows "check offline".

## Step C — Exit criteria

1. Generate 50 passwords via UI → all match policy, entropy label correct, zero
   ambiguous chars when toggled.
2. Store two logins with the same password → Security page flags both; a `correct-horse`
   style weak password scores ≤ 1; a 6/4 passphrase scores ≥ 3.
3. Reuse/weak lists work in **shared** vaults too (admin sees, read-only member sees
   but cannot regenerate).
4. `npm test` (crypto/core) green; web + extension `tsc` clean; `go build/vet/test`
   untouched (no server changes in A/B).
5. Screenshot walkthrough (`.shots/` flow script) of generate → audit → fix.

## Deferred decisions (write ADR-008 when picked up)

- Desktop keychain: DPAPI vs age-encrypted file for the AUK cache; whether the Tauri
  shell reuses `apps/web` unchanged (likely) or shares a new `packages/ui`.
- Mobile autofill (iOS Credential Provider) needs passkey/WebAuthn groundwork —
  sequence **after** a passkeys phase, not before.
- HIBP: online-by-default vs opt-in toggle; per-item vs per-vault batching; proxy
  through server for IP privacy (breaks zero-knowledge-of-metadata claim → needs ADR).
