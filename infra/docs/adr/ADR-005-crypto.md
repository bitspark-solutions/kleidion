# ADR-005: Encryption architecture — 2SKD, SRP-6a, Argon2id, XChaCha20-Poly1305, X25519

Date: 2026-10-03 · Status: accepted (pending Phase 2 security review)

## Decision
Follow the published two-secret key-derivation (2SKD) design that zero-knowledge
password managers have converged on:

1. **Two secrets (2SKD):** user holds account password (memorized) + Secret Key (128-bit CSPRNG,
   generated at signup, lives only on devices / printed Emergency Kit).
2. **KDF:** Argon2id (baseline m=64MiB, t=3, p=4; parameters stored per-user so clients can adapt,
   e.g. lower memory on mobile) → AUK = argon2id(password) ⊕ HKDF(SecretKey).
3. **Auth:** SRP-6a (RFC 5054, 2048-bit MODP group, SHA-256) with a dedicated SRP salt distinct
   from the AUK salt (2SKD independence). SRP-6a is implemented in-repo on both sides
   SRP math in `packages/crypto` cross-tested against Go vectors.
4. **Keys:** per-user X25519 keypair generated client-side; private key wrapped with AUK before
   upload. Per-vault random 256-bit keys; vault keys wrapped with each member's X25519 public key
   (sharing = wrap once per member, never re-encrypt items). Ed25519 signing key reserved for
   future item-integrity signatures.
5. **Items:** XChaCha20-Poly1305 (libsodium `crypto_aead_xchacha20poly1305_ietf`) over canonical
   JSON; random 24-byte nonce per encryption; item version counter for sync (LWW + conflict copy).
6. **Server-side search:** HMAC-SHA256 over normalized titles with a vault-key-derived search key
   (server can match but not read).
7. **No custom primitives.** Only libsodium and x/crypto primitives, plus RFC 5054 SRP-6a
   implemented in-repo and locked down by golden test vectors. Any protocol change
   requires a new ADR + security review.

## Rationale
Zero-knowledge is the product. The 2SKD + SRP key hierarchy is published, peer-reviewed, and has
withstood a decade of scrutiny across production password managers; adopting it gives us a
defensible security story and a well-understood threat model. Argon2id over PBKDF2: current OWASP recommendation, memory-hard.

## Consequences
- No server-side password reset (Emergency Kit is the recovery path; trusted-contact recovery in
  Phase 6). Losing both secrets = permanent data loss — signup UX must enforce Emergency Kit save.
- Server code must never handle plaintext item material; CI canary tests enforce this invariant.
