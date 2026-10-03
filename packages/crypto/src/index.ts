// @kleidion/crypto — the security core. One implementation, consumed by web,
// extension, desktop and mobile. See ADR-005 for the crypto design and the
// master plan §5 for the full intended API.
//
// Implemented so far (Phase 2, in progress): SRP-6a params + client/server
// session derivation, validated against golden interop vectors captured from
// secure-remote-password@0.3.1. Next: 2SKD/Argon2id key derivation, Secret
// Key handling, vault/item encryption (XChaCha20-Poly1305), password gen.
//
// NOTHING here ships until it passes cross-language SRP test vectors against
// the Go server and has >=95% coverage.

export * from "./srp/params";
export * from "./srp/client";
export * from "./srp/server";
