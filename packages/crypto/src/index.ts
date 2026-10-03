// @kleidion/crypto — Phase 2 implements the security core here (ADR-005).
//
// Planned exports (see master plan §5):
//   generateSecretKey, deriveAUK, deriveSrpX, srpClientStart/Finish,
//   generateVaultKey, wrapVaultKey/unwrapVaultKey, encryptItem/decryptItem,
//   searchHmac, generatePassword/Passphrase, totpNow, emergencyKit.
//
// NOTHING in this package ships until it passes cross-language SRP test
// vectors against the Go server and has ≥95% coverage. This stub exists only
// so the npm workspace graph resolves during Phase 1.
export const PHASE = "not-implemented";
