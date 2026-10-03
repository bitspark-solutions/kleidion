// Singleton libsodium (sumo build — required for crypto_pwhash / Argon2id,
// which the standard libsodium-wrappers build omits).
//
// The package ships its own types and exposes everything as a DEFAULT export
// object (`declare const sodium: {...}; export default sodium`), so we derive
// the type from that default export rather than a named `Sodium` interface
// (which does not exist).

import sodium from "libsodium-wrappers-sumo";

/** The libsodium API surface. */
export type Sodium = typeof sodium;

let initialized: Sodium | null = null;

/**
 * Await once before any crypto operation. Safe to call repeatedly; resolves as
 * soon as the WASM instance is ready.
 */
export async function ready(): Promise<Sodium> {
  if (initialized) return initialized;
  await sodium.ready;
  initialized = sodium;
  return sodium;
}

/** Synchronous accessor — throws if `ready()` has not resolved yet. */
export function nacl(): Sodium {
  if (!initialized) {
    throw new Error("@kleidion/crypto: call `await ready()` before crypto operations");
  }
  return initialized;
}
