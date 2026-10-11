// X25519 master keypair helpers (ADR-005/006).
//
// The account keypair is generated from a 32-byte seed at enroll; the seed is
// stored AUK-wrapped in the key bundle, so the keypair is re-derivable on
// every unlock via keypairFromSeed. Sealed-box vault-key wrapping
// (wrapVaultKey/unwrapVaultKey in item.ts) uses this keypair.

import { ready } from "./sodium";

export interface X25519Keypair {
  publicKey: Uint8Array; // 32 bytes
  privateKey: Uint8Array; // 32-byte X25519 secret key
  seed: Uint8Array; // 32 bytes — the AUK-wrapped secret stored in the bundle
}

/** Generate a fresh X25519 keypair from a random seed. */
export async function generateX25519Keypair(): Promise<X25519Keypair> {
  const s = await ready();
  const seed = s.randombytes_buf(32);
  const kp = s.crypto_box_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, seed };
}

/** Re-derive the keypair from its stored 32-byte seed. */
export async function keypairFromSeed(seed: Uint8Array): Promise<X25519Keypair> {
  const s = await ready();
  const kp = s.crypto_box_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, seed };
}
