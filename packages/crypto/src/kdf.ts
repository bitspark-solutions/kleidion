// Key derivation — the two-secret key derivation (2SKD) scheme from ADR-005.
//
//   AUK = Argon2id(password, aukSalt) XOR HKDF-SHA256(secretKeyBytes, ikm) 
//   SRP-x = Argon2id(password, srpSalt) XOR HKDF-SHA256(secretKeyBytes, ikm)
//
// with independent salts so the unlock key and the auth key are unrelated.
// The server never sees password, secretKey, AUK, or x — only the SRP
// verifier v = g^x (computed on the client at enroll time).
//
// HKDF is built from sodium's HMAC-SHA256 (extract/expand) because
// libsodium-wrappers does not expose crypto_kdf_hkdf in all builds.

import { nacl, ready } from "./sodium";
import { fromHex, toHex, utf8Bytes, timingSafeEqual } from "./encoding";

/** Argon2id parameters. Stored per-user server-side so clients can adapt. */
export interface KdfParams {
  algo: "argon2id";
  opsLimit: number;   // t (iterations)
  memLimit: number;   // m (bytes)
}

// libsodium constants (verified against libsodium-wrappers-sumo 0.8.4):
//   OPSLIMIT   INTERACTIVE=2  MODERATE=3  SENSITIVE=4
//   MEMLIMIT   INTERACTIVE=64MiB  MODERATE=256MiB  SENSITIVE=1GiB
// We use MODERATE (t=3, m=256MiB) as the desktop/web baseline — a good
// security/latency tradeoff for a one-time unlock. Mobile can use INTERACTIVE.

/** Baseline (desktop/web): Argon2id t=3, m=256 MiB. */
export const KDF_SENSITIVE: KdfParams = {
  algo: "argon2id",
  opsLimit: 3,
  memLimit: 268435456, // 256 MiB (crypto_pwhash_MEMLIMIT_MODERATE)
};

/** Lighter params for constrained devices: t=2, m=64 MiB. */
export const KDF_INTERACTIVE: KdfParams = {
  algo: "argon2id",
  opsLimit: 2,
  memLimit: 67108864, // 64 MiB (crypto_pwhash_MEMLIMIT_INTERACTIVE)
};

const KDF_CONTEXT = "kleidion-kdf-v1";

/**
 * HMAC-SHA256 with an arbitrary-length key, via the streaming API.
 * (The one-shot crypto_auth_hmacsha256 enforces a 32-byte key, which breaks
 * HKDF-extract with a 16-byte salt.) Verified to match Node's crypto.createHmac.
 */
function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const s = nacl();
  const st = s.crypto_auth_hmacsha256_init(key);
  s.crypto_auth_hmacsha256_update(st, msg);
  return s.crypto_auth_hmacsha256_final(st);
}

/**
 * HKDF-SHA256 extract: PRK = HMAC(salt, ikm).
 */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt, ikm);
}

/**
 * HKDF-SHA256 expand to `length` bytes (length <= 32*255).
 */
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  let pos = 0;
  let counter = 1;
  while (pos < length) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[input.length - 1] = counter;
    t = hmacSha256(prk, input);
    const take = Math.min(t.length, length - pos);
    out.set(t.subarray(0, take), pos);
    pos += take;
    counter++;
  }
  return out;
}

/**
 * HKDF(secretKeyBytes, salt=contextBytes, info) → 32 bytes.
 * The Secret Key is the IKM (high entropy), the derivation context is the salt.
 */
function hkdfFromSecretKey(secretKeyBytes: Uint8Array, info: string): Uint8Array {
  const salt = utf8Bytes(KDF_CONTEXT);
  const prk = hkdfExtract(salt, secretKeyBytes);
  return hkdfExpand(prk, utf8Bytes(info), 32);
}

/**
 * Two-secret key derivation: Argon2id(password, salt) XOR HKDF(secretKey).
 * `purpose` binds the derived key to its role ("auk" | "srp-x") so the unlock
 * and auth keys are cryptographically independent even with the same password.
 */
export async function derive2SKD(
  password: string,
  secretKeyBytes: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
  purpose: "auk" | "srp-x",
): Promise<Uint8Array> {
  await ready();
  const s = nacl();
  if (salt.length !== s.crypto_pwhash_SALTBYTES) {
    throw new Error(`derive2SKD: salt must be ${s.crypto_pwhash_SALTBYTES} bytes`);
  }
  const argon = s.crypto_pwhash(
    32,
    password,
    salt,
    params.opsLimit,
    params.memLimit,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const hkdf = hkdfFromSecretKey(secretKeyBytes, purpose);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = argon[i] ^ hkdf[i];
  return out;
}

/** Account Unlock Key — encrypts the user's private key. */
export function deriveAUK(
  password: string,
  secretKeyBytes: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  return derive2SKD(password, secretKeyBytes, salt, params, "auk");
}

/**
 * SRP private key x — feeds into v = g^x at enroll and the handshake at signin.
 * Returns lowercase hex (32 bytes).
 */
export async function deriveSrpX(
  password: string,
  secretKeyBytes: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
): Promise<string> {
  const x = await derive2SKD(password, secretKeyBytes, salt, params, "srp-x");
  return toHex(x);
}

/** Generate a fresh Argon2id salt (16 bytes). */
export async function generateSalt(): Promise<Uint8Array> {
  const s = await ready();
  return s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
}

export { hkdfExtract, hkdfExpand, timingSafeEqual, fromHex, toHex };
