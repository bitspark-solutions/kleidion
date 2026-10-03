// SRP-6a parameters matching secure-remote-password@0.3.1 exactly:
// RFC 5054 2048-bit group, generator g=2, hash SHA-256, k = H(N | g).
//
// This is the INTEROP CONTRACT with the Go server. The golden vector in
// test/vectors/srp-golden.json was produced by the reference JS lib; both our
// TS client and the Go server must reproduce K/M1/M2 byte-for-byte.
//
// CRITICAL interop details learned by testing against the golden vector:
//  1. k = H(N | g) where g hashes as a SINGLE byte 0x02 (the ref builds g via
//     fromHex("02") and pads only to its own length). Padding g to 256 bytes
//     breaks k, B, and every proof.
//  2. A, B, S pad to N's byte-length (256) before hashing.
//  3. M1 = H( H(N) XOR H(g) | H(I) | s | A | B | K )  [RFC 2945/5054 form]
//     M2 = H( A | M1 | K )
//     where H(N)/H(g) hash N as 256 bytes and g as the single byte 0x02, H(I)
//     hashes the UTF-8 username, and s is the raw salt bytes.

import { sha256Bytes, sha256HexOf } from "../sha256";
import { fromHex, toHex, utf8Bytes } from "../encoding";

// RFC 5054 Section 3, 2048-bit group modulus N.
export const N_HEX =
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
  "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
  "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
  "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
  "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
  "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
  "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
  "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
  "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
  "9E4AFF73";

/** Number of bytes in the padded group order N (256 for the 2048-bit group). */
const N_BYTES = N_HEX.length / 2;

export const N = BigInt("0x" + N_HEX);
export const g = 2n;

/** SHA-256 over the concatenation of hex-string arguments. */
export function sha256Hex(...hexArgs: string[]): string {
  const parts = hexArgs.map((h) => fromHex(h));
  return sha256HexOf(concat(parts));
}

/** SHA-256 over concatenated byte arrays, returning raw bytes. */
function sha256Buf(...bufs: Uint8Array[]): Uint8Array {
  return sha256Bytes(concat(bufs));
}

/** SHA-256 over UTF-8 string arguments. */
export function sha256Utf8(...args: string[]): string {
  return sha256HexOf(concat(args.map((a) => utf8Bytes(a))));
}

/** Concatenate byte arrays. */
function concat(arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

/** Pad a hex value to N's byte-length (256 bytes), matching the ref's toHex(). */
export function padToN(hex: string): string {
  return hex.padStart(N_BYTES * 2, "0");
}

/**
 * k = H(N | g). g hashes as the single byte 0x02 (see header note 1).
 */
export const k = BigInt("0x" + sha256Hex(padToN(N.toString(16)), "02"));

/** H(N) XOR H(g) — the fixed prefix of the SRP-6a proof M1. */
const HN_XOR_HG: Uint8Array = (() => {
  const HN = sha256Buf(fromHex(padToN(N.toString(16))));
  const HG = sha256Buf(fromHex("02"));
  const out = new Uint8Array(HN.length);
  for (let i = 0; i < HN.length; i++) out[i] = HN[i] ^ HG[i];
  return out;
})();

/** modpow: base^exp mod m for bigints. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/** u = H(A | B), both padded to N-length. */
export function computeU(A_hex: string, B_hex: string): bigint {
  return BigInt("0x" + sha256Hex(padToN(A_hex), padToN(B_hex)));
}

/**
 * M1 (client proof) = H( H(N)^H(g) | H(I) | s | A | B | K ).
 * A_hex/B_hex/K_hex are hex; username is UTF-8; saltHex is raw salt bytes.
 */
export function computeM1(
  A_hex: string,
  B_hex: string,
  K_hex: string,
  username: string,
  saltHex: string,
): string {
  const HI = sha256Buf(utf8Bytes(username));
  const s = fromHex(saltHex);
  const A = fromHex(padToN(A_hex));
  const B = fromHex(padToN(B_hex));
  const K = fromHex(K_hex);
  return toHex(sha256Buf(HN_XOR_HG, HI, s, A, B, K));
}

/** M2 (server proof) = H( A | M1 | K ). */
export function computeM2(A_hex: string, M1_hex: string, K_hex: string): string {
  const A = fromHex(padToN(A_hex));
  const M1 = fromHex(M1_hex);
  const K = fromHex(K_hex);
  return toHex(sha256Buf(A, M1, K));
}

/**
 * Standard SRP-6a private key: x = H(s | H(I | ":" | p)).
 * NOT used for real accounts (we derive x from 2SKD/Argon2id — see deriveSrpX);
 * present for test vectors and protocol completeness.
 */
export function derivePrivateKeyStd(saltHex: string, username: string, password: string): string {
  const inner = sha256Utf8(username + ":" + password);
  return sha256Hex(saltHex, inner);
}

/** v = g^x mod N (verifier). */
export function deriveVerifier(xHex: string): string {
  return modPow(g, BigInt("0x" + xHex), N).toString(16);
}
