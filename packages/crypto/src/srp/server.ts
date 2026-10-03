// SRP-6a server-side session derivation. This is the EXACT logic the Go server
// must reproduce. Validated against the golden vector from
// secure-remote-password@0.3.1.

import {
  N,
  g,
  k,
  modPow,
  computeU,
  computeM1,
  computeM2,
  sha256Hex,
  padToN,
} from "./params";

export interface ServerSession {
  /** Shared session key K = H(S). */
  key: string;
  /** Server proof M2 = H(A | M1 | K). */
  proof: string;
  /** Whether the client's M1 proof was valid. */
  clientProofValid: boolean;
}

/**
 * Derive the server session key, verify client proof M1, and compute M2.
 * @param serverSecretEphemeral b (hex)
 * @param clientPublicEphemeral A (hex)
 * @param saltHex s (hex) — used in the M1 proof
 * @param username I — used in the M1 proof (H(I))
 * @param verifierHex v (hex)
 * @param clientProofHex M1 (hex) from the client
 */
export function deriveServerSession(
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  saltHex: string,
  username: string,
  verifierHex: string,
  clientProofHex: string,
): ServerSession {
  const b = BigInt("0x" + serverSecretEphemeral);
  const A = BigInt("0x" + clientPublicEphemeral);
  const v = BigInt("0x" + verifierHex);

  const A_hex = padToN(A.toString(16));
  const B_hex = padToN(B_of(b, v).toString(16));
  const u = computeU(A_hex, B_hex);

  // S = (A * v^u) ^ b mod N   [SRP-6a server premaster]
  const vu = modPow(v, u, N);
  const Avu = (A * vu) % N;
  const S = modPow(Avu, b, N);
  const S_hex = padToN(S.toString(16));

  const key = sha256Hex(S_hex); // K = H(S)
  const expectedM1 = computeM1(A_hex, B_hex, key, username, saltHex);
  const clientProofValid = expectedM1 === clientProofHex.toLowerCase();
  const proof = computeM2(A_hex, clientProofHex.toLowerCase(), key); // M2 = H(A | M1 | K)

  return { key, proof, clientProofValid };
}

/** B = k*v + g^b mod N (server public ephemeral). */
export function B_of(b: bigint, v: bigint): bigint {
  return ((k * v) % N + modPow(g, b, N)) % N;
}
