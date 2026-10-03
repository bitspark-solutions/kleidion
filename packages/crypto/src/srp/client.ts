// SRP-6a client-side session derivation. Independent implementation (not the
// ref lib) so it can be ported to Go verbatim. Validated against the golden
// vector captured from secure-remote-password@0.3.1.

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

export interface ClientSession {
  /** Shared session key K = H(S). */
  key: string;
  /** Client proof M1 = H(H(N)^H(g) | H(I) | s | A | B | K). */
  proof: string;
}

/**
 * Derive the client session key + proof (M1).
 * @param clientSecretEphemeral a (hex)
 * @param serverPublicEphemeral B (hex)
 * @param saltHex s (hex)
 * @param username I
 * @param privateKeyHex x (hex) — from 2SKD in production, or derivePrivateKeyStd in tests
 */
export function deriveClientSession(
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  saltHex: string,
  username: string,
  privateKeyHex: string,
): ClientSession {
  const a = BigInt("0x" + clientSecretEphemeral);
  const B = BigInt("0x" + serverPublicEphemeral);
  const x = BigInt("0x" + privateKeyHex);

  const A = modPow(g, a, N);
  const A_hex = padToN(A.toString(16));
  const B_hex = padToN(B.toString(16));

  const u = computeU(A_hex, B_hex);

  // S = (B - k*g^x) ^ (a + u*x) mod N   [SRP-6a client premaster]
  const kgx = (k * modPow(g, x, N)) % N;
  const diff = (B - kgx + N * ((kgx > B ? 1n : 0n) + 1n)) % N; // ensure positive
  const exp = a + u * x;
  const S = modPow(diff, exp, N);
  const S_hex = padToN(S.toString(16));

  const key = sha256Hex(S_hex); // K = H(S)
  const proof = computeM1(A_hex, B_hex, key, username, saltHex); // M1 = H(H(N)^H(g)|H(I)|s|A|B|K)

  return { key, proof };
}

/** M2 = H(A | M1 | K) — what the client expects back from the server. */
export function expectedServerProof(
  clientPublicEphemeral: string,
  clientProof: string,
  key: string,
): string {
  const A_hex = padToN(BigInt("0x" + clientPublicEphemeral).toString(16));
  return computeM2(A_hex, clientProof, key);
}
