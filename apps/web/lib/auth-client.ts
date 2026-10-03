// Auth client — the REAL signup/signin flows against the Go SRP API.
//
// Crypto contract (mirrors ADR-005 / phase3-contract.md):
//   signup: Secret Key -> x = deriveSrpX(password, sk, srpSalt) -> v = g^x ->
//           X25519 keypair + random sym key, both wrapped with the AUK ->
//           POST /v1/auth/enroll -> Emergency Kit (Secret Key shown ONCE).
//   signin: POST /v1/auth/srp/start -> x -> deriveClientSession -> M1 ->
//           POST /v1/auth/srp/finish -> VERIFY M2 -> unwrap key material.
//
// AUK key-wrapping format (documented choice, mirrored on both paths):
//   crypto_secretbox_easy (XSalsa20-Poly1305) under the AUK.
//   encryptedPrivateKey = base64( aukSalt(16) || nonce(24) || ct(seed32) )
//   encryptedSymKey     = base64( nonce(24) || ct(symKey32) )
// The AUK salt lives inside the opaque encryptedPrivateKey blob (the server
// stores it as-is; there is no separate aukSalt column), so the unlock path
// round-trips: parse salt from blob -> deriveAUK(password, sk, salt, kdf).
//
// NOTE: client SRP ephemeral (a, A=g^a) is implemented here because
// @kleidion/crypto does not export a client generateEphemeral() yet. It uses
// the package's exported N, g, modPow, padToN — no re-implementation of SRP.

"use client";

import {
  N,
  g,
  modPow,
  padToN,
  ready,
  nacl,
  deriveVerifier,
  deriveSrpX,
  deriveAUK,
  deriveClientSession,
  expectedServerProof,
  generateSalt,
  generateSecretKey,
  parseSecretKey,
  KDF_SENSITIVE,
  timingSafeEqual,
  type KdfParams,
} from "@kleidion/crypto";
import { fetchJson } from "@/lib/api-base";
import { setSession, type KeyMaterial } from "@/lib/session";

// ---------------------------------------------------------------------------
// Browser-safe hex/base64 (avoids Buffer so this module works client-side).
// ---------------------------------------------------------------------------

function hexFromBytes(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function bytesFromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) {
    throw new Error("Invalid hex string");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64FromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function bytesFromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

// ---------------------------------------------------------------------------
// SRP client ephemeral (gap workaround — see header note).
// ---------------------------------------------------------------------------

/** Generate a client ephemeral pair: a (32 random bytes), A = g^a mod N. */
export function generateClientEphemeral(): { aHex: string; aPublicHex: string } {
  for (;;) {
    const aHex = hexFromBytes(randomBytes(32));
    const A = modPow(g, BigInt("0x" + aHex), N);
    if (A === 0n) continue; // probability ~2^-2048; retry defensively
    return { aHex, aPublicHex: padToN(A.toString(16)) };
  }
}

// ---------------------------------------------------------------------------
// AUK wrapping helpers (crypto_secretbox_easy under the AUK).
// ---------------------------------------------------------------------------

async function wrapWithAuk(plain: Uint8Array, auk: Uint8Array, saltPrefix?: Uint8Array): Promise<Uint8Array> {
  const s = await ready();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES); // 24
  const ct = s.crypto_secretbox_easy(plain, nonce, auk);
  const parts = saltPrefix ? [saltPrefix, nonce, ct] : [nonce, ct];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const blob = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    blob.set(p, off);
    off += p.length;
  }
  return blob;
}

async function unwrapWithAuk(blob: Uint8Array, auk: Uint8Array, saltLen: number): Promise<Uint8Array> {
  const s = await ready();
  const nonceLen = s.crypto_secretbox_NONCEBYTES;
  if (blob.length <= saltLen + nonceLen) throw new Error("Corrupt encrypted key blob");
  const nonce = blob.slice(saltLen, saltLen + nonceLen);
  const ct = blob.slice(saltLen + nonceLen);
  return s.crypto_secretbox_open_easy(ct, nonce, auk); // throws on auth failure
}

// ---------------------------------------------------------------------------
// Wire types (match apps/server/internal/auth/service.go JSON tags).
// ---------------------------------------------------------------------------

interface EnrollResponse {
  userId: string;
  email: string;
  accountId: string;
}

interface SrpStartResponse {
  challengeId: string;
  srpSalt: string;
  serverPublicB: string;
  kdf: KdfParams;
  keyBundle: unknown; // always null at start
}

interface KeyBundleWire {
  masterPublicKey: string;
  encryptedPrivateKey: string;
  encryptedSymKey: string;
}

interface SrpFinishResponse {
  sessionToken: string;
  serverProof: string;
  userId: string;
  email: string;
  keyBundle: KeyBundleWire | null;
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

export interface SignupResult {
  userId: string;
  email: string;
  accountId: string;
  /** Secret Key display string (KL-<ACCOUNT>-...). Shown ONCE. */
  secretKey: string;
}

export interface SignupInput {
  email: string;
  password: string;
}

/**
 * Full enrollment: generate Secret Key + key material locally, derive the SRP
 * verifier, POST /v1/auth/enroll, and return the Emergency Kit data.
 * The password/Secret Key never leave this function.
 */
export async function signup({ email, password }: SignupInput): Promise<SignupResult> {
  const s = await ready();

  // Secret Key first (placeholder account fragment — the real one comes from
  // the server in the enroll response; the KDF input is the secret chars only,
  // so re-formatting the display afterwards is safe).
  const tmp = await generateSecretKey("AAAAAA");

  const srpSalt = await generateSalt(); // 16 bytes
  const aukSalt = await generateSalt(); // independent salt for the AUK
  const xHex = await deriveSrpX(password, tmp.bytes, srpSalt, KDF_SENSITIVE);
  const verifierHex = deriveVerifier(xHex);

  // X25519 master keypair from a random seed + vault-independent sym key.
  const seed = s.randombytes_buf(32);
  const kp = s.crypto_box_seed_keypair(seed);
  const symKey = s.randombytes_buf(32);

  const auk = await deriveAUK(password, tmp.bytes, aukSalt, KDF_SENSITIVE);
  const encryptedPrivateKey = await wrapWithAuk(seed, auk, aukSalt);
  const encryptedSymKey = await wrapWithAuk(symKey, auk);

  const resp = await fetchJson<EnrollResponse>("/v1/auth/enroll", {
    method: "POST",
    body: {
      email,
      srpSalt: hexFromBytes(srpSalt),
      srpVerifier: verifierHex,
      kdf: KDF_SENSITIVE,
      masterPublicKey: hexFromBytes(kp.publicKey),
      encryptedPrivateKey: b64FromBytes(encryptedPrivateKey),
      encryptedSymKey: b64FromBytes(encryptedSymKey),
    },
  });

  // Rebuild the display string with the server-assigned account fragment.
  const secretPart = tmp.display.split("-").slice(2).join("-");
  const secretKey = `KL-${resp.accountId}-${secretPart}`;

  // Hygiene: wipe local copies of secrets we no longer need.
  auk.fill(0);
  symKey.fill(0);
  seed.fill(0);
  kp.privateKey.fill(0);
  tmp.bytes.fill(0);

  return { userId: resp.userId, email: resp.email, accountId: resp.accountId, secretKey };
}

// ---------------------------------------------------------------------------
// Signin (also the unlock path — the session store is memory-only, so
// unlocking after auto-lock/reload is a full SRP sign-in).
// ---------------------------------------------------------------------------

export interface SigninInput {
  email: string;
  password: string;
  /** Secret Key display string from the Emergency Kit. */
  secretKey: string;
  deviceName?: string;
}

/**
 * SRP sign-in: start -> derive x -> M1 -> finish -> verify M2 -> unwrap keys
 * -> store the session in memory (starts the 15-min idle auto-lock).
 * Throws on invalid credentials (401) or server-proof mismatch.
 */
export async function signin({ email, password, secretKey, deviceName }: SigninInput): Promise<void> {
  const s = await ready();
  const skBytes = parseSecretKey(secretKey);

  const { aHex, aPublicHex } = generateClientEphemeral();

  const start = await fetchJson<SrpStartResponse>("/v1/auth/srp/start", {
    method: "POST",
    body: { email, clientPublicA: aPublicHex },
  });

  const xHex = await deriveSrpX(password, skBytes, bytesFromHex(start.srpSalt), start.kdf);
  const client = deriveClientSession(aHex, start.serverPublicB, start.srpSalt, email, xHex);

  const finish = await fetchJson<SrpFinishResponse>("/v1/auth/srp/finish", {
    method: "POST",
    body: {
      challengeId: start.challengeId,
      clientProof: client.proof,
      deviceName: deviceName || defaultDeviceName(),
      devicePlatform: "web",
    },
  });

  // VERIFY the server proof M2 — reject and discard the token on mismatch.
  const expected = expectedServerProof(aPublicHex, client.proof, client.key);
  if (!timingSafeEqual(bytesFromHex(expected), bytesFromHex(finish.serverProof))) {
    throw new Error("Server proof verification failed — refusing session");
  }
  if (!finish.keyBundle) {
    throw new Error("Server returned no key bundle");
  }

  // Unwrap key material with the AUK (salt embedded in the private-key blob).
  const privBlob = bytesFromB64(finish.keyBundle.encryptedPrivateKey);
  const saltLen = s.crypto_pwhash_SALTBYTES; // 16
  const aukSalt = privBlob.slice(0, saltLen);
  const auk = await deriveAUK(password, skBytes, aukSalt, start.kdf);

  const seed = await unwrapWithAuk(privBlob, auk, saltLen);
  const kp = s.crypto_box_seed_keypair(seed);
  const symKey = await unwrapWithAuk(bytesFromB64(finish.keyBundle.encryptedSymKey), auk, 0);

  const keys: KeyMaterial = {
    masterPublicKey: bytesFromHex(finish.keyBundle.masterPublicKey),
    privateKeySeed: seed,
    privateKey: kp.privateKey,
    symKey,
    auk,
  };

  skBytes.fill(0); // AUK (inside keys) is retained for re-wrapping on lock-free ops

  setSession({
    sessionToken: finish.sessionToken,
    userId: finish.userId,
    email: finish.email,
    keys,
    unlockedAt: Date.now(),
  });
}

function defaultDeviceName(): string {
  if (typeof navigator === "undefined") return "web device";
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Edg\//.test(ua)) return "Edge";
  if (/Chrome\//.test(ua)) return "Chrome";
  if (/Safari\//.test(ua)) return "Safari";
  return "Web browser";
}
