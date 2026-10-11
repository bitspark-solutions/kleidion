/**
 * SRP-6a sign-in for the extension — the same protocol as apps/web
 * (lib/auth-client.ts), ported to run inside the MV3 service worker.
 * Returns the unlocked session; persistence is the caller's job.
 */
import {
  deriveAUK,
  deriveClientSession,
  deriveSrpX,
  expectedServerProof,
  fromBase64,
  fromHex,
  g,
  keypairFromSeed,
  modPow,
  N,
  padToN,
  parseSecretKey,
  ready,
  timingSafeEqual,
  toHex,
  type KdfParams,
} from "@kleidion/crypto";
import { API_BASE } from "./env";
import type { Session } from "./store";

interface SrpStartResponse {
  challengeId: string;
  srpSalt: string;
  serverPublicB: string;
  kdf: KdfParams;
}

interface KeyBundleWire {
  masterPublicKey: string;
  encryptedPrivateKey: string;
  encryptedSymKey: string;
}

interface SrpFinishWire {
  sessionToken: string;
  serverProof: string;
  userId: string;
  email: string;
  deviceId: string;
  keyBundle: KeyBundleWire | null;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const j = (await res.json()) as { error?: unknown };
      if (typeof j.error === "string") message = j.error;
    } catch {
      /* keep status message */
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

/** Client ephemeral a / A = g^a mod N (same construction as the web client). */
function generateClientEphemeral(): { aHex: string; aPublicHex: string } {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf);
    const aHex = toHex(buf);
    const A = modPow(g, BigInt(`0x${aHex}`), N);
    if (A !== 0n) return { aHex, aPublicHex: padToN(A.toString(16)) };
  }
}

/** crypto_secretbox blob layout written by enroll (web) — mirrored here. */
async function unwrapWithAuk(blob: Uint8Array, auk: Uint8Array, saltLen: number): Promise<Uint8Array> {
  const s = await ready();
  const nonceLen = s.crypto_secretbox_NONCEBYTES;
  if (blob.length <= saltLen + nonceLen) throw new Error("Corrupt encrypted key blob");
  const nonce = blob.slice(saltLen, saltLen + nonceLen);
  const ct = blob.slice(saltLen + nonceLen);
  return s.crypto_secretbox_open_easy(ct, nonce, auk);
}

export async function signin(
  email: string,
  password: string,
  secretKeyDisplay: string,
): Promise<Session> {
  const s = await ready();
  const skBytes = parseSecretKey(secretKeyDisplay);

  const { aHex, aPublicHex } = generateClientEphemeral();
  const start = await postJson<SrpStartResponse>("/v1/auth/srp/start", {
    email,
    clientPublicA: aPublicHex,
  });

  const xHex = await deriveSrpX(password, skBytes, fromHex(start.srpSalt), start.kdf);
  const client = deriveClientSession(aHex, start.serverPublicB, start.srpSalt, email, xHex);

  const finish = await postJson<SrpFinishWire>("/v1/auth/srp/finish", {
    challengeId: start.challengeId,
    clientProof: client.proof,
    deviceName: "Kleidion extension",
    devicePlatform: "extension",
  });

  const expected = expectedServerProof(aPublicHex, client.proof, client.key);
  if (!timingSafeEqual(fromHex(expected), fromHex(finish.serverProof))) {
    throw new Error("Server proof verification failed — refusing session");
  }
  if (!finish.keyBundle) throw new Error("Server returned no key bundle");

  const privBlob = fromBase64(finish.keyBundle.encryptedPrivateKey);
  const saltLen = s.crypto_pwhash_SALTBYTES;
  const auk = await deriveAUK(password, skBytes, privBlob.slice(0, saltLen), start.kdf);
  const seed = await unwrapWithAuk(privBlob, auk, saltLen);
  const kp = await keypairFromSeed(seed);
  const symKey = await unwrapWithAuk(fromBase64(finish.keyBundle.encryptedSymKey), auk, 0);

  skBytes.fill(0);
  seed.fill(0);

  return {
    sessionToken: finish.sessionToken,
    userId: finish.userId,
    email: finish.email,
    deviceId: finish.deviceId,
    masterPublicKey: fromHex(finish.keyBundle.masterPublicKey),
    privateKey: kp.privateKey,
    symKey,
  };
}
