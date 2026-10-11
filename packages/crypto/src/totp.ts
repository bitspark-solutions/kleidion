// TOTP — RFC 6238 (HMAC-based OTP), Google-Authenticator compatible.
//
// Seeds live inside item ciphertext (the server never sees them). We support
// the standard SHA1/SHA256/SHA512 variants, 6- or 8-digit codes, and otpauth:
// URI parsing (RFC 6238 §3 + Key-URI-URL de-facto spec used by authenticator
// apps).

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type TotpAlgorithm = "sha1" | "sha256" | "sha512";

export interface TotpOptions {
  digits?: number; // 6 or 8 (default 6)
  period?: number; // seconds (default 30)
  algorithm?: TotpAlgorithm; // default sha1 (what authenticator apps use)
  /** Fixed time; defaults to now. */
  at?: Date;
}

export interface TotpCode {
  code: string;
  /** Seconds left before this code expires. */
  secondsRemaining: number;
  period: number;
}

export interface OtpauthParams {
  secret: string; // base32, uppercase
  issuer?: string;
  account?: string;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
}

/** Decode a base32 secret (RFC 4648; case-insensitive, spaces/dashes/padding ignored). */
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Encode bytes as unpadded uppercase base32. */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// libsodium-wrappers does not expose crypto_auth_hmacsha*, and TOTP HMACs
// take variable-length keys, so WebCrypto's HMAC is the browser-safe fit.
const HMAC_ALGOS: Record<TotpAlgorithm, string> = {
  sha1: "SHA-1",
  sha256: "SHA-256",
  sha512: "SHA-512",
};

async function hmac(algo: TotpAlgorithm, key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  // Copy into fresh ArrayBuffer-backed views (DOM lib types reject
  // ArrayBufferLike buffers, e.g. SharedArrayBuffer, as BufferSource).
  const k = new Uint8Array(key.length);
  k.set(key);
  const m = new Uint8Array(msg.length);
  m.set(msg);
  const cryptoKey = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: HMAC_ALGOS[algo] }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, m);
  return new Uint8Array(sig);
}

/** HOTP (RFC 4226) for an explicit counter. */
export async function hotp(
  secretBase32: string,
  counter: number,
  digits = 6,
  algorithm: TotpAlgorithm = "sha1",
): Promise<string> {
  const key = base32Decode(secretBase32);
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const mac = await hmac(algorithm, key, msg);
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    (((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]) >>> 0;
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

/** Current (or point-in-time) TOTP code. */
export async function totp(secretBase32: string, opts: TotpOptions = {}): Promise<TotpCode> {
  const digits = opts.digits ?? 6;
  const period = opts.period ?? 30;
  const algorithm = opts.algorithm ?? "sha1";
  const at = opts.at ?? new Date();
  const seconds = Math.floor(at.getTime() / 1000);
  const code = await hotp(secretBase32, Math.floor(seconds / period), digits, algorithm);
  return { code, secondsRemaining: period - (seconds % period), period };
}

/** Parse an otpauth://totp/ URI; throws on malformed input. */
export function parseOtpauthUri(uri: string): OtpauthParams {
  const u = new URL(uri.trim());
  if (u.protocol !== "otpauth:") throw new Error("Not an otpauth: URI");
  if (u.hostname !== "totp") throw new Error("Only otpauth://totp is supported");
  const secret = u.searchParams.get("secret");
  if (!secret) throw new Error("otpauth URI missing secret");
  const normalizedSecret = secret.toUpperCase().replace(/[\s=-]/g, "");
  base32Decode(normalizedSecret); // validate early
  // Path is [issuer:]account (account may itself contain ':' — take last segment).
  const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
  const colon = label.lastIndexOf(":");
  const account = colon >= 0 ? label.slice(colon + 1).trim() : label.trim();
  const issuerParam = u.searchParams.get("issuer") ?? undefined;
  const issuer = issuerParam ?? (colon >= 0 ? label.slice(0, colon).trim() : undefined);
  const algoRaw = (u.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  const algorithm: TotpAlgorithm =
    algoRaw === "SHA1" ? "sha1" : algoRaw === "SHA256" ? "sha256" : algoRaw === "SHA512" ? "sha512" : (() => {
      throw new Error(`Unsupported TOTP algorithm: ${algoRaw}`);
    })();
  return {
    secret: normalizedSecret,
    issuer,
    account: account || undefined,
    digits: parseInt(u.searchParams.get("digits") ?? "6", 10) || 6,
    period: parseInt(u.searchParams.get("period") ?? "30", 10) || 30,
    algorithm,
  };
}
