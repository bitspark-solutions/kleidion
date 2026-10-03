// Encoding helpers. All secret material crosses module boundaries as either
// Uint8Array (raw bytes) or lowercase hex (wire/storage). Never base64 for
// anything that feeds SRP/KDF — hex avoids ambiguity about padding.
//
// Environment-agnostic on purpose: this package runs in the browser (client
// components), Node (vitest), and workers. Node's Buffer is NOT polyfilled in
// Next.js client bundles, so we use only Web-standard APIs: TextEncoder,
// TextDecoder, btoa/atob (with a Node fallback for older runtimes).

const HEX = "0123456789abcdef";

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0f];
  }
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("fromHex: odd-length hex string");
  if (!/^[0-9a-f]*$/.test(clean)) throw new Error("fromHex: non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  // Build a binary string, then let the runtime base64-encode it.
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  if (typeof btoa === "function") return btoa(bin);
  // Node without a global btoa (older versions).
  return (globalThis as any).Buffer.from(bytes).toString("base64");
}

export function fromBase64(b64: string): Uint8Array {
  let bin: string;
  if (typeof atob === "function") {
    bin = atob(b64);
  } else {
    bin = (globalThis as any).Buffer.from(b64, "base64").toString("binary");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8String(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** Constant-time comparison of two byte arrays. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
