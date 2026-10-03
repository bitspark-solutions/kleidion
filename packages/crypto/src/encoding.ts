// Encoding helpers. All secret material crosses module boundaries as either
// Uint8Array (raw bytes) or lowercase hex (wire/storage). Never base64 for
// anything that feeds SRP/KDF — hex avoids ambiguity about padding.

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("fromHex: odd-length hex string");
  if (!/^[0-9a-f]*$/.test(clean)) throw new Error("fromHex: non-hex characters");
  return new Uint8Array(Buffer.from(clean, "hex"));
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function utf8Bytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "utf8"));
}

/** Constant-time comparison of two byte arrays. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
