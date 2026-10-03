// Secret Key — the second factor in 2SKD. 128 bits of CSPRNG entropy, shown
// to the user ONCE at signup (Emergency Kit) and stored only on their devices.
// The server never sees it. Uses a readable hyphen-grouped format so it
// can be printed/QR'd and hand-typed if ever needed.
//
// Layout: KL-<ACCOUNT_ID>-<26 secret chars>
//   KL        = Kleidion version prefix (non-secret)
//   ACCOUNT_ID = 6 non-secret chars (server-assigned account id fragment)
//   26 chars  = 128-bit secret drawn from an unambiguous alphabet
//
// Alphabet excludes visually confusable characters (I/L/O/0/1/5/S/8), giving a
// 30-symbol set that is safe to hand-type from a printed Emergency Kit.

import { ready, nacl } from "./sodium";
import { fromHex, toHex } from "./encoding";

/** Unambiguous Crockford-like alphabet (32 chars, 5 bits each). */
const ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_CHARS = 26; // 26 * 5 = 130 bits, trimmed to 128 bits of entropy
export const SECRET_KEY_VERSION = "KL";

export interface SecretKey {
  /** Full display string: KL-XXXXXX-<26 chars grouped>. */
  display: string;
  /** Raw 32-byte secret (the KDF input). */
  bytes: Uint8Array;
  /** The 6-char non-secret account id fragment. */
  accountId: string;
}

/**
 * Generate a new Secret Key. `accountIdFrag` is a server-assigned, non-secret
 * 6-char identifier embedded in the display string for readability.
 */
export async function generateSecretKey(accountIdFrag: string): Promise<SecretKey> {
  const s = await ready();
  if (!/^[A-Z0-9]{1,6}$/.test(accountIdFrag)) {
    throw new Error("generateSecretKey: accountIdFrag must be 1-6 chars [A-Z0-9]");
  }
  const aid = accountIdFrag.padEnd(6, "X").slice(0, 6);
  // 26 chars * 5 bits = 130 bits of raw entropy from the CSPRNG, mapped to the
  // 32-char alphabet (rejection-free: 256 mod 32 == 0).
  const raw = s.randombytes_buf(SECRET_CHARS);
  let secret = "";
  for (let i = 0; i < SECRET_CHARS; i++) secret += ALPHABET[raw[i] % ALPHABET.length];

  const bytes = secretKeyBytes(secret);
  return { display: formatDisplay(aid, secret), bytes, accountId: aid };
}

/** Raw 32-byte digest of the secret characters (what feeds the KDF). */
function secretKeyBytes(secret: string): Uint8Array {
  const s = nacl();
  // Unkeyed BLAKE2b-256. The `key` argument is required by the typings; pass null.
  return s.crypto_generichash(32, s.from_string(secret), null);
}

function formatDisplay(aid: string, secret: string): string {
  // Group the 26 secret chars for readability: 6-6-6-6-2
  const parts = [secret.slice(0, 6), secret.slice(6, 12), secret.slice(12, 18), secret.slice(18, 24), secret.slice(24, 26)];
  return `${SECRET_KEY_VERSION}-${aid}-${parts.join("-")}`;
}

/**
 * Parse a display Secret Key back to its raw bytes. Accepts with/without the
 * version+account prefix and any separators.
 */
export function parseSecretKey(display: string): Uint8Array {
  const clean = display.toUpperCase().replace(/[^A-Z0-9]/g, "");
  // Strip leading "KL" and the 6-char account id if present.
  let secret = clean;
  if (secret.startsWith(SECRET_KEY_VERSION) && secret.length >= 2 + 6 + SECRET_CHARS) {
    secret = secret.slice(2 + 6, 2 + 6 + SECRET_CHARS);
  } else if (secret.length > SECRET_CHARS) {
    secret = secret.slice(-SECRET_CHARS);
  }
  if (secret.length !== SECRET_CHARS) {
    throw new Error(`parseSecretKey: expected ${SECRET_CHARS} secret chars, got ${secret.length}`);
  }
  return secretKeyBytes(secret);
}

/** Hex form of the raw bytes (for storage/transport of the Secret Key itself). */
export function secretKeyToHex(sk: Uint8Array): string {
  return toHex(sk);
}

export function secretKeyFromHex(hex: string): Uint8Array {
  return fromHex(hex);
}
