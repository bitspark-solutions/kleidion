// Item + vault-key encryption (ADR-005).
//
// - Vault keys: random 256-bit symmetric keys.
// - Items: XChaCha20-Poly1305 (AEAD) over canonical JSON, random 24-byte nonce
//   per encryption. The server stores {ciphertext, nonce, searchHmac} and can
//   never recover plaintext.
// - Vault-key wrapping: crypto_box_seal (X25519 + XChaCha20-Poly1305) with a
//   member's public key → sharing = wrap once per member, items untouched.
// - searchHmac: HMAC-SHA256 under a vault-key-derived search subkey over the
//   normalized title, so the server can match searches without decrypting.

import { ready, nacl } from "./sodium";
import { fromHex, toHex, utf8Bytes, timingSafeEqual } from "./encoding";

export const VAULT_KEY_BYTES = 32;
const SEARCH_INFO = utf8Bytes("kleidion-search-v1");

/** Generate a random 256-bit vault key. */
export async function generateVaultKey(): Promise<Uint8Array> {
  const s = await ready();
  return s.randombytes_buf(VAULT_KEY_BYTES);
}

export interface EncryptedItem {
  /** Ciphertext INCLUDING the 16-byte Poly1305 tag (sodium convention). */
  ciphertext: Uint8Array;
  /** 24-byte XChaCha20 nonce. */
  nonce: Uint8Array;
}

/** Encrypt an item's canonical JSON with the vault key. */
export async function encryptItem(vaultKey: Uint8Array, itemJson: string): Promise<EncryptedItem> {
  const s = await ready();
  if (vaultKey.length !== VAULT_KEY_BYTES) throw new Error("encryptItem: vault key must be 32 bytes");
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    utf8Bytes(itemJson),
    null, // no additional data
    null,
    nonce,
    vaultKey,
  );
  return { ciphertext, nonce };
}

/** Decrypt an item; throws if the tag fails (tamper detection). */
export async function decryptItem(vaultKey: Uint8Array, enc: EncryptedItem): Promise<string> {
  const s = await ready();
  const plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    enc.ciphertext,
    null,
    enc.nonce,
    vaultKey,
  );
  return s.to_string(plain);
}

/**
 * Search HMAC over a normalized title, keyed by a subkey derived from the
 * vault key via HKDF-free domain separation (generichash with a fixed context).
 * The server stores this and can match on it without decrypting the item.
 */
export async function searchHmac(vaultKey: Uint8Array, title: string): Promise<Uint8Array> {
  const s = await ready();
  const subkey = s.crypto_generichash(32, SEARCH_INFO, vaultKey);
  const normalized = normalizeTitle(title);
  return s.crypto_auth_hmacsha256(utf8Bytes(normalized), subkey);
}

function normalizeTitle(title: string): string {
  return title.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Wrap a vault key with a member's X25519 public key (sealed box: ephemeral
 * sender key + XChaCha20-Poly1305). Anonymous — the recipient can't tell who
 * wrapped it, which is what we want for shared-vault membership.
 */
export async function wrapVaultKey(vaultKey: Uint8Array, recipientPubKey: Uint8Array): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_box_seal(vaultKey, recipientPubKey);
}

/** Unwrap a vault key with the member's X25519 keypair. Throws if it fails. */
export async function unwrapVaultKey(
  wrapped: Uint8Array,
  pubKey: Uint8Array,
  privKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_box_seal_open(wrapped, pubKey, privKey);
}

export { fromHex, toHex, timingSafeEqual };
