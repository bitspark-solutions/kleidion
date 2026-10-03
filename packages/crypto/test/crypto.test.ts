import { describe, it, expect, beforeAll } from "vitest";
import { ready, nacl } from "../src/sodium";
import { toHex, fromHex, timingSafeEqual } from "../src/encoding";
import {
  derive2SKD, deriveAUK, deriveSrpX, generateSalt,
  KDF_INTERACTIVE, KDF_SENSITIVE,
} from "../src/kdf";
import { generateSecretKey, parseSecretKey, secretKeyToHex, secretKeyFromHex } from "../src/secretkey";
import {
  generateVaultKey, encryptItem, decryptItem, searchHmac,
  wrapVaultKey, unwrapVaultKey,
} from "../src/item";

beforeAll(async () => {
  await ready();
});

describe("Secret Key", () => {
  it("generates a display string with the KL prefix and 26 secret chars", async () => {
    const sk = await generateSecretKey("AB12CD");
    expect(sk.display).toMatch(/^KL-AB12CD-/);
    const secretPart = sk.display.split("-").slice(2).join("");
    expect(secretPart).toHaveLength(26);
    expect(sk.accountId).toBe("AB12CD");
  });

  it("produces 32 raw bytes", async () => {
    const sk = await generateSecretKey("ZZZZZZ");
    expect(sk.bytes).toHaveLength(32);
  });

  it("round-trips through parseSecretKey", async () => {
    const sk = await generateSecretKey("AB12CD");
    const parsed = parseSecretKey(sk.display);
    expect(timingSafeEqual(parsed, sk.bytes)).toBe(true);
  });

  it("parse tolerates missing separators/prefix", async () => {
    const sk = await generateSecretKey("AB12CD");
    const secretPart = sk.display.split("-").slice(2).join("");
    expect(timingSafeEqual(parseSecretKey(secretPart), sk.bytes)).toBe(true);
  });

  it("hex round-trips", async () => {
    const sk = await generateSecretKey("AB12CD");
    expect(timingSafeEqual(secretKeyFromHex(secretKeyToHex(sk.bytes)), sk.bytes)).toBe(true);
  });

  it("two keys are different (CSPRNG)", async () => {
    const a = await generateSecretKey("AAAAAA");
    const b = await generateSecretKey("AAAAAA");
    expect(timingSafeEqual(a.bytes, b.bytes)).toBe(false);
  });

  it("rejects invalid account id fragments", async () => {
    await expect(generateSecretKey("lower!")).rejects.toThrow();
  });
});

describe("KDF (2SKD)", () => {
  it("is deterministic for the same inputs", async () => {
    const salt = fromHex("00112233445566778899aabbccddeeff");
    const sk = fromHex("aa".repeat(32));
    const a = await deriveAUK("pw", sk, salt, KDF_INTERACTIVE);
    const b = await deriveAUK("pw", sk, salt, KDF_INTERACTIVE);
    expect(timingSafeEqual(a, b)).toBe(true);
    expect(a).toHaveLength(32);
  });

  it("AUK and SRP-x are independent (different purposes → different keys)", async () => {
    const salt = fromHex("00112233445566778899aabbccddeeff");
    const sk = fromHex("bb".repeat(32));
    const auk = await derive2SKD("pw", sk, salt, KDF_INTERACTIVE, "auk");
    const srpx = await derive2SKD("pw", sk, salt, KDF_INTERACTIVE, "srp-x");
    expect(timingSafeEqual(auk, srpx)).toBe(false);
  });

  it("changes when the password changes", async () => {
    const salt = fromHex("00112233445566778899aabbccddeeff");
    const sk = fromHex("cc".repeat(32));
    const a = await deriveAUK("pw1", sk, salt, KDF_INTERACTIVE);
    const b = await deriveAUK("pw2", sk, salt, KDF_INTERACTIVE);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it("changes when the Secret Key changes", async () => {
    const salt = fromHex("00112233445566778899aabbccddeeff");
    const a = await deriveAUK("pw", fromHex("11".repeat(32)), salt, KDF_INTERACTIVE);
    const b = await deriveAUK("pw", fromHex("22".repeat(32)), salt, KDF_INTERACTIVE);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it("deriveSrpX returns 32-byte lowercase hex", async () => {
    const salt = await generateSalt();
    const sk = fromHex("dd".repeat(32));
    const x = await deriveSrpX("pw", sk, salt, KDF_INTERACTIVE);
    expect(x).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a wrong-length salt", async () => {
    const sk = fromHex("ee".repeat(32));
    await expect(deriveAUK("pw", sk, fromHex("0011"), KDF_INTERACTIVE)).rejects.toThrow();
  });

  it("generateSalt returns 16 bytes", async () => {
    const salt = await generateSalt();
    expect(salt).toHaveLength(16);
  });
});

describe("Item encryption (XChaCha20-Poly1305)", () => {
  it("round-trips an item", async () => {
    const vk = await generateVaultKey();
    const json = JSON.stringify({ title: "GitHub", username: "alice", password: "***" });
    const enc = await encryptItem(vk, json);
    expect(enc.nonce).toHaveLength(24);
    const dec = await decryptItem(vk, enc);
    expect(dec).toBe(json);
  });

  it("uses a fresh nonce each time (ciphertext differs)", async () => {
    const vk = await generateVaultKey();
    const a = await encryptItem(vk, "same");
    const b = await encryptItem(vk, "same");
    expect(toHex(a.ciphertext)).not.toBe(toHex(b.ciphertext));
    expect(toHex(a.nonce)).not.toBe(toHex(b.nonce));
  });

  it("detects tampering with the ciphertext", async () => {
    const vk = await generateVaultKey();
    const enc = await encryptItem(vk, "secret data");
    enc.ciphertext[0] ^= 0xff; // flip a byte
    await expect(decryptItem(vk, enc)).rejects.toThrow();
  });

  it("fails to decrypt with the wrong key", async () => {
    const vk = await generateVaultKey();
    const wrong = await generateVaultKey();
    const enc = await encryptItem(vk, "secret");
    await expect(decryptItem(wrong, enc)).rejects.toThrow();
  });

  it("rejects a wrong-length vault key", async () => {
    await expect(encryptItem(new Uint8Array(16), "x")).rejects.toThrow();
  });
});

describe("searchHmac", () => {
  it("is deterministic and normalizes case/whitespace", async () => {
    const vk = await generateVaultKey();
    const a = await searchHmac(vk, "  GitHub  Login ");
    const b = await searchHmac(vk, "github login");
    expect(timingSafeEqual(a, b)).toBe(true);
    expect(a).toHaveLength(32);
  });

  it("differs for different titles", async () => {
    const vk = await generateVaultKey();
    const a = await searchHmac(vk, "GitHub");
    const b = await searchHmac(vk, "GitLab");
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it("differs for different vault keys (no cross-vault correlation)", async () => {
    const a = await searchHmac(await generateVaultKey(), "GitHub");
    const b = await searchHmac(await generateVaultKey(), "GitHub");
    expect(timingSafeEqual(a, b)).toBe(false);
  });
});

describe("Vault key wrapping (sealed box / X25519)", () => {
  it("round-trips a vault key through wrap/unwrap", async () => {
    const s = nacl();
    const kp = s.crypto_box_keypair();
    const vk = await generateVaultKey();
    const wrapped = await wrapVaultKey(vk, kp.publicKey);
    const unwrapped = await unwrapVaultKey(wrapped, kp.publicKey, kp.privateKey);
    expect(timingSafeEqual(unwrapped, vk)).toBe(true);
  });

  it("fails to unwrap with the wrong private key", async () => {
    const s = nacl();
    const kp = s.crypto_box_keypair();
    const wrong = s.crypto_box_keypair();
    const vk = await generateVaultKey();
    const wrapped = await wrapVaultKey(vk, kp.publicKey);
    await expect(unwrapVaultKey(wrapped, wrong.publicKey, wrong.privateKey)).rejects.toThrow();
  });

  it("sharing: same vault key wrapped for two recipients unwraps on both", async () => {
    const s = nacl();
    const alice = s.crypto_box_keypair();
    const bob = s.crypto_box_keypair();
    const vk = await generateVaultKey();
    const wA = await wrapVaultKey(vk, alice.publicKey);
    const wB = await wrapVaultKey(vk, bob.publicKey);
    const ua = await unwrapVaultKey(wA, alice.publicKey, alice.privateKey);
    const ub = await unwrapVaultKey(wB, bob.publicKey, bob.privateKey);
    expect(timingSafeEqual(ua, vk)).toBe(true);
    expect(timingSafeEqual(ub, vk)).toBe(true);
  });
});
