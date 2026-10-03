import { describe, it, expect } from "vitest";
import { createHash, randomBytes } from "crypto";

import { sha256Bytes, sha256HexOf } from "../src/sha256";

const nodeHex = (buf: Uint8Array) => createHash("sha256").update(buf).digest("hex");

describe("sha256Bytes / sha256HexOf — RFC 6234 known-answer vectors", () => {
  // Official NIST/RFC test vectors.
  const vectors: Array<[string, string]> = [
    ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    [
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ],
    [
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ],
  ];
  for (const [input, expected] of vectors) {
    it(`sha256(${JSON.stringify(input.slice(0, 24))}${input.length > 24 ? "…" : ""})`, () => {
      const bytes = new TextEncoder().encode(input);
      expect(sha256HexOf(bytes)).toBe(expected);
    });
  }

  it("one million 'a' characters (RFC 6234 long vector)", () => {
    const input = new Uint8Array(1_000_000).fill(0x61);
    expect(sha256HexOf(input)).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });
});

describe("cross-check against node:crypto (the implementation we're replacing)", () => {
  it("matches for lengths 0..300 (exercises every padding path)", () => {
    for (let len = 0; len <= 300; len++) {
      const buf = randomBytes(len);
      expect(sha256HexOf(buf)).toBe(nodeHex(buf));
    }
  });

  it("matches at 64-byte block boundaries (55, 56, 63, 64, 65, 119, 120, 128)", () => {
    // 55/56 and 119/120 straddle the point where the length field needs an
    // extra padding block — classic off-by-one territory.
    for (const len of [55, 56, 63, 64, 65, 119, 120, 128, 129]) {
      const buf = randomBytes(len);
      expect(sha256HexOf(buf)).toBe(nodeHex(buf));
    }
  });

  it("matches on large random inputs", () => {
    for (const len of [4096, 65537, 200_000]) {
      const buf = randomBytes(len);
      expect(sha256HexOf(buf)).toBe(nodeHex(buf));
    }
  });

  it("sha256Bytes returns 32 raw bytes equal to the hex form", () => {
    const buf = randomBytes(100);
    const raw = sha256Bytes(buf);
    expect(raw).toBeInstanceOf(Uint8Array);
    expect(raw.length).toBe(32);
    expect(Buffer.from(raw).toString("hex")).toBe(nodeHex(buf));
  });

  it("is deterministic and does not mutate its input", () => {
    const buf = new Uint8Array(randomBytes(200));
    const copy = Uint8Array.from(buf);
    const a = sha256HexOf(buf);
    const b = sha256HexOf(buf);
    expect(a).toBe(b);
    // Compare bytes, not container types (Buffer vs Uint8Array differ under toEqual).
    expect(sha256HexOf(buf)).toBe(sha256HexOf(copy));
    expect(Array.from(buf)).toEqual(Array.from(copy));
  });
});
