import { describe, it, expect, beforeAll } from "vitest";
import { ready } from "../src/sodium";
import {
  base32Decode, base32Encode, hotp, totp, parseOtpauthUri,
} from "../src/totp";

beforeAll(async () => {
  await ready();
});

// RFC 6238 §3 seed: ASCII "12345678901234567890" (20 bytes, SHA1 row).
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const at = (unixSeconds: number) => new Date(unixSeconds * 1000);

describe("base32", () => {
  it("decodes the RFC 6238 seed to the ASCII byte string", () => {
    const bytes = base32Decode(RFC_SECRET);
    expect(Array.from(bytes)).toEqual(Array.from(new TextEncoder().encode("12345678901234567890")));
  });

  it("round-trips arbitrary bytes through base32Encode/base32Decode", () => {
    for (const src of ["a", "ab", "abc", "abcd", "abcde", "kleidion secret key!"]) {
      const bytes = new TextEncoder().encode(src);
      expect(Array.from(base32Decode(base32Encode(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it("accepts lowercase, spaces and dashes (Google Authenticator style)", () => {
    const a = base32Decode("jbsw y3dp ejrb uq3d l5kk c4zh e5xg gzdq");
    const b = base32Decode("JBSWY3DPEJRBUQ3DL5KKC4ZHE5XGGZDQ");
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("rejects invalid characters", () => {
    expect(() => base32Decode("0189")).toThrow(/Invalid base32/);
  });
});

describe("HOTP (RFC 4226)", () => {
  it("produces the RFC 4226 test values (seed '12345678901234567890', 8 digits)", async () => {
    const expected = [
      "755224", "287082", "359152", "969429", "338314",
      "254676", "287922", "162583", "399871", "520489",
    ];
    for (let c = 0; c < expected.length; c++) {
      expect(await hotp(RFC_SECRET, c)).toBe(expected[c]);
    }
  });
});

describe("TOTP (RFC 6238)", () => {
  it("matches the published RFC 6238 vectors for SHA1", async () => {
    const vectors: [number, string][] = [
      [59, "94287082"],
      [1111111109, "07081804"],
      [1111111111, "14050471"],
      [1234567890, "89005924"],
      [2000000000, "69279037"],
      [20000000000, "65353130"],
    ];
    for (const [t, code] of vectors) {
      const got = await totp(RFC_SECRET, { at: at(t), digits: 8 });
      expect(got.code).toBe(code);
    }
  });

  it("matches the SHA256 row of the RFC table (seed length 32)", async () => {
    // RFC uses ASCII 32..63; base32 of "12345678901234567890123456789012".
    const sha256Secret = base32Encode(new TextEncoder().encode("12345678901234567890123456789012"));
    const got = await totp(sha256Secret, { at: at(59), digits: 8, algorithm: "sha256" });
    expect(got.code).toBe("46119246");
  });

  it("6-digit codes are the 8-digit RFC codes mod 1e6", async () => {
    const six = await totp(RFC_SECRET, { at: at(59) });
    expect(six.code).toBe("287082");
    expect(six.secondsRemaining).toBe(1); // 59s into a 30s window -> 1s left
  });

  it("reports countdown consistent with the wall clock", async () => {
    const got = await totp(RFC_SECRET, { at: at(30) });
    expect(got.secondsRemaining).toBe(30);
    expect(got.period).toBe(30);
  });
});

describe("otpauth:// URI parsing", () => {
  it("parses the full Google-style URI", () => {
    const p = parseOtpauthUri(
      "otpauth://totp/GitHub:alice@example.com?secret=jbsw y3dp ejrb uq3d&issuer=GitHub&digits=6&period=30",
    );
    expect(p.secret).toBe("JBSWY3DPEJRBUQ3D");
    expect(p.issuer).toBe("GitHub");
    expect(p.account).toBe("alice@example.com");
    expect(p.digits).toBe(6);
    expect(p.period).toBe(30);
    expect(p.algorithm).toBe("sha1");
  });

  it("takes issuer from the label when the query param is absent", () => {
    const p = parseOtpauthUri("otpauth://totp/ACME%20Co:bob@example.net?secret=JBSWY3DP");
    expect(p.issuer).toBe("ACME Co");
    expect(p.account).toBe("bob@example.net");
  });

  it("supports SHA512 and 8 digits", () => {
    const p = parseOtpauthUri(`otpauth://totp/x:y?secret=${RFC_SECRET}&algorithm=SHA512&digits=8`);
    expect(p.algorithm).toBe("sha512");
    expect(p.digits).toBe(8);
  });

  it("rejects non-otpauth schemes and missing secrets", () => {
    expect(() => parseOtpauthUri("https://example.com")).toThrow(/otpauth/);
    expect(() => parseOtpauthUri("otpauth://totp/A:b?secret=")).toThrow(/secret/);
    expect(() => parseOtpauthUri("otpauth://hotp/A:b?secret=JBSWY3DP")).toThrow(/totp/);
  });
});
