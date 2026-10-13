import { describe, expect, it } from "vitest";
import { findReuse, isOld, scorePassword } from "../src/audit.js";

describe("scorePassword", () => {
  it("flags well-known leaked passwords as critical", () => {
    for (const pw of ["password", "123456", "qwerty", "letmein", "P@ssw0rd".toLowerCase()]) {
      const s = scorePassword(pw);
      expect(s.score, pw).toBe(0);
      expect(s.reasons.length).toBeGreaterThan(0);
    }
  });

  it("scores short / single-class passwords low", () => {
    expect(scorePassword("abcdef").score).toBeLessThanOrEqual(1);
    expect(scorePassword("alllowercaseandlongenough").score).toBeLessThanOrEqual(1);
  });

  it("penalizes sequences and repeats", () => {
    expect(scorePassword("Xqwerty9!Zx").score).toBeLessThanOrEqual(1);
    expect(scorePassword("Aaa12345!zzqwx").score).toBeLessThanOrEqual(1);
  });

  it("scores a generated 20-char class password high", () => {
    const s = scorePassword("n7uJ$PjDsOl#N#by8#s]", { entropyBits: 131 });
    expect(s.score).toBeGreaterThanOrEqual(3);
    expect(s.reasons).toEqual([]);
  });

  it("scores a 6-word passphrase >= 3", () => {
    const s = scorePassword("Just-Using-Student-Updated-Foreign-Never");
    expect(s.score).toBeGreaterThanOrEqual(3);
  });

  it("blocklist beats entropy floor", () => {
    expect(scorePassword("password", { entropyBits: 200 }).score).toBe(0);
  });

  it("is unicode-safe (no crash, code-point length)", () => {
    const s = scorePassword("Pässwörd-mīt-ƒøur-🔒-løng");
    expect(s.score).toBeGreaterThanOrEqual(2);
    expect(() => scorePassword("a\u0301bc")).not.toThrow();
  });

  it("handles empty input", () => {
    expect(scorePassword("").score).toBe(0);
  });

  it("blocklist match is case-insensitive and NFKC-normalized", () => {
    expect(scorePassword("PASSWORD").score).toBe(0);
    expect(scorePassword("PassWord").score).toBe(0);
    // fullwidth "ｐａｓｓｗｏｒｄ" NFKC-normalizes to "password"
    expect(scorePassword("\uFF30\uFF41\uFF53\uFF53\uFF57\uFF4F\uFF52\uFF44").score).toBe(0);
  });

  it("detects reverse sequences (9876, dcba)", () => {
    expect(scorePassword("X9876mQ!zzpl").score).toBeLessThanOrEqual(1);
    expect(scorePassword("Wdcba7!kkmnq").score).toBeLessThanOrEqual(1);
  });

  it("detects keyboard-row sequences (uiop, asdf)", () => {
    expect(scorePassword("ZXuiop9!kkwq").score).toBeLessThanOrEqual(1);
    expect(scorePassword("Qasdf7!xxmbr").score).toBeLessThanOrEqual(1);
  });

  it("entropy floor cannot rescue a 7-char password", () => {
    const s = scorePassword("Ab3!dE9", { entropyBits: 200 });
    expect(s.score).toBeLessThanOrEqual(1);
    expect(s.reasons).toContain("Shorter than 8 characters");
  });

  it("long single-class passphrase-style string still capped low", () => {
    expect(scorePassword("aaaaaaaaaaaaaaaaaaaaaaaaaaaa").score).toBeLessThanOrEqual(1);
  });
});

describe("findReuse", () => {
  const a = { id: "a", password: "shared-1" };
  const b = { id: "b", password: "shared-1" };
  const c = { id: "c", password: "unique-2" };
  const d = { id: "d", password: "" };

  it("groups passwords used by 2+ logins", () => {
    const groups = findReuse([a, b, c, d]);
    expect([...groups.keys()]).toEqual(["shared-1"]);
    expect(groups.get("shared-1")!.map((l) => l.id)).toEqual(["a", "b"]);
  });

  it("ignores empty passwords and singletons", () => {
    expect(findReuse([c, d]).size).toBe(0);
  });

  it("is exact-match, not prefix or case-folded", () => {
    expect(findReuse([{ id: "1", password: "Abc" }, { id: "2", password: "abc" }]).size).toBe(0);
  });

  it("groups 3-way reuse and multiple groups", () => {
    const rows = [
      { id: "a", password: "x1" },
      { id: "b", password: "x1" },
      { id: "c", password: "x1" },
      { id: "d", password: "x2" },
      { id: "e", password: "x2" },
      { id: "f", password: "solo" },
    ];
    const groups = findReuse(rows);
    expect(groups.size).toBe(2);
    expect(groups.get("x1")!.map((l) => l.id)).toEqual(["a", "b", "c"]);
    expect(groups.get("x2")!.map((l) => l.id)).toEqual(["d", "e"]);
    expect(groups.has("solo")).toBe(false);
  });
});

describe("isOld", () => {
  const now = Date.parse("2026-10-14T00:00:00Z");
  it("flags items older than the threshold", () => {
    expect(isOld("2026-01-01T00:00:00Z", 180, now)).toBe(true);
    expect(isOld("2026-10-01T00:00:00Z", 180, now)).toBe(false);
  });
  it("tolerates garbage timestamps", () => {
    expect(isOld("not-a-date", 180, now)).toBe(false);
  });
  it("boundary is exclusive: exactly 180d is not old, +1ms is", () => {
    const at = new Date(now - 180 * 24 * 60 * 60 * 1000).toISOString();
    expect(isOld(at, 180, now)).toBe(false);
    const past = new Date(now - 180 * 24 * 60 * 60 * 1000 - 1).toISOString();
    expect(isOld(past, 180, now)).toBe(true);
  });
});
