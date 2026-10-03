import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { ready } from "../src/sodium";
import {
  generatePassword,
  generatePassphrase,
  passwordEntropyBits,
  passphraseEntropyBits,
  strengthLabel,
  WORDLIST,
  WORDLIST_SIZE,
  type PasswordRecipe,
  type PassphraseRecipe,
} from "../src/password";

beforeAll(async () => {
  await ready();
});

const allClasses: PasswordRecipe = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

function recipe(over: Partial<PasswordRecipe> = {}): PasswordRecipe {
  return { ...allClasses, ...over };
}

const AMBIGUOUS_RE = /[Il1O0|`'"]/;

describe("generatePassword", () => {
  it("returns the requested length (default 20 when not finite)", async () => {
    expect(await generatePassword(recipe({ length: 24 }))).toHaveLength(24);
    expect(await generatePassword(recipe({ length: 128 }))).toHaveLength(128);
    expect(await generatePassword(recipe({ length: NaN }))).toHaveLength(20);
  });

  it("clamps out-of-range lengths to 8..128", async () => {
    expect(await generatePassword(recipe({ length: 1 }))).toHaveLength(8);
    expect(await generatePassword(recipe({ length: -5 }))).toHaveLength(8);
    expect(await generatePassword(recipe({ length: 10000 }))).toHaveLength(128);
  });

  it("contains only allowed charset characters", async () => {
    for (let i = 0; i < 20; i++) {
      const pw = await generatePassword(recipe({ length: 32 }));
      expect(pw).toMatch(/^[A-Za-z0-9!-\/:-@\[-`{-~]+$/);
    }
  });

  it("respects `exclude`", async () => {
    for (let i = 0; i < 20; i++) {
      const pw = await generatePassword(recipe({ length: 64, exclude: "abc&*@" }));
      expect(pw).not.toMatch(/[abc&*@]/);
    }
  });

  it("omits ambiguous characters when excludeAmbiguous is set", async () => {
    for (let i = 0; i < 20; i++) {
      const pw = await generatePassword(recipe({ length: 64, excludeAmbiguous: true }));
      expect(AMBIGUOUS_RE.test(pw)).toBe(false);
    }
  });

  it("guarantees at least one char from each enabled class (50 iterations)", async () => {
    for (let i = 0; i < 50; i++) {
      const pw = await generatePassword(recipe({ length: 12 }));
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/);
    }
  });

  it("guarantees classes with a partial recipe (lower+digits only)", async () => {
    for (let i = 0; i < 50; i++) {
      const pw = await generatePassword(recipe({ length: 10, upper: false, symbols: false }));
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).not.toMatch(/[A-Z]/);
      expect(pw).toMatch(/^[a-z0-9]+$/);
    }
  });

  it("throws when no class is enabled", async () => {
    await expect(
      generatePassword(recipe({ upper: false, lower: false, digits: false, symbols: false })),
    ).rejects.toThrow();
  });

  it("throws when exclusions empty an enabled class", async () => {
    await expect(generatePassword(recipe({ digits: true, upper: false, lower: false, symbols: false, exclude: "0123456789" }))).rejects.toThrow();
  });

  it("produces different passwords on repeated calls", async () => {
    const a = await generatePassword(recipe({ length: 32 }));
    const b = await generatePassword(recipe({ length: 32 }));
    expect(a).not.toBe(b);
  });
});

describe("generatePassphrase", () => {
  it("defaults to 6 words joined by '-'", async () => {
    const recipe = { words: 6, separator: "-", capitalize: false, includeNumber: false };
    const pp = await generatePassphrase(recipe);
    expect(pp.split("-")).toHaveLength(6);
  });

  it("honors word count and custom separator", async () => {
    const pp = await generatePassphrase({ words: 4, separator: ".", capitalize: false, includeNumber: false });
    const parts = pp.split(".");
    expect(parts).toHaveLength(4);
    expect(pp).not.toContain("-");
  });

  it("every word is in the wordlist", async () => {
    for (let i = 0; i < 20; i++) {
      const pp = await generatePassphrase({ words: 7, separator: " ", capitalize: false, includeNumber: false });
      for (const w of pp.split(" ")) expect(WORDLIST).toContain(w);
    }
  });

  it("capitalize uppercases exactly the first letter of each word", async () => {
    for (let i = 0; i < 20; i++) {
      const pp = await generatePassphrase({ words: 5, separator: "-", capitalize: true, includeNumber: false });
      for (const w of pp.split("-")) {
        expect(w[0]).toBe(w[0].toUpperCase());
        expect(w[0]).not.toBe(w[0].toLowerCase());
        expect(w.slice(1)).toBe(w.slice(1).toLowerCase());
        expect(WORDLIST).toContain(w.toLowerCase());
      }
    }
  });

  it("includeNumber appends a zero-padded 0-9999 token", async () => {
    for (let i = 0; i < 20; i++) {
      const pp = await generatePassphrase({ words: 3, separator: "-", capitalize: false, includeNumber: true });
      const parts = pp.split("-");
      expect(parts).toHaveLength(4);
      const token = parts[3];
      expect(token).toMatch(/^[0-9]{4}$/);
      expect(Number(token)).toBeLessThanOrEqual(9999);
      for (const w of parts.slice(0, 3)) expect(WORDLIST).toContain(w);
    }
  });

  it("produces different passphrases on repeated calls", async () => {
    const r: PassphraseRecipe = { words: 6, separator: "-", capitalize: false, includeNumber: false };
    const a = await generatePassphrase(r);
    const b = await generatePassphrase(r);
    expect(a).not.toBe(b);
  });

  it("clamps word count to 1..32", async () => {
    const lo = await generatePassphrase({ words: 0, separator: "-", capitalize: false, includeNumber: false });
    expect(lo.split("-")).toHaveLength(1);
    const hi = await generatePassphrase({ words: 1000, separator: "-", capitalize: false, includeNumber: false });
    expect(hi.split("-")).toHaveLength(32);
  });
});

describe("wordlist", () => {
  it("has exactly WORDLIST_SIZE = 1024 unique lowercase alpha words", () => {
    expect(WORDLIST_SIZE).toBe(1024);
    expect(WORDLIST).toHaveLength(1024);
    expect(new Set(WORDLIST).size).toBe(1024);
    for (const w of WORDLIST) {
      expect(w).toMatch(/^[a-z]+$/);
    }
  });
});

describe("entropy", () => {
  it("passwordEntropyBits = length * log2(charset)", () => {
    // lower only (26), length 20 → 20 * log2(26)
    const bits = passwordEntropyBits(recipe({ length: 20, upper: false, digits: false, symbols: false }));
    expect(bits).toBeCloseTo(20 * Math.log2(26), 9);
    // digits only (10), length 8 → 8 * log2(10)
    expect(passwordEntropyBits(recipe({ length: 8, upper: false, lower: false, symbols: false }))).toBeCloseTo(
      8 * Math.log2(10),
      9,
    );
    // no classes → 0
    expect(
      passwordEntropyBits(recipe({ upper: false, lower: false, digits: false, symbols: false })),
    ).toBe(0);
  });

  it("passwordEntropyBits accounts for excludeAmbiguous shrinking the charset", () => {
    const withAmb = passwordEntropyBits(recipe({ length: 20 }));
    const noAmb = passwordEntropyBits(recipe({ length: 20, excludeAmbiguous: true }));
    expect(noAmb).toBeLessThan(withAmb);
  });

  it("passphraseEntropyBits = words * log2(WORDLIST_SIZE)", () => {
    expect(passphraseEntropyBits({ words: 6, separator: "-", capitalize: false, includeNumber: false })).toBeCloseTo(
      6 * Math.log2(1024),
      9,
    );
    expect(passphraseEntropyBits({ words: 6, separator: "-", capitalize: false, includeNumber: false })).toBe(60);
    expect(passphraseEntropyBits({ words: 10, separator: "-", capitalize: false, includeNumber: false })).toBe(100);
  });

  it("strengthLabel thresholds (28/36/60/128)", () => {
    expect(strengthLabel(0)).toBe("very weak");
    expect(strengthLabel(27.9)).toBe("very weak");
    expect(strengthLabel(28)).toBe("weak");
    expect(strengthLabel(35.9)).toBe("weak");
    expect(strengthLabel(36)).toBe("fair");
    expect(strengthLabel(59.9)).toBe("fair");
    expect(strengthLabel(60)).toBe("strong");
    expect(strengthLabel(127.9)).toBe("strong");
    expect(strengthLabel(128)).toBe("very strong");
    expect(strengthLabel(300)).toBe("very strong");
  });
});

describe("never uses Math.random", () => {
  const original = Math.random;

  afterAll(() => {
    Math.random = original;
    vi.restoreAllMocks();
  });

  it("generatePassword and generatePassphrase succeed with Math.random stubbed to throw", async () => {
    Math.random = () => {
      throw new Error("Math.random must not be used");
    };
    const pw = await generatePassword(recipe({ length: 20 }));
    expect(pw).toHaveLength(20);
    const pp = await generatePassphrase({ words: 5, separator: "-", capitalize: true, includeNumber: true });
    expect(pp.split("-")).toHaveLength(6);
    // Entropy/label are pure math and must also work.
    expect(passwordEntropyBits(recipe({ length: 20 }))).toBeGreaterThan(0);
    expect(strengthLabel(64)).toBe("strong");
  });
});
