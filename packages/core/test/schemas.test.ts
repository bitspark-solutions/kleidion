import { describe, expect, it } from "vitest";
import {
  base64ByteLength,
  CreateItemInputSchema,
  CreateVaultInputSchema,
  isBase64,
  ItemPlainSchema,
  ItemSchema,
  PostCursorInputSchema,
  SyncChangesParamsSchema,
  UpdateItemInputSchema,
  VaultMetaSchema,
} from "../src/schemas.js";

const b64 = (n: number, fill = 7) =>
  Buffer.from(new Uint8Array(n).fill(fill)).toString("base64");

const NONCE24 = b64(24);
const HMAC32 = b64(32);
const CIPHERTEXT = b64(64, 9);

const validItem = {
  id: "9c0e5d3a-0000-4000-8000-000000000001",
  vaultId: "9c0e5d3a-0000-4000-8000-000000000002",
  itemType: 1,
  ciphertext: CIPHERTEXT,
  nonce: NONCE24,
  searchHmac: HMAC32,
  version: 3,
  favorite: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-02T00:00:00Z",
  deletedAt: null,
};

describe("base64 helpers", () => {
  it("accepts canonical base64", () => {
    expect(isBase64(NONCE24)).toBe(true);
    expect(isBase64(HMAC32)).toBe(true);
    expect(base64ByteLength(NONCE24)).toBe(24);
    expect(base64ByteLength(HMAC32)).toBe(32);
  });

  it("rejects empty, non-alphabet, and bad-padding strings", () => {
    expect(isBase64("")).toBe(false);
    expect(isBase64("not base64!!")).toBe(false);
    expect(isBase64("abc")).toBe(false); // length not multiple of 4
  });
});

describe("ItemSchema", () => {
  it("accepts a valid item", () => {
    expect(ItemSchema.safeParse(validItem).success).toBe(true);
  });

  it("accepts null searchHmac and non-null deletedAt", () => {
    const r = ItemSchema.safeParse({
      ...validItem,
      searchHmac: null,
      deletedAt: "2026-01-03T00:00:00Z",
    });
    expect(r.success).toBe(true);
  });

  it("rejects itemType outside 1..4", () => {
    expect(ItemSchema.safeParse({ ...validItem, itemType: 0 }).success).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, itemType: 5 }).success).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, itemType: 2.5 }).success).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, itemType: "1" }).success).toBe(false);
  });

  it("accepts every itemType 1..4", () => {
    for (const t of [1, 2, 3, 4]) {
      expect(ItemSchema.safeParse({ ...validItem, itemType: t }).success).toBe(true);
    }
  });

  it("rejects a missing nonce", () => {
    const { nonce: _nonce, ...noNonce } = validItem;
    expect(ItemSchema.safeParse(noNonce).success).toBe(false);
  });

  it("rejects non-base64 ciphertext/nonce", () => {
    expect(
      ItemSchema.safeParse({ ...validItem, ciphertext: "not-base64!!" }).success,
    ).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, nonce: "" }).success).toBe(false);
  });

  it("rejects a nonce that is not 24 bytes", () => {
    expect(
      ItemSchema.safeParse({ ...validItem, nonce: b64(12) }).success,
    ).toBe(false);
  });

  it("rejects a searchHmac that is not 32 bytes", () => {
    expect(
      ItemSchema.safeParse({ ...validItem, searchHmac: b64(16) }).success,
    ).toBe(false);
  });

  it("rejects ciphertext over 1 MiB", () => {
    const huge = b64(1024 * 1024 + 1);
    expect(
      ItemSchema.safeParse({ ...validItem, ciphertext: huge }).success,
    ).toBe(false);
  });

  it("rejects a negative version and a fractional version", () => {
    expect(ItemSchema.safeParse({ ...validItem, version: -1 }).success).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, version: 1.5 }).success).toBe(false);
    expect(ItemSchema.safeParse({ ...validItem, version: 0 }).success).toBe(true);
  });
});

describe("VaultMetaSchema", () => {
  const validVault = {
    id: "v-1",
    kind: "personal",
    encryptedMeta: CIPHERTEXT,
    nonce: NONCE24,
    role: "admin",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  };

  it("accepts valid personal/shared kinds and all roles", () => {
    expect(VaultMetaSchema.safeParse(validVault).success).toBe(true);
    expect(VaultMetaSchema.safeParse({ ...validVault, kind: "shared" }).success).toBe(true);
    for (const role of ["admin", "write", "read"]) {
      expect(VaultMetaSchema.safeParse({ ...validVault, role }).success).toBe(true);
    }
  });

  it("rejects unknown kind/role", () => {
    expect(VaultMetaSchema.safeParse({ ...validVault, kind: "team" }).success).toBe(false);
    expect(VaultMetaSchema.safeParse({ ...validVault, role: "owner" }).success).toBe(false);
  });
});

describe("ItemPlainSchema", () => {
  it("accepts title-only plaintext", () => {
    expect(ItemPlainSchema.safeParse({ title: "GitHub" }).success).toBe(true);
  });

  it("accepts full plaintext with typed fields", () => {
    const plain = {
      title: "GitHub",
      notes: "work account",
      tags: ["dev", "sso"],
      fields: [
        { label: "user", value: "me", type: "text" },
        { label: "pw", value: "s3cret", type: "password" },
        { label: "site", value: "https://github.com", type: "url" },
        { label: "otp", value: "JBSWY3DPEHPK3PXP", type: "totp" },
      ],
    };
    expect(ItemPlainSchema.safeParse(plain).success).toBe(true);
  });

  it("rejects missing title and unknown field type", () => {
    expect(ItemPlainSchema.safeParse({ notes: "x" }).success).toBe(false);
    expect(
      ItemPlainSchema.safeParse({
        title: "t",
        fields: [{ label: "a", value: "b", type: "hidden" }],
      }).success,
    ).toBe(false);
  });
});

describe("request inputs", () => {
  it("CreateVaultInput: kind optional, requires base64 meta+nonce", () => {
    expect(
      CreateVaultInputSchema.safeParse({ encryptedMeta: CIPHERTEXT, nonce: NONCE24 })
        .success,
    ).toBe(true);
    expect(
      CreateVaultInputSchema.safeParse({
        kind: "shared",
        encryptedMeta: CIPHERTEXT,
        nonce: NONCE24,
      }).success,
    ).toBe(true);
    expect(CreateVaultInputSchema.safeParse({ nonce: NONCE24 }).success).toBe(false);
    expect(
      CreateVaultInputSchema.safeParse({ encryptedMeta: "!!", nonce: NONCE24 }).success,
    ).toBe(false);
  });

  it("CreateItemInput: searchHmac nullish, favorite optional", () => {
    const base = {
      vaultId: "v-1",
      itemType: 2,
      ciphertext: CIPHERTEXT,
      nonce: NONCE24,
    };
    expect(CreateItemInputSchema.safeParse(base).success).toBe(true);
    expect(
      CreateItemInputSchema.safeParse({ ...base, searchHmac: null }).success,
    ).toBe(true);
    expect(
      CreateItemInputSchema.safeParse({ ...base, searchHmac: HMAC32, favorite: true })
        .success,
    ).toBe(true);
    expect(
      CreateItemInputSchema.safeParse({ ...base, itemType: 7 }).success,
    ).toBe(false);
  });

  it("UpdateItemInput: all optional but each validated", () => {
    expect(UpdateItemInputSchema.safeParse({ favorite: true }).success).toBe(true);
    expect(
      UpdateItemInputSchema.safeParse({ ciphertext: CIPHERTEXT, nonce: NONCE24 })
        .success,
    ).toBe(true);
    expect(UpdateItemInputSchema.safeParse({ nonce: b64(10) }).success).toBe(false);
    expect(UpdateItemInputSchema.safeParse({ itemType: 0 }).success).toBe(false);
  });

  it("SyncChangesParams: since required, non-negative", () => {
    expect(SyncChangesParamsSchema.safeParse({ vaultId: "v", since: 0 }).success).toBe(true);
    expect(SyncChangesParamsSchema.safeParse({ vaultId: "v" }).success).toBe(false);
    expect(SyncChangesParamsSchema.safeParse({ vaultId: "v", since: -2 }).success).toBe(false);
  });

  it("PostCursorInput: lastVersion non-negative", () => {
    expect(
      PostCursorInputSchema.safeParse({ vaultId: "v", lastVersion: 12, deviceId: "d" })
        .success,
    ).toBe(true);
    expect(
      PostCursorInputSchema.safeParse({ vaultId: "v", lastVersion: -1, deviceId: "d" })
        .success,
    ).toBe(false);
  });
});
