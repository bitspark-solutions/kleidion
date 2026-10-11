import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient } from "../src/api.js";

const b64 = (n: number, fill = 7) =>
  Buffer.from(new Uint8Array(n).fill(fill)).toString("base64");

const NONCE24 = b64(24);
const HMAC32 = b64(32);
const CIPHERTEXT = b64(64, 9);

const item = {
  id: "item-1",
  vaultId: "vault-1",
  itemType: 1,
  ciphertext: CIPHERTEXT,
  nonce: NONCE24,
  searchHmac: HMAC32,
  version: 1,
  favorite: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  deletedAt: null,
};

const vault = {
  id: "vault-1",
  kind: "personal",
  encryptedMeta: CIPHERTEXT,
  nonce: NONCE24,
  role: "admin",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: unknown;
}

function mockFetch(handler: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fn = vi.fn(async (input: unknown, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: (init?.method ?? "GET").toUpperCase(),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body !== undefined ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    return handler(call);
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function client(fetchImpl: typeof fetch, token = "tok-123") {
  return createApiClient({
    baseUrl: "http://api.test",
    getToken: () => token,
    fetchImpl,
  });
}

describe("createApiClient — success paths", () => {
  it("listVaults parses {vaults:[...]}", async () => {
    const { fn, calls } = mockFetch(() => json(200, { vaults: [vault] }));
    const res = await client(fn).listVaults();
    expect(res.vaults).toHaveLength(1);
    expect(res.vaults[0]!.id).toBe("vault-1");
    expect(calls[0]!.url).toBe("http://api.test/v1/vaults");
    expect(calls[0]!.method).toBe("GET");
  });

  it("attaches Authorization: Bearer <token>", async () => {
    const { fn, calls } = mockFetch(() => json(200, { vaults: [] }));
    await client(fn, "secret-token").listVaults();
    expect(calls[0]!.headers.Authorization).toBe("Bearer secret-token");
  });

  it("createVault POSTs the body and parses {vault}", async () => {
    const { fn, calls } = mockFetch(() => json(201, { vault }));
    const input = { kind: "personal" as const, encryptedMeta: CIPHERTEXT, nonce: NONCE24 };
    const res = await client(fn).createVault(input);
    expect(res.vault.id).toBe("vault-1");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.body).toEqual(input);
    expect(calls[0]!.headers["Content-Type"]).toBe("application/json");
  });

  it("createItem / updateItem / deleteItem / itemVersions / syncChanges / postCursor", async () => {
    const { fn, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v1/sync/cursor")) return json(200, { ok: true });
      if (call.url.includes("/versions"))
        return json(200, { versions: [{ version: 1, createdAt: "2026-01-01T00:00:00Z" }] });
      if (call.url.includes("/v1/sync/changes"))
        return json(200, { changes: [item], latestVersion: 5, hasMore: false });
      return json(200, { item });
    });
    const c = client(fn);

    const created = await c.createItem({
      vaultId: "vault-1",
      itemType: 1,
      ciphertext: CIPHERTEXT,
      nonce: NONCE24,
    });
    expect(created.item.version).toBe(1);

    const updated = await c.updateItem("item-1", { favorite: true });
    expect(updated.item.id).toBe("item-1");

    const deleted = await c.deleteItem("item-1");
    expect(deleted.item.id).toBe("item-1");

    const versions = await c.itemVersions("item-1");
    expect(versions.versions[0]!.version).toBe(1);

    const sync = await c.syncChanges({ vaultId: "vault-1", since: 0 });
    expect(sync.latestVersion).toBe(5);
    expect(sync.hasMore).toBe(false);
    expect(sync.changes[0]!.id).toBe("item-1");

    const cursor = await c.postCursor({ vaultId: "vault-1", lastVersion: 5, deviceId: "dev-1" });
    expect(cursor.ok).toBe(true);

    const methods = calls.map((x) => `${x.method} ${new URL(x.url).pathname}`);
    expect(methods).toEqual([
      "POST /v1/items",
      "PUT /v1/items/item-1",
      "DELETE /v1/items/item-1",
      "GET /v1/items/item-1/versions",
      "GET /v1/sync/changes",
      "POST /v1/sync/cursor",
    ]);
  });
});

describe("createApiClient — query string building", () => {
  it("includes defined params, skips undefined", async () => {
    const { fn, calls } = mockFetch(() => json(200, { items: [], serverVersion: 0 }));
    await client(fn).listItems({ vaultId: "vault-1", since: 7, searchHmac: undefined });
    const url = new URL(calls[0]!.url);
    expect(url.pathname).toBe("/v1/items");
    expect(url.searchParams.get("vaultId")).toBe("vault-1");
    expect(url.searchParams.get("since")).toBe("7");
    expect(url.searchParams.has("searchHmac")).toBe(false);
  });

  it("passes searchHmac through when defined", async () => {
    const { fn, calls } = mockFetch(() => json(200, { items: [], serverVersion: 0 }));
    await client(fn).listItems({ vaultId: "v", searchHmac: HMAC32 });
    expect(new URL(calls[0]!.url).searchParams.get("searchHmac")).toBe(HMAC32);
  });

  it("syncChanges requires since", async () => {
    const { fn, calls } = mockFetch(() =>
      json(200, { changes: [], latestVersion: 0, hasMore: false }),
    );
    await client(fn).syncChanges({ vaultId: "v", since: 42 });
    const url = new URL(calls[0]!.url);
    expect(url.searchParams.get("vaultId")).toBe("v");
    expect(url.searchParams.get("since")).toBe("42");
  });
});

describe("createApiClient — error handling", () => {
  it("400 surfaces the server's {error} message with status", async () => {
    const { fn } = mockFetch(() => json(400, { error: "itemType must be 1..4" }));
    const err = await client(fn)
      .createItem({ vaultId: "v", itemType: 9 as 1, ciphertext: CIPHERTEXT, nonce: NONCE24 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(400);
    expect((err as ApiError).message).toBe("itemType must be 1..4");
  });

  it("401 surfaces server message", async () => {
    const { fn } = mockFetch(() => json(401, { error: "unauthorized" }));
    const err = await client(fn).listVaults().catch((e: unknown) => e);
    expect((err as ApiError).status).toBe(401);
    expect((err as ApiError).message).toBe("unauthorized");
  });

  it("non-JSON error body falls back to HTTP <status>: <text>", async () => {
    const { fn } = mockFetch(() => new Response("gateway boom", { status: 502 }));
    const err = await client(fn).listVaults().catch((e: unknown) => e);
    expect((err as ApiError).status).toBe(502);
    expect((err as ApiError).message).toContain("gateway boom");
  });

  it("response validation failure is a clear ApiError with status 0", async () => {
    const { fn } = mockFetch(() =>
      json(200, { items: [{ ...item, itemType: 99 }], serverVersion: 1 }),
    );
    const err = await client(fn)
      .listItems({ vaultId: "v" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(0);
    expect((err as ApiError).message).toContain("response validation failed");
    expect((err as ApiError).message).toContain("itemType");
  });

  it("missing required response field fails validation", async () => {
    const { fn } = mockFetch(() => json(200, { vaults: "not-an-array" }));
    const err = await client(fn).listVaults().catch((e: unknown) => e);
    expect((err as ApiError).status).toBe(0);
    expect((err as ApiError).message).toContain("response validation failed");
  });
});

const member = {
  userId: "user-2",
  email: "b@example.com",
  role: "write",
  createdAt: "2026-01-01T00:00:00Z",
};

const shareLink = {
  id: "link-1",
  itemId: "item-1",
  recipientEmail: null,
  viewOnly: true,
  expiresAt: "2026-02-01T00:00:00Z",
  maxViews: null,
  views: 0,
  revokedAt: null,
  createdAt: "2026-01-01T00:00:00Z",
};

describe("createApiClient — Phase 4 members / share links / wrapped key", () => {
  it("setWrappedKey PUTs to the per-vault wrapped-key route", async () => {
    const { fn, calls } = mockFetch(() => json(200, { ok: true }));
    const res = await client(fn).setWrappedKey("vault-1", { wrappedVaultKey: CIPHERTEXT });
    expect(res.ok).toBe(true);
    expect(calls[0]!.method).toBe("PUT");
    expect(calls[0]!.url).toBe("http://api.test/v1/vaults/vault-1/wrapped-key");
    expect(calls[0]!.body).toEqual({ wrappedVaultKey: CIPHERTEXT });
  });

  it("listMembers / addMember / patchMemberRole / removeMember", async () => {
    const { fn, calls } = mockFetch((call) => {
      if (call.method === "POST") return json(201, { member });
      if (call.method === "PATCH" || call.method === "DELETE") return json(200, { ok: true });
      return json(200, { members: [member] });
    });
    const c = client(fn);
    expect((await c.listMembers("vault-1")).members[0]!.userId).toBe("user-2");
    expect((await c.addMember("vault-1", { email: "b@example.com", role: "write", wrappedVaultKey: CIPHERTEXT })).member.role).toBe("write");
    expect((await c.patchMemberRole("vault-1", "user-2", "read")).ok).toBe(true);
    expect((await c.removeMember("vault-1", "user-2")).ok).toBe(true);
    expect(calls.map((x) => x.method)).toEqual(["GET", "POST", "PATCH", "DELETE"]);
  });

  it("lookupUser GETs the email directory", async () => {
    const { fn, calls } = mockFetch(() =>
      json(200, { userId: "user-2", email: "b@example.com", masterPublicKey: "aabbcc" }),
    );
    const res = await client(fn).lookupUser("b@example.com");
    expect(res.masterPublicKey).toBe("aabbcc");
    expect(new URL(calls[0]!.url).searchParams.get("email")).toBe("b@example.com");
  });

  it("lookupUser rejects a non-hex masterPublicKey", async () => {
    const { fn } = mockFetch(() =>
      json(200, { userId: "u", email: "b@example.com", masterPublicKey: "zzz!" }),
    );
    const err = await client(fn).lookupUser("b@example.com").catch((e: unknown) => e);
    expect((err as ApiError).status).toBe(0);
  });

  it("createShareLink returns the once-only token", async () => {
    const { fn } = mockFetch(() => json(201, { shareLink, token: "tok-abc" }));
    const res = await client(fn).createShareLink({
      itemId: "item-1",
      wrappedItem: CIPHERTEXT,
      wrappedNonce: NONCE24,
      viewOnly: true,
      expiresAt: "2026-02-01T00:00:00Z",
    });
    expect(res.token).toBe("tok-abc");
    expect(res.shareLink.id).toBe("link-1");
  });

  it("listShareLinks / revokeShareLink / redeemShareLink", async () => {
    const { fn, calls } = mockFetch((call) => {
      if (call.url.endsWith("/v1/share-links")) return json(200, { shareLinks: [shareLink] });
      if (call.method === "DELETE") return json(200, { ok: true });
      return json(200, { wrappedItem: CIPHERTEXT, wrappedNonce: NONCE24, viewOnly: true });
    });
    const c = client(fn);
    expect((await c.listShareLinks()).shareLinks[0]!.id).toBe("link-1");
    expect((await c.revokeShareLink("link-1")).ok).toBe(true);
    const redeemed = await c.redeemShareLink("tok-abc");
    expect(redeemed.viewOnly).toBe(true);
    expect(calls[2]!.url).toBe("http://api.test/v1/public/share-links/tok-abc");
    expect(calls[2]!.method).toBe("POST");
  });
});
