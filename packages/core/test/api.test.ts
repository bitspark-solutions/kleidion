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
