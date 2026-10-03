// Tiny fetch wrapper for the Phase 3 Go API (contract: .hermes/plans/phase3-contract.md).
//
// No TanStack Query (deliberately — plain fetch + React state in the components,
// structured so a query library can replace the call sites later). Every call
// throws ApiError with the server's {"error"} message on non-2xx.
//
// Auth: the session token lives in the auth agent's in-memory store
// (apps/web/lib/session.ts — owned elsewhere, NOT imported here to avoid a
// race). Instead, the vault context registers a token provider via
// setAuthTokenProvider(); every request reads it lazily.

import type { Item, ItemVersionInfo, VaultKind, VaultMeta } from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:18080";

type TokenProvider = () => string | null;

let tokenProvider: TokenProvider = () => null;

/** Register the session-token source (called by VaultProvider). */
export function setAuthTokenProvider(provider: TokenProvider): void {
  tokenProvider = provider;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = tokenProvider();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...init,
    headers,
  });
  if (!res.ok) {
    let message = `Request failed with status ${res.status}`;
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body.error === "string") message = body.error;
    } catch {
      // non-JSON error body; keep the status message
    }
    throw new ApiError(message, res.status);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------- vaults

export interface CreateVaultInput {
  kind: VaultKind;
  /** base64 ciphertext of the encrypted vault meta JSON. */
  encryptedMeta: string;
  /** base64 24-byte nonce. */
  nonce: string;
  /**
   * base64 sealed-box (crypto_box_seal) of the vault key under the creator's
   * master X25519 public key. The server stores it in vault_keys so the
   * creator can unwrap their own vault key later. REQUIRED by the API.
   */
  wrappedVaultKey: string;
}

export function listVaults(): Promise<{ vaults: VaultMeta[] }> {
  return request<{ vaults: VaultMeta[] }>("/v1/vaults");
}

export function createVault(
  input: CreateVaultInput,
): Promise<{ vault: VaultMeta }> {
  return request<{ vault: VaultMeta }>("/v1/vaults", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

// ----------------------------------------------------------------- items

export interface ListItemsParams {
  vaultId: string;
  /** Return only items with version > since (includes tombstones). */
  since?: number;
  /** base64 32-byte HMAC for exact-match server-side title search. */
  searchHmac?: string;
}

export interface ItemWriteInput {
  vaultId: string;
  itemType: number;
  /** base64 ciphertext. */
  ciphertext: string;
  /** base64 nonce. */
  nonce: string;
  /** base64 search HMAC or null. */
  searchHmac?: string | null;
  favorite?: boolean;
}

export function listItems(
  params: ListItemsParams,
): Promise<{ items: Item[]; serverVersion: number }> {
  const qs = new URLSearchParams({ vaultId: params.vaultId });
  if (params.since !== undefined) qs.set("since", String(params.since));
  if (params.searchHmac) qs.set("searchHmac", params.searchHmac);
  return request<{ items: Item[]; serverVersion: number }>(
    `/v1/items?${qs.toString()}`,
  );
}

export function createItem(input: ItemWriteInput): Promise<{ item: Item }> {
  return request<{ item: Item }>("/v1/items", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateItem(
  id: string,
  input: Partial<ItemWriteInput>,
): Promise<{ item: Item }> {
  return request<{ item: Item }>(`/v1/items/${id}`, {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

/** Soft delete (trash); bumps version, returns the tombstoned item. */
export function deleteItem(id: string): Promise<{ item: Item }> {
  return request<{ item: Item }>(`/v1/items/${id}`, { method: "DELETE" });
}

export function itemVersions(
  id: string,
): Promise<{ versions: ItemVersionInfo[] }> {
  return request<{ versions: ItemVersionInfo[] }>(
    `/v1/items/${id}/versions`,
  );
}

// ------------------------------------------------------------------ sync

export function syncChanges(params: {
  vaultId: string;
  since: number;
}): Promise<{ changes: Item[]; latestVersion: number; hasMore: boolean }> {
  const qs = new URLSearchParams({
    vaultId: params.vaultId,
    since: String(params.since),
  });
  return request<{
    changes: Item[];
    latestVersion: number;
    hasMore: boolean;
  }>(`/v1/sync/changes?${qs.toString()}`);
}

export function postCursor(input: {
  vaultId: string;
  lastVersion: number;
  deviceId: string;
}): Promise<{ ok: true }> {
  return request<{ ok: true }>("/v1/sync/cursor", {
    method: "POST",
    body: JSON.stringify(input),
  });
}
