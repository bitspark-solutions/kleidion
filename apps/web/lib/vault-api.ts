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

/**
 * PUT /v1/vaults/:id/wrapped-key — replace the CALLER's sealed vault key row.
 * Used by the Phase 4 migration (re-wrap a Phase 3 symKey under the keypair).
 */
export function setWrappedKey(
  vaultId: string,
  wrappedVaultKey: string,
): Promise<{ ok: true }> {
  return request<{ ok: true }>(`/v1/vaults/${vaultId}/wrapped-key`, {
    method: "PUT",
    body: JSON.stringify({ wrappedVaultKey }),
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

// ---------------------------------------------------------- shared vaults

export interface VaultMemberInfo {
  userId: string;
  email: string;
  role: "admin" | "write" | "read";
  createdAt: string;
}

export interface UserLookup {
  userId: string;
  email: string;
  /** hex X25519 public key — seal the vault key with this. */
  masterPublicKey: string;
}

export function listMembers(vaultId: string): Promise<{ members: VaultMemberInfo[] }> {
  return request<{ members: VaultMemberInfo[] }>(`/v1/vaults/${vaultId}/members`);
}

export function lookupUser(email: string): Promise<UserLookup> {
  return request<UserLookup>(`/v1/users/lookup?email=${encodeURIComponent(email)}`);
}

export function addMember(
  vaultId: string,
  input: { email: string; role: VaultMemberInfo["role"]; wrappedVaultKey: string },
): Promise<{ member: VaultMemberInfo }> {
  return request<{ member: VaultMemberInfo }>(`/v1/vaults/${vaultId}/members`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function patchMemberRole(
  vaultId: string,
  userId: string,
  role: VaultMemberInfo["role"],
): Promise<{ ok: true }> {
  return request<{ ok: true }>(`/v1/vaults/${vaultId}/members/${userId}`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

export function removeMember(vaultId: string, userId: string): Promise<{ ok: true }> {
  return request<{ ok: true }>(`/v1/vaults/${vaultId}/members/${userId}`, {
    method: "DELETE",
  });
}

// ------------------------------------------------------------- share links

/** ShareLink row as returned by the API (never contains the token). */
export interface ShareLinkInfo {
  id: string;
  itemId: string;
  recipientEmail: string | null;
  viewOnly: boolean;
  expiresAt: string;
  maxViews: number | null;
  views: number;
  revokedAt: string | null;
  createdAt: string;
}

export function createShareLink(input: {
  itemId: string;
  wrappedItem: string;
  wrappedNonce: string;
  recipientEmail?: string;
  viewOnly: boolean;
  expiresAt: string;
  maxViews?: number;
}): Promise<{ shareLink: ShareLinkInfo; token: string }> {
  return request<{ shareLink: ShareLinkInfo; token: string }>("/v1/share-links", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function listShareLinks(): Promise<{ shareLinks: ShareLinkInfo[] }> {
  return request<{ shareLinks: ShareLinkInfo[] }>("/v1/share-links");
}

export function revokeShareLink(id: string): Promise<{ ok: true }> {
  return request<{ ok: true }>(`/v1/share-links/${id}`, { method: "DELETE" });
}

/**
 * Unauthenticated visitor redeem. Uses plain fetch (no bearer token); the
 * request itself spends one view. Throws on 404 (gone/expired/exhausted).
 */
export function redeemShareLink(
  token: string,
): Promise<{ wrappedItem: string; wrappedNonce: string; viewOnly: boolean }> {
  return request<{ wrappedItem: string; wrappedNonce: string; viewOnly: boolean }>(
    `/v1/public/share-links/${token}`,
    { method: "POST" },
  );
}
