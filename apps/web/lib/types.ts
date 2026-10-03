// Wire types for the Phase 3 vault/item/sync API.
//
// DELIBERATELY DUPLICATED from `.hermes/plans/phase3-contract.md` (§JSON shapes)
// instead of imported from `@kleidion/core`: that package is being built
// concurrently by another agent, and importing it here would create a race.
// Once core lands, these definitions must match its zod-inferred types exactly
// (or be swapped for re-exports). Do not invent fields beyond the contract.

export type VaultKind = "personal" | "shared";
export type VaultRole = "admin" | "write" | "read";

/** A vault as returned by GET/POST /v1/vaults. Binary fields are base64. */
export interface VaultMeta {
  id: string;
  kind: VaultKind;
  /** base64 ciphertext of the client-encrypted vault meta JSON ({name,...}). */
  encryptedMeta: string;
  /** base64 24-byte nonce. */
  nonce: string;
  role: VaultRole;
  createdAt: string;
  updatedAt: string;
}

/** An item row as returned by the items/sync endpoints. Binary fields are base64. */
export interface Item {
  id: string;
  vaultId: string;
  /** 1=Login 2=SecureNote 3=Card 4=Identity */
  itemType: number;
  /** base64 ciphertext (XChaCha20-Poly1305, includes tag). */
  ciphertext: string;
  /** base64 24-byte nonce. */
  nonce: string;
  /** base64 32-byte HMAC, or null. Enables server-side exact-title match. */
  searchHmac: string | null;
  /** Monotonic per vault; drives delta sync. */
  version: number;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  /** Soft-delete tombstone (trash); null when live. */
  deletedAt: string | null;
}

export type ItemFieldType = "text" | "password" | "url" | "totp";

export interface ItemField {
  label: string;
  value: string;
  type: ItemFieldType;
}

/** Item plaintext JSON — client-side only, the server never sees this. */
export interface ItemPlain {
  title: string;
  notes?: string;
  tags?: string[];
  fields?: ItemField[];
}

/** itemType mapping from the contract. */
export const ITEM_TYPES = {
  Login: 1,
  SecureNote: 2,
  Card: 3,
  Identity: 4,
} as const;

export const ITEM_TYPE_LABELS: Record<number, string> = {
  1: "Login",
  2: "Secure Note",
  3: "Card",
  4: "Identity",
};

/** Entry returned by GET /v1/items/:id/versions. */
export interface ItemVersionInfo {
  version: number;
  createdAt: string;
}
