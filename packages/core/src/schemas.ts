/**
 * Phase 3 contract schemas (zod v4) — camelCase wire format.
 * Authoritative source: .hermes/plans/phase3-contract.md
 *
 * Binary fields are base64 strings on the wire. The server stores bytea and
 * NEVER sees plaintext; ItemPlain is client-side only.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

const BASE64_RE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** True when `s` is a non-empty, canonically-padded base64 string. */
export function isBase64(s: string): boolean {
  return s.length > 0 && s.length % 4 === 0 && BASE64_RE.test(s);
}

/** Decoded byte length of a base64 string, or null if not valid base64. */
export function base64ByteLength(s: string): number | null {
  if (!isBase64(s)) return null;
  let padding = 0;
  if (s.endsWith("==")) padding = 2;
  else if (s.endsWith("=")) padding = 1;
  return (s.length / 4) * 3 - padding;
}

/** Non-empty base64 string (no length constraint). */
export const base64Schema = z
  .string()
  .refine(isBase64, { message: "must be a non-empty base64 string" });

/** Base64 string decoding to exactly `n` bytes. */
export function base64BytesSchema(n: number): z.ZodType<string> {
  return base64Schema.refine((s) => base64ByteLength(s) === n, {
    message: `must be base64 decoding to exactly ${n} bytes`,
  });
}

/** Max ciphertext size enforced by the server: 1 MiB. */
export const MAX_CIPHERTEXT_BYTES = 1024 * 1024;

/** Base64 string decoding to at most `max` bytes. */
export function base64MaxBytesSchema(max: number): z.ZodType<string> {
  return base64Schema.refine(
    (s) => (base64ByteLength(s) ?? Infinity) <= max,
    { message: `must be base64 decoding to at most ${max} bytes` },
  );
}

/** itemType: 1=Login, 2=SecureNote, 3=Card, 4=Identity. */
export const ItemTypeSchema = z.union([
  z.literal(1),
  z.literal(2),
  z.literal(3),
  z.literal(4),
]);

/** vault_keys.role */
export const RoleSchema = z.union([
  z.literal("admin"),
  z.literal("write"),
  z.literal("read"),
]);

/** vaults.kind */
export const VaultKindSchema = z.union([
  z.literal("personal"),
  z.literal("shared"),
]);

/** Non-negative integer (versions are monotonic per vault, starting at 1; 0 means "no data yet"). */
export const VersionSchema = z.number().int().nonnegative();

// ---------------------------------------------------------------------------
// Wire DTOs
// ---------------------------------------------------------------------------

export const VaultMetaSchema = z.object({
  id: z.string(),
  kind: VaultKindSchema,
  encryptedMeta: base64Schema,
  nonce: base64Schema,
  role: RoleSchema,
  /** Caller's sealed vault key (GET /v1/vaults only; Phase 4 ADR-006). */
  wrappedVaultKey: base64Schema.optional(),
  /**
   * Rotation counter (ADR-008). A client holding a key from an older epoch must
   * re-unwrap: every row on the server was rewritten under a new key. Optional
   * so a pre-000006 server still validates.
   */
  keyEpoch: z.number().int().positive().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type VaultMeta = z.infer<typeof VaultMetaSchema>;

export const ItemSchema = z.object({
  id: z.string(),
  vaultId: z.string(),
  itemType: ItemTypeSchema,
  ciphertext: base64MaxBytesSchema(MAX_CIPHERTEXT_BYTES),
  nonce: base64BytesSchema(24),
  searchHmac: base64BytesSchema(32).nullable(),
  version: VersionSchema,
  favorite: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
  deletedAt: z.string().nullable(),
});
export type Item = z.infer<typeof ItemSchema>;

// ---------------------------------------------------------------------------
// Client-side-only plaintext shape (server never sees this)
// ---------------------------------------------------------------------------

export const ItemFieldTypeSchema = z.union([
  z.literal("text"),
  z.literal("password"),
  z.literal("url"),
  z.literal("totp"),
]);
export type ItemFieldType = z.infer<typeof ItemFieldTypeSchema>;

export const ItemFieldSchema = z.object({
  label: z.string(),
  value: z.string(),
  type: ItemFieldTypeSchema,
});
export type ItemField = z.infer<typeof ItemFieldSchema>;

export const ItemPlainSchema = z.object({
  title: z.string(),
  notes: z.string().optional(),
  tags: z.array(z.string()).optional(),
  fields: z.array(ItemFieldSchema).optional(),
});
export type ItemPlain = z.infer<typeof ItemPlainSchema>;

// ---------------------------------------------------------------------------
// Request inputs
// ---------------------------------------------------------------------------

/** POST /v1/vaults body. `kind` omitted -> server default "personal". */
export const CreateVaultInputSchema = z.object({
  kind: VaultKindSchema.optional(),
  encryptedMeta: base64Schema,
  nonce: base64Schema,
  /** base64 sealed-box of the new vault key under the creator's pubkey. */
  wrappedVaultKey: base64Schema.optional(),
});
export type CreateVaultInput = z.infer<typeof CreateVaultInputSchema>;

/** POST /v1/items body. */
export const CreateItemInputSchema = z.object({
  vaultId: z.string(),
  itemType: ItemTypeSchema,
  ciphertext: base64MaxBytesSchema(MAX_CIPHERTEXT_BYTES),
  nonce: base64BytesSchema(24),
  searchHmac: base64BytesSchema(32).nullish(),
  favorite: z.boolean().optional(),
});
export type CreateItemInput = z.infer<typeof CreateItemInputSchema>;

/** PUT /v1/items/:id body. */
export const UpdateItemInputSchema = z.object({
  itemType: ItemTypeSchema.optional(),
  ciphertext: base64MaxBytesSchema(MAX_CIPHERTEXT_BYTES).optional(),
  nonce: base64BytesSchema(24).optional(),
  searchHmac: base64BytesSchema(32).nullish(),
  favorite: z.boolean().optional(),
});
export type UpdateItemInput = z.infer<typeof UpdateItemInputSchema>;

/** GET /v1/items query params. */
export const ListItemsParamsSchema = z.object({
  vaultId: z.string(),
  since: VersionSchema.optional(),
  searchHmac: base64BytesSchema(32).optional(),
});
export type ListItemsParams = z.infer<typeof ListItemsParamsSchema>;

/** GET /v1/sync/changes query params. */
export const SyncChangesParamsSchema = z.object({
  vaultId: z.string(),
  since: VersionSchema,
});
export type SyncChangesParams = z.infer<typeof SyncChangesParamsSchema>;

/** POST /v1/sync/cursor body. */
export const PostCursorInputSchema = z.object({
  vaultId: z.string(),
  lastVersion: VersionSchema,
  deviceId: z.string(),
});
export type PostCursorInput = z.infer<typeof PostCursorInputSchema>;

// ---------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------

export const ListVaultsResponseSchema = z.object({
  vaults: z.array(VaultMetaSchema),
});
export type ListVaultsResponse = z.infer<typeof ListVaultsResponseSchema>;

export const CreateVaultResponseSchema = z.object({
  vault: VaultMetaSchema,
});
export type CreateVaultResponse = z.infer<typeof CreateVaultResponseSchema>;

export const ListItemsResponseSchema = z.object({
  items: z.array(ItemSchema),
  serverVersion: VersionSchema,
  /** Vault rotation counter; see VaultMetaSchema.keyEpoch (ADR-008). */
  keyEpoch: z.number().int().positive().optional(),
});
export type ListItemsResponse = z.infer<typeof ListItemsResponseSchema>;

export const ItemResponseSchema = z.object({ item: ItemSchema });
export type ItemResponse = z.infer<typeof ItemResponseSchema>;

export const ItemVersionSummarySchema = z.object({
  version: VersionSchema,
  createdAt: z.string(),
});
export type ItemVersionSummary = z.infer<typeof ItemVersionSummarySchema>;

export const ItemVersionsResponseSchema = z.object({
  versions: z.array(ItemVersionSummarySchema),
});
export type ItemVersionsResponse = z.infer<typeof ItemVersionsResponseSchema>;

export const SyncChangesResponseSchema = z.object({
  changes: z.array(ItemSchema),
  latestVersion: VersionSchema,
  hasMore: z.boolean(),
  /** Vault rotation counter; a change means the cached vault key is stale. */
  keyEpoch: z.number().int().positive().optional(),
});
export type SyncChangesResponse = z.infer<typeof SyncChangesResponseSchema>;

export const PostCursorResponseSchema = z.object({ ok: z.literal(true) });
export type PostCursorResponse = z.infer<typeof PostCursorResponseSchema>;

// ---------------------------------------------------------------------------
// Phase 4 — per-vault keys, SRP finish, members, share links
// Authoritative spec: .hermes/plans/phase4-contract.md
// ---------------------------------------------------------------------------

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Lower/upper hex string (X25519 keys are hex on the auth/lookup wire). */
export const hexSchema = z
  .string()
  .regex(HEX_RE, "must be a hex string");

/** Generic {"ok":true} ack used by several Phase 4 write routes. */
export const OkResponseSchema = z.object({ ok: z.literal(true) });
export type OkResponse = z.infer<typeof OkResponseSchema>;

/**
 * PUT /v1/vaults/:id/wrapped-key body — re-seal the CALLER's vault key
 * (Phase 3 -> Phase 4 ADR-006 migration).
 */
export const SetWrappedKeyInputSchema = z.object({
  wrappedVaultKey: base64Schema,
});
export type SetWrappedKeyInput = z.infer<typeof SetWrappedKeyInputSchema>;

/** SRP finish key bundle (hex keys + base64 AUK-wrapped blobs). */
export const KeyBundleWireSchema = z.object({
  masterPublicKey: hexSchema,
  encryptedPrivateKey: base64Schema,
  encryptedSymKey: base64Schema,
});
export type KeyBundleWire = z.infer<typeof KeyBundleWireSchema>;

/**
 * POST /v1/auth/srp/finish response. `deviceId` closes the ADR-006 sync-cursor
 * gap (Phase 4 Step A) — the client must persist and echo it on cursor posts.
 */
export const SrpFinishResponseSchema = z.object({
  sessionToken: z.string(),
  serverProof: z.string(),
  userId: z.string(),
  email: z.string(),
  deviceId: z.string(),
  keyBundle: KeyBundleWireSchema.nullable(),
});
export type SrpFinishResponse = z.infer<typeof SrpFinishResponseSchema>;

/** A vault member (GET/POST /v1/vaults/:id/members). */
export const VaultMemberSchema = z.object({
  userId: z.string(),
  email: z.string(),
  role: RoleSchema,
  createdAt: z.string(),
});
export type VaultMember = z.infer<typeof VaultMemberSchema>;

/** GET /v1/users/lookup?email= — minimal public directory entry. */
export const UserLookupSchema = z.object({
  userId: z.string(),
  email: z.string(),
  /** hex X25519 public key — seal the vault key with this, client-side. */
  masterPublicKey: hexSchema,
});
export type UserLookup = z.infer<typeof UserLookupSchema>;

/** POST /v1/vaults/:id/members body. */
export const AddMemberInputSchema = z.object({
  email: z.string().min(1),
  role: RoleSchema,
  /** sealed-box (crypto_box_seal) of the vault key under the member pubkey. */
  wrappedVaultKey: base64Schema,
});
export type AddMemberInput = z.infer<typeof AddMemberInputSchema>;

/** PATCH /v1/vaults/:id/members/:userId body. */
export const PatchMemberInputSchema = z.object({ role: RoleSchema });
export type PatchMemberInput = z.infer<typeof PatchMemberInputSchema>;

export const ListMembersResponseSchema = z.object({
  members: z.array(VaultMemberSchema),
});
export type ListMembersResponse = z.infer<typeof ListMembersResponseSchema>;

export const MemberResponseSchema = z.object({ member: VaultMemberSchema });
export type MemberResponse = z.infer<typeof MemberResponseSchema>;

/** ShareLink row as returned to its creator (never carries the token). */
export const ShareLinkInfoSchema = z.object({
  id: z.string(),
  itemId: z.string(),
  recipientEmail: z.string().nullable(),
  viewOnly: z.boolean(),
  expiresAt: z.string(),
  maxViews: z.number().int().nonnegative().nullable(),
  views: z.number().int().nonnegative(),
  revokedAt: z.string().nullable(),
  createdAt: z.string(),
});
export type ShareLinkInfo = z.infer<typeof ShareLinkInfoSchema>;

/** POST /v1/share-links body. */
export const CreateShareLinkInputSchema = z.object({
  itemId: z.string(),
  /** item JSON re-encrypted with the ephemeral linkKey (base64). */
  wrappedItem: base64Schema,
  wrappedNonce: base64Schema,
  recipientEmail: z.string().optional(),
  viewOnly: z.boolean(),
  expiresAt: z.string(),
  maxViews: z.number().int().nonnegative().optional(),
});
export type CreateShareLinkInput = z.infer<typeof CreateShareLinkInputSchema>;

/** Create response: the row + the once-only token. */
export const CreateShareLinkResponseSchema = z.object({
  shareLink: ShareLinkInfoSchema,
  token: z.string(),
});
export type CreateShareLinkResponse = z.infer<
  typeof CreateShareLinkResponseSchema
>;

export const ListShareLinksResponseSchema = z.object({
  shareLinks: z.array(ShareLinkInfoSchema),
});
export type ListShareLinksResponse = z.infer<
  typeof ListShareLinksResponseSchema
>;

/** POST /v1/public/share-links/:token (UNAUTHED) -> ciphertext, spends a view. */
export const RedeemShareLinkResponseSchema = z.object({
  wrappedItem: base64Schema,
  wrappedNonce: base64Schema,
  viewOnly: z.boolean(),
});
export type RedeemShareLinkResponse = z.infer<
  typeof RedeemShareLinkResponseSchema
>;
