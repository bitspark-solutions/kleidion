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
});
export type SyncChangesResponse = z.infer<typeof SyncChangesResponseSchema>;

export const PostCursorResponseSchema = z.object({ ok: z.literal(true) });
export type PostCursorResponse = z.infer<typeof PostCursorResponseSchema>;
