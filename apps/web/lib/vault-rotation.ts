"use client";

// Vault-key rotation (ADR-008) — the client half of revoking a shared-vault
// member. The server can store only ciphertext, so it cannot rotate a key by
// itself: an admin's device must re-encrypt every row under a fresh key.
//
// Rotation is all-or-nothing by design. A vault where some rows are under the
// old key and some under the new one is still readable by the revoked member,
// so this refuses to proceed unless EVERY row's plaintext is available locally.

import {
  decryptItem,
  encryptItem,
  fromBase64,
  fromHex,
  generateVaultKey,
  ready,
  searchHmac,
  toBase64,
  wrapVaultKey,
} from "@kleidion/crypto";
import { rotateVaultKey, type RotateItemInput, type RotateMemberInput } from "./vault-api";
import type { Item, ItemPlain } from "./types";

export interface RotationRequest {
  vaultId: string;
  /** The key about to be retired; every row is currently encrypted under it. */
  currentKey: Uint8Array;
  /** Every item row of the vault, tombstones included. */
  items: Item[];
  /** Decrypted plaintext per item id; null means "could not decrypt". */
  plains: Record<string, ItemPlain | null>;
  /** Current base64 vault meta ciphertext + nonce, re-encrypted under the new key. */
  encryptedMeta: string;
  metaNonce: string;
  /** Surviving roster: id + hex X25519 public key from GET /v1/vaults/:id/members. */
  remainingMembers: { userId: string; masterPublicKey: string }[];
  /** Member being revoked, if this rotation is a removal. */
  revokedUserId?: string;
}

export class RotationBlockedError extends Error {
  readonly unreadableItemIds: string[];
  constructor(message: string, unreadableItemIds: string[] = []) {
    super(message);
    this.name = "RotationBlockedError";
    this.unreadableItemIds = unreadableItemIds;
  }
}

/**
 * Re-encrypts the whole vault under a new key and posts it. Resolves with the
 * vault's new key epoch.
 */
export async function rotateVault(req: RotationRequest): Promise<number> {
  await ready();

  const unreadable = req.items.filter((it) => !req.plains[it.id]);
  if (unreadable.length > 0) {
    throw new RotationBlockedError(
      `Cannot rotate: ${unreadable.length} item(s) in this vault failed to decrypt. ` +
        "Rotating now would leave those rows readable with the key being retired.",
      unreadable.map((it) => it.id),
    );
  }
  if (req.remainingMembers.length === 0) {
    throw new RotationBlockedError("Cannot rotate: no remaining member has a public key to seal the new vault key for.");
  }

  // Recover the vault's own metadata (name etc.) under the retiring key.
  let metaJson: string;
  try {
    metaJson = await decryptItem(req.currentKey, {
      ciphertext: fromBase64(req.encryptedMeta),
      nonce: fromBase64(req.metaNonce),
    });
  } catch {
    throw new RotationBlockedError(
      "Cannot rotate: this vault's name could not be decrypted, so the vault key may already be stale. " +
        "Lock and unlock, then try again.",
    );
  }

  const newKey = await generateVaultKey();
  try {
    const encMeta = await encryptItem(newKey, metaJson);

    const items: RotateItemInput[] = [];
    for (const it of req.items) {
      const plain = req.plains[it.id] as ItemPlain;
      const enc = await encryptItem(newKey, JSON.stringify(plain));
      const hmac = await searchHmac(newKey, plain.title);
      items.push({
        id: it.id,
        itemType: it.itemType,
        ciphertext: toBase64(enc.ciphertext),
        nonce: toBase64(enc.nonce),
        searchHmac: toBase64(hmac),
        favorite: it.favorite,
      });
    }

    const members: RotateMemberInput[] = [];
    for (const m of req.remainingMembers) {
      const wrapped = await wrapVaultKey(newKey, fromHex(m.masterPublicKey));
      members.push({ userId: m.userId, wrappedVaultKey: toBase64(wrapped) });
    }

    const res = await rotateVaultKey(req.vaultId, {
      revokedUserId: req.revokedUserId,
      encryptedMeta: toBase64(encMeta.ciphertext),
      nonce: toBase64(encMeta.nonce),
      members,
      items,
    });
    return res.keyEpoch;
  } finally {
    // The new key now exists only as per-member sealed wraps; drop this copy.
    // The caller re-unwraps its own from GET /v1/vaults.
    newKey.fill(0);
  }
}
