"use client";

// MembersDialog — Phase 4 Step D. Sharing a vault = wrapping its key with
// each member's X25519 public key (sealed box, client-side) and uploading the
// opaque result. The server enforces roles but can never read the vault key.
//
// REMOVAL is a different operation (ADR-008): deleting the member's wrap only
// stops future access to the key, it does not undo that they can decrypt every
// row they already synced. So removing a member also rotates the vault key —
// this device re-encrypts the whole vault under a fresh key and re-seals it for
// the survivors, in one request. If that rotation fails, the member is NOT
// removed: a half-done revocation looks like a fix and isn't one.

import { useCallback, useEffect, useState } from "react";
import { fromHex, ready, toBase64, wrapVaultKey } from "@kleidion/crypto";
import {
  addMember,
  listMembers,
  lookupUser,
  patchMemberRole,
  removeMember,
  type VaultMemberInfo,
} from "@/lib/vault-api";
import { rotateVault } from "@/lib/vault-rotation";
import type { Item, ItemPlain, VaultRole } from "@/lib/types";

const ROLES: VaultRole[] = ["admin", "write", "read"];

export default function MembersDialog({
  vaultId,
  vaultKey,
  selfUserId,
  selfRole,
  items,
  plains,
  encryptedMeta,
  metaNonce,
  onRotated,
  onClose,
}: {
  vaultId: string;
  vaultKey: Uint8Array;
  selfUserId: string;
  selfRole: VaultRole;
  /** Every row of this vault (tombstones included) — needed to re-encrypt. */
  items: Item[];
  /** Decrypted plaintext per item id; a null blocks rotation. */
  plains: Record<string, ItemPlain | null>;
  encryptedMeta: string;
  metaNonce: string;
  /** Called after a successful rotation so the parent reloads keys + rows. */
  onRotated: () => Promise<void>;
  onClose: () => void;
}) {
  const isAdmin = selfRole === "admin";
  const [members, setMembers] = useState<VaultMemberInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<VaultRole>("write");
  const [busy, setBusy] = useState(false);
  // Member awaiting confirmation for revoke+rotate. Removal is destructive to
  // the whole vault's ciphertext, so it gets an explicit second step.
  const [pendingRevoke, setPendingRevoke] = useState<VaultMemberInfo | null>(null);
  const [rotated, setRotated] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const res = await listMembers(vaultId);
      setMembers(res.members);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load members");
    } finally {
      setLoading(false);
    }
  }, [vaultId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const invite = useCallback(async () => {
    const trimmed = email.trim().toLowerCase();
    if (!trimmed || busy) return;
    if (rotated) {
      // vaultKey here is the retired key; sealing it for a new member would
      // hand them something that decrypts nothing.
      setError("The vault key was rotated in this dialog. Close and reopen it to invite.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await ready();
      const user = await lookupUser(trimmed);
      const wrapped = await wrapVaultKey(vaultKey, fromHex(user.masterPublicKey));
      await addMember(vaultId, {
        email: user.email,
        role,
        wrappedVaultKey: toBase64(wrapped),
      });
      setEmail("");
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invite failed");
    } finally {
      setBusy(false);
    }
  }, [email, role, vaultKey, vaultId, busy, rotated, reload]);

  // Admin removing someone: revoke their access AND retire the vault key they
  // still hold, in one atomic request. A failed rotation must leave the roster
  // untouched — see the file header.
  const revokeAndRotate = useCallback(
    async (target: VaultMemberInfo) => {
      if (busy) return;
      if (rotated) {
        setError("The vault key was already rotated in this dialog. Close and reopen it to make further changes.");
        return;
      }
      setBusy(true);
      setError(null);
      try {
        const remaining = members
          .filter((m) => m.userId !== target.userId)
          .map((m) => ({ userId: m.userId, masterPublicKey: m.masterPublicKey }));
        await rotateVault({
          vaultId,
          currentKey: vaultKey,
          items,
          plains,
          encryptedMeta,
          metaNonce,
          remainingMembers: remaining,
          revokedUserId: target.userId,
        });
        setPendingRevoke(null);
        setRotated(true);
        await onRotated();
        await reload();
      } catch (err) {
        const detail = err instanceof Error ? err.message : "the vault key could not be rotated";
        setError(`${detail} ${target.email} was NOT removed.`);
      } finally {
        setBusy(false);
      }
    },
    [busy, rotated, members, vaultId, vaultKey, items, plains, encryptedMeta, metaNonce, onRotated, reload],
  );

  return (
    <div
      role="dialog"
      aria-label="Vault members"
      className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-border bg-bg p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-fg">Members</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md px-2 py-1 text-sm text-fg-muted hover:bg-surface-hover hover:text-fg"
          >
            ✕
          </button>
        </div>
        <p className="mt-1 text-xs text-fg-muted">
          The vault key is sealed separately for each member on this device; the server only
          stores opaque wraps and enforces roles.
        </p>

        {error && (
          <p role="alert" className="mt-2 text-xs text-danger">
            {error}
          </p>
        )}

        <ul className="mt-4 space-y-1">
          {loading && <li className="text-sm text-fg-muted">Loading…</li>}
          {members.map((m) => (
            <li
              key={m.userId}
              className="flex items-center justify-between gap-2 rounded-md border border-border bg-surface px-3 py-2 text-sm"
            >
              <span className="min-w-0 truncate text-fg">
                {m.email}
                {m.userId === selfUserId && (
                  <span className="ml-1 text-xs text-fg-muted">(you)</span>
                )}
              </span>
              <span className="flex shrink-0 items-center gap-2">
                {isAdmin ? (
                  <select
                    value={m.role}
                    onChange={async (e) => {
                      const next = e.target.value as VaultRole;
                      try {
                        await patchMemberRole(vaultId, m.userId, next);
                        await reload();
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "Role update failed");
                      }
                    }}
                    aria-label={`Role for ${m.email}`}
                    className="rounded-md border border-border bg-bg px-1.5 py-1 text-xs text-fg"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span className="text-xs uppercase tracking-wide text-fg-muted">{m.role}</span>
                )}
                {m.userId === selfUserId ? (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={async () => {
                      // Leaving is deliberately NOT a rotation: the member who
                      // leaves already holds the key and cannot retire it for
                      // the others. Whoever stays should rotate the vault key.
                      setBusy(true);
                      try {
                        await removeMember(vaultId, m.userId);
                        onClose();
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "Could not leave this vault");
                      } finally {
                        setBusy(false);
                      }
                    }}
                    className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-danger hover:text-danger"
                  >
                    Leave
                  </button>
                ) : isAdmin ? (
                  <button
                    type="button"
                    disabled={busy || rotated}
                    onClick={() => {
                      setError(null);
                      setPendingRevoke(m);
                    }}
                    className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-danger hover:text-danger disabled:opacity-50"
                  >
                    Remove
                  </button>
                ) : null}
              </span>
            </li>
          ))}
        </ul>

        {pendingRevoke && (
          <div
            role="alertdialog"
            aria-label="Confirm removal"
            className="mt-4 rounded-lg border border-danger/60 bg-surface p-4"
          >
            <p className="text-sm font-semibold text-fg">
              Remove {pendingRevoke.email} and rotate the vault key?
            </p>
            <p className="mt-1 text-xs leading-relaxed text-fg-muted">
              Their access alone would not revoke the key they already hold, so this
              device re-encrypts all {items.length} row(s) of this vault under a new
              key and re-seals it for the {members.length - 1} remaining member(s).
              Password history for this vault is cleared as part of that. Nothing is
              sent in the clear, and this cannot be undone.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => void revokeAndRotate(pendingRevoke)}
                className="rounded-md bg-danger px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
              >
                {busy ? "Rotating…" : "Remove and rotate"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setPendingRevoke(null)}
                className="rounded-md border border-border px-3 py-1.5 text-sm text-fg-muted hover:text-fg"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {rotated && (
          <p className="mt-3 rounded-md border border-border bg-surface px-3 py-2 text-xs text-fg-muted">
            Vault key rotated. This dialog still holds the retired key, so close and
            reopen it before inviting anyone.
          </p>
        )}

        {isAdmin && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void invite();
            }}
            className="mt-4 flex items-end gap-2"
          >
            <label className="min-w-0 flex-1">
              <span className="text-xs text-fg-muted">Invite by email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="they@kleidion.app"
                className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-sm text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none"
              />
            </label>
            <label>
              <span className="text-xs text-fg-muted">Role</span>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as VaultRole)}
                className="mt-1 block rounded-md border border-border bg-surface px-2 py-1.5 text-sm text-fg"
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="submit"
              disabled={busy || !email.trim() || rotated}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
            >
              {busy ? "…" : "Invite"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
