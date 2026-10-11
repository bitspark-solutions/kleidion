"use client";

// MembersDialog — Phase 4 Step D. Sharing a vault = wrapping its key with
// each member's X25519 public key (sealed box, client-side) and uploading the
// opaque result. The server enforces roles but can never read the vault key.

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
import type { VaultRole } from "@/lib/types";

const ROLES: VaultRole[] = ["admin", "write", "read"];

export default function MembersDialog({
  vaultId,
  vaultKey,
  selfUserId,
  selfRole,
  onClose,
}: {
  vaultId: string;
  vaultKey: Uint8Array;
  selfUserId: string;
  selfRole: VaultRole;
  onClose: () => void;
}) {
  const isAdmin = selfRole === "admin";
  const [members, setMembers] = useState<VaultMemberInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<VaultRole>("write");
  const [busy, setBusy] = useState(false);

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
  }, [email, role, vaultKey, vaultId, busy, reload]);

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
                {(isAdmin || m.userId === selfUserId) && (
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await removeMember(vaultId, m.userId);
                        if (m.userId === selfUserId) onClose();
                        else await reload();
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "Removal failed");
                      }
                    }}
                    className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-danger hover:text-danger"
                  >
                    {m.userId === selfUserId ? "Leave" : "Remove"}
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>

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
              disabled={busy || !email.trim()}
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
