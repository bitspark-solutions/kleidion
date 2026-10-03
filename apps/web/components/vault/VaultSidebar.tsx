"use client";

// Left sidebar: vault switcher, categories by itemType, Favorites, Trash —
// with live counts. Purely presentational; VaultShell owns all state.

import { useState, type FormEvent } from "react";
import { ITEM_TYPES, type VaultRole } from "@/lib/types";

export type VaultCategory =
  | "all"
  | "logins"
  | "notes"
  | "cards"
  | "identities"
  | "favorites"
  | "trash";

export interface SidebarVault {
  id: string;
  name: string;
  kind: "personal" | "shared";
  role: VaultRole;
}

export interface VaultSidebarProps {
  vaults: SidebarVault[];
  selectedVaultId: string | null;
  onSelectVault: (vaultId: string) => void;
  category: VaultCategory;
  onSelectCategory: (category: VaultCategory) => void;
  /** Counts for the SELECTED vault: keys "logins"|"notes"|"cards"|"identities"|"all"|"favorites"|"trash". */
  counts: Partial<Record<VaultCategory, number>>;
  onCreateVault: (name: string) => Promise<void>;
  canWrite: boolean;
}

const CATEGORIES: { key: VaultCategory; label: string; glyph: string }[] = [
  { key: "all", label: "All items", glyph: "▦" },
  { key: "logins", label: "Logins", glyph: "🔑" },
  { key: "notes", label: "Secure Notes", glyph: "📝" },
  { key: "cards", label: "Cards", glyph: "💳" },
  { key: "identities", label: "Identities", glyph: "🪪" },
  { key: "favorites", label: "Favorites", glyph: "★" },
  { key: "trash", label: "Trash", glyph: "🗑" },
];

export const CATEGORY_ITEM_TYPE: Partial<Record<VaultCategory, number>> = {
  logins: ITEM_TYPES.Login,
  notes: ITEM_TYPES.SecureNote,
  cards: ITEM_TYPES.Card,
  identities: ITEM_TYPES.Identity,
};

export default function VaultSidebar({
  vaults,
  selectedVaultId,
  onSelectVault,
  category,
  onSelectCategory,
  counts,
  onCreateVault,
  canWrite,
}: VaultSidebarProps) {
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  async function submitCreate(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    try {
      await onCreateVault(trimmed);
      setName("");
      setCreating(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <nav
      aria-label="Vault navigation"
      className="flex h-full w-full flex-col gap-6 overflow-y-auto border-r border-border bg-surface p-4"
    >
      <section>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
            Vaults
          </h2>
          {canWrite && (
            <button
              type="button"
              onClick={() => setCreating((c) => !c)}
              className="rounded-md px-1.5 py-0.5 text-sm text-accent hover:bg-surface-hover"
              aria-label="New vault"
            >
              +
            </button>
          )}
        </div>
        {creating && (
          <form onSubmit={submitCreate} className="mb-2 flex gap-1">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Vault name"
              autoFocus
              className="min-w-0 flex-1 rounded-md border border-border bg-bg px-2 py-1 text-sm text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none"
            />
            <button
              type="submit"
              disabled={busy || !name.trim()}
              className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-fg disabled:opacity-50"
            >
              {busy ? "…" : "Create"}
            </button>
          </form>
        )}
        <ul className="space-y-0.5">
          {vaults.length === 0 && (
            <li className="px-2 py-1 text-sm text-fg-muted">No vaults yet</li>
          )}
          {vaults.map((v) => (
            <li key={v.id}>
              <button
                type="button"
                onClick={() => onSelectVault(v.id)}
                aria-current={v.id === selectedVaultId}
                className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-surface-hover ${
                  v.id === selectedVaultId
                    ? "bg-surface-hover font-medium text-fg"
                    : "text-fg-muted"
                }`}
              >
                <span className="truncate">
                  {v.name || (v.kind === "shared" ? "Shared vault" : "Personal vault")}
                </span>
                <span className="shrink-0 text-[10px] uppercase tracking-wide opacity-70">
                  {v.kind === "shared" ? v.role : v.kind}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section className="flex-1">
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">
          Categories
        </h2>
        <ul className="space-y-0.5">
          {CATEGORIES.map((c) => {
            const count = counts[c.key] ?? 0;
            return (
              <li key={c.key}>
                <button
                  type="button"
                  onClick={() => onSelectCategory(c.key)}
                  aria-current={c.key === category}
                  className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-surface-hover ${
                    c.key === category
                      ? "bg-surface-hover font-medium text-fg"
                      : "text-fg-muted"
                  }`}
                >
                  <span aria-hidden className="w-5 text-center">
                    {c.glyph}
                  </span>
                  <span className="flex-1 truncate">{c.label}</span>
                  {count > 0 && (
                    <span className="rounded-full bg-bg px-1.5 text-[10px] tabular-nums text-fg-muted">
                      {count}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </section>

      <p className="text-[10px] leading-relaxed text-fg-muted">
        Zero-knowledge: everything you see here was decrypted on this device.
      </p>
    </nav>
  );
}
