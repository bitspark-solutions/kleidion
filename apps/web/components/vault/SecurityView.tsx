"use client";

// Security health ("Watchtower-lite", Phase 5 contract Step B): decrypts every
// login across ALL unlocked vaults client-side and reports reuse, weak
// passwords, missing TOTP and stale items. Nothing here ever reaches the
// server — the audit runs on decrypted plaintext only.

import { useEffect, useMemo, useState } from "react";
import { decryptItem, fromBase64, ready } from "@kleidion/crypto";
import { findReuse, isOld, scorePassword, type PasswordScore } from "@kleidion/core/audit";
import { listItems } from "@/lib/vault-api";
import { ITEM_TYPES, type Item, type ItemPlain } from "@/lib/types";

interface LoginRow {
  item: Item;
  plain: ItemPlain;
  vaultId: string;
  vaultName: string;
  vaultRole: "admin" | "write" | "read";
  password: string | null;
  hasTotp: boolean;
}

export interface SecurityViewProps {
  vaults: { id: string; name: string; role: "admin" | "write" | "read" }[];
  getVaultKey: (vaultId: string) => Uint8Array | null;
  /** Bump to re-run the audit after item mutations. */
  refreshNonce: number;
  /** Jump to the item in its vault. */
  onOpen: (vaultId: string, itemId: string) => void;
  /** Open the editor for the item with a freshly generated password applied. */
  onRegenerate: (item: Item, plain: ItemPlain) => void;
}

function passwordOf(plain: ItemPlain): string | null {
  const f = (plain.fields ?? []).find(
    (x) => x.type === "password" && x.label.toLowerCase() === "password",
  );
  return f ? f.value : null;
}

function HealthRing({ pct }: { pct: number }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  const color = pct >= 80 ? "text-accent" : pct >= 50 ? "text-fg-muted" : "text-danger";
  return (
    <svg width="72" height="72" viewBox="0 0 64 64" role="img" aria-label={`Vault health ${pct}%`}>
      <circle cx="32" cy="32" r={r} fill="none" stroke="currentColor" strokeWidth="6" className="text-border" opacity="0.5" />
      <circle
        cx="32"
        cy="32"
        r={r}
        fill="none"
        stroke="currentColor"
        strokeWidth="6"
        strokeLinecap="round"
        strokeDasharray={`${(c * pct) / 100} ${c}`}
        transform="rotate(-90 32 32)"
        className={color}
      />
      <text x="32" y="37" textAnchor="middle" className="fill-current text-sm font-semibold" fontSize="14">
        {pct}%
      </text>
    </svg>
  );
}

function Section({
  title,
  hint,
  rows,
  renderMeta,
  onOpen,
  onRegen,
}: {
  title: string;
  hint: string;
  rows: LoginRow[];
  renderMeta: (r: LoginRow) => string;
  onOpen: (r: LoginRow) => void;
  onRegen?: (r: LoginRow) => void;
}) {
  if (rows.length === 0) return null;
  return (
    <section className="mt-6">
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      <p className="text-xs text-fg-muted">{hint}</p>
      <ul className="mt-2 divide-y divide-border rounded-lg border border-border bg-surface">
        {rows.map((r) => (
          <li key={`${title}-${r.item.id}`} className="flex items-center gap-3 px-3 py-2">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-fg">{r.plain.title}</p>
              <p className="truncate text-xs text-fg-muted">
                {r.vaultName} · {renderMeta(r)}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onOpen(r)}
              className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg"
            >
              Open
            </button>
            {onRegen && r.vaultRole !== "read" && (
              <button
                type="button"
                onClick={() => onRegen(r)}
                className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-fg hover:opacity-90"
              >
                Regenerate
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function SecurityView({ vaults, getVaultKey, refreshNonce, onOpen, onRegenerate }: SecurityViewProps) {
  const [rows, setRows] = useState<LoginRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setError(null);
      try {
        await ready();
        const out: LoginRow[] = [];
        for (const v of vaults) {
          const key = getVaultKey(v.id);
          if (!key) continue;
          const res = await listItems({ vaultId: v.id });
          for (const it of res.items) {
            if (it.itemType !== ITEM_TYPES.Login || it.deletedAt) continue;
            try {
              const json = await decryptItem(key, {
                ciphertext: fromBase64(it.ciphertext),
                nonce: fromBase64(it.nonce),
              });
              const plain = JSON.parse(json) as ItemPlain;
              out.push({
                item: it,
                plain,
                vaultId: v.id,
                vaultName: v.name || "Vault",
                vaultRole: v.role,
                password: passwordOf(plain),
                hasTotp: (plain.fields ?? []).some((f) => f.type === "totp" && f.value !== ""),
              });
            } catch {
              /* undecryptable items are skipped in the audit */
            }
          }
        }
        if (!cancelled) setRows(out);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Audit failed");
      }
    })().catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [vaults, getVaultKey, refreshNonce]);

  const analysis = useMemo(() => {
    if (!rows) return null;
    const withPw = rows.filter((r) => r.password !== null);
    const scores = new Map<string, PasswordScore>();
    for (const r of withPw) {
      scores.set(r.item.id, scorePassword(r.password!));
    }
    const reuse = findReuse(
      withPw.map((r) => ({ id: r.item.id, password: r.password! })),
    );
    const byId = new Map(withPw.map((r) => [r.item.id, r]));
    const reusedRows: LoginRow[] = [];
    const groupSize = new Map<string, number>();
    for (const group of reuse.values()) {
      for (const g of group) groupSize.set(g.id, group.length);
      for (const g of group) {
        const row = byId.get(g.id);
        if (row) reusedRows.push(row);
      }
    }
    const weak = withPw.filter((r) => (scores.get(r.item.id)?.score ?? 0) <= 1);
    const missingTotp = withPw.filter((r) => !r.hasTotp);
    const stale = withPw.filter((r) => isOld(r.item.updatedAt));
    const healthy = withPw.filter((r) => (scores.get(r.item.id)?.score ?? 0) >= 3).length;
    const pct = withPw.length === 0 ? 100 : Math.round((healthy / withPw.length) * 100);
    return { reuseCount: reuse.size, reusedRows, groupSize, weak, missingTotp, stale, pct, scores };
  }, [rows]);

  const open = (r: LoginRow) => onOpen(r.vaultId, r.item.id);
  const regen = (r: LoginRow) => onRegenerate(r.item, r.plain);

  return (
    <div className="h-full overflow-y-auto bg-bg p-6">
      <h2 className="text-lg font-semibold text-fg">Security</h2>
      <p className="text-xs text-fg-muted">
        Computed on this device only — the server cannot see these results.
      </p>

      {error && <p role="alert" className="mt-4 text-sm text-danger">{error}</p>}
      {!rows && !error && <p className="mt-4 text-sm text-fg-muted">Auditing your vaults…</p>}

      {analysis && (
        <>
          <div className="mt-4 flex items-center gap-6 rounded-lg border border-border bg-surface p-4">
            <HealthRing pct={analysis.pct} />
            <div className="grid flex-1 grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { label: "Reused", value: analysis.reuseCount },
                { label: "Weak", value: analysis.weak.length },
                { label: "No TOTP", value: analysis.missingTotp.length },
                { label: "Old (>180d)", value: analysis.stale.length },
              ].map((c) => (
                <div key={c.label} className="rounded-md border border-border bg-bg px-3 py-2">
                  <p className="text-xl font-semibold tabular-nums text-fg">{c.value}</p>
                  <p className="text-xs text-fg-muted">{c.label}</p>
                </div>
              ))}
            </div>
          </div>

          <Section
            title="Reused passwords"
            hint="The same password protects multiple logins."
            rows={analysis.reusedRows}
            renderMeta={(r) => `Used on ${analysis.groupSize.get(r.item.id) ?? 2} logins`}
            onOpen={open}
            onRegen={regen}
          />
          <Section
            title="Weak passwords"
            hint="Scored 0–1 by the built-in heuristic checker. Have I Been Pwned: check offline (not yet wired)."
            rows={analysis.weak}
            renderMeta={(r) =>
              analysis.scores.get(r.item.id)?.reasons.join("; ") || "weak"
            }
            onOpen={open}
            onRegen={regen}
          />
          <Section
            title="Logins without 2FA"
            hint="Adding a TOTP secret protects these accounts if the password leaks."
            rows={analysis.missingTotp}
            renderMeta={(r) => `updated ${new Date(r.item.updatedAt).toLocaleDateString()}`}
            onOpen={open}
          />
          <Section
            title="Haven't changed in 180+ days"
            hint="Consider rotating these passwords."
            rows={analysis.stale}
            renderMeta={(r) => `updated ${new Date(r.item.updatedAt).toLocaleDateString()}`}
            onOpen={open}
          />
        </>
      )}
    </div>
  );
}
