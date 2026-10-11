import { useEffect, useMemo, useState } from "react";
import type { CredentialsData, MatchEntry } from "../../lib/messages";
import { errMsg, send } from "./send";
import TotpChip from "./TotpChip";

/** All logins across every unlocked vault, filterable — the popup mini-vault. */
export default function AllItems() {
  const [entries, setEntries] = useState<MatchEntry[] | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    send<MatchEntry[]>({ type: "list" })
      .then(setEntries)
      .catch((e) => {
        setError(errMsg(e));
        setEntries([]);
      });
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = entries ?? [];
    if (!q) return list;
    return list.filter(
      (e) =>
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.vaultName.toLowerCase().includes(q),
    );
  }, [entries, query]);

  function flashCopy(key: string, text: string) {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied((c) => (c === key ? null : c)), 1200);
    });
  }

  async function copyPassword(itemId: string, key: string) {
    try {
      const cred = await send<CredentialsData>({ type: "credentials", itemId });
      flashCopy(key, cred.password);
    } catch (e) {
      setError(errMsg(e));
    }
  }

  return (
    <section className="p-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
          All items
        </h2>
        <span className="text-[11px] text-fg-muted">
          {entries ? `${filtered.length}` : "…"}
        </span>
      </div>
      <input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search vaults…"
        className="mt-2 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-sm text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none"
      />
      {error && <p className="mt-2 text-xs text-danger">{error}</p>}
      {entries === null ? (
        <p className="mt-2 text-sm text-fg-muted">Loading…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-2 text-sm text-fg-muted">Nothing found.</p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {filtered.map((e) => (
            <li
              key={e.itemId}
              className="rounded-lg border border-border bg-surface px-2.5 py-2"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm text-fg">{e.title}</p>
                  <p className="truncate text-[11px] text-fg-muted">
                    {e.username} · {e.vaultName || "Personal"}
                  </p>
                </div>
                {e.hasTotp && <TotpChip itemId={e.itemId} />}
              </div>
              <div className="mt-1.5 flex gap-1.5">
                <button
                  type="button"
                  onClick={() => flashCopy(`u-${e.itemId}`, e.username)}
                  className="rounded-md border border-border px-2 py-0.5 text-[11px] text-fg-muted hover:bg-surface-hover"
                >
                  {copied === `u-${e.itemId}` ? "Copied" : "Copy user"}
                </button>
                <button
                  type="button"
                  onClick={() => void copyPassword(e.itemId, `p-${e.itemId}`)}
                  className="rounded-md border border-border px-2 py-0.5 text-[11px] text-fg-muted hover:bg-surface-hover"
                >
                  {copied === `p-${e.itemId}` ? "Copied" : "Copy pass"}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
