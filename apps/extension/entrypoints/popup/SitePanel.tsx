import { useEffect, useState } from "react";
import type { CredentialsData, MatchEntry } from "../../lib/messages";
import { errMsg, send } from "./send";
import TotpChip from "./TotpChip";
import { autofillIntoPage } from "../../lib/dom-fill";

async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

/** Self-clearing "Copied" flash on a row action. */
function useFlash(): [string | null, (key: string) => void] {
  const [flash, setFlash] = useState<string | null>(null);
  const fire = (key: string) => {
    setFlash(key);
    setTimeout(() => setFlash((f) => (f === key ? null : f)), 1200);
  };
  return [flash, fire];
}

export default function SitePanel({
  host,
  tabId,
}: {
  host: string;
  tabId: number | null;
}) {
  const [entries, setEntries] = useState<MatchEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [flash, fire] = useFlash();

  useEffect(() => {
    setEntries(null);
    send<MatchEntry[]>({ type: "match", hostname: host })
      .then(setEntries)
      .catch((e) => {
        setError(errMsg(e));
        setEntries([]);
      });
  }, [host]);

  async function fill(entry: MatchEntry) {
    if (tabId === null) return;
    try {
      const cred = await send<CredentialsData>({ type: "credentials", itemId: entry.itemId });
      await chrome.scripting.executeScript({
        target: { tabId },
        func: autofillIntoPage,
        args: [cred.username, cred.password],
      });
    } catch (e) {
      setError(errMsg(e));
    }
  }

  return (
    <section className="border-b border-border p-3">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
        Logins for {host}
      </h2>
      {error && <p className="mt-2 text-xs text-danger">{error}</p>}
      {entries === null ? (
        <p className="mt-2 text-sm text-fg-muted">Searching your vault…</p>
      ) : entries.length === 0 ? (
        <p className="mt-2 text-sm text-fg-muted">No matching logins.</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {entries.map((e) => (
            <li
              key={e.itemId}
              className="rounded-lg border border-border bg-surface p-2.5"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-fg">{e.title}</p>
                  <p className="truncate text-xs text-fg-muted">
                    {e.username} · {e.vaultName || "Personal"}
                  </p>
                </div>
                {tabId !== null && (
                  <button
                    type="button"
                    onClick={() => void fill(e)}
                    className="shrink-0 rounded-md bg-accent px-2.5 py-1 text-xs font-medium text-accent-fg hover:opacity-90"
                  >
                    Fill
                  </button>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void copyText(e.username).then(() => fire(`u-${e.itemId}`))}
                  className="rounded-md border border-border px-2 py-0.5 text-[11px] text-fg-muted hover:bg-surface-hover"
                >
                  {flash === `u-${e.itemId}` ? "Copied" : "Copy username"}
                </button>
                {e.hasTotp && <TotpChip itemId={e.itemId} />}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
