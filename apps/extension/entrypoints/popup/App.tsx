/**
 * Popup entry — session router. Locked shows the SRP sign-in form; unlocked
 * shows current-site matches (fill/TOTP) plus an all-items browser.
 */
import { useCallback, useEffect, useState } from "react";
import type { StatusData } from "../../lib/messages";
import { errMsg, send } from "./send";
import SignInForm from "./SignInForm";
import SitePanel from "./SitePanel";
import AllItems from "./AllItems";

export default function App() {
  const [status, setStatus] = useState<StatusData | null>(null);
  const [host, setHost] = useState("");
  const [tabId, setTabId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await send<StatusData>({ type: "status" }));
    } catch (e) {
      setError(errMsg(e));
      setStatus({ unlocked: false, email: null });
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    chrome.tabs
      .query({ active: true, currentWindow: true })
      .then(([tab]) => {
        setTabId(tab?.id ?? null);
        try {
          setHost(tab?.url ? new URL(tab.url).hostname : "");
        } catch {
          setHost("");
        }
      })
      .catch(() => undefined);
  }, []);

  async function handleLock() {
    try {
      setStatus(await send<StatusData>({ type: "lock" }));
    } catch (e) {
      setError(errMsg(e));
    }
  }

  return (
    <div className="w-[360px] bg-bg text-sm text-fg">
      <header className="flex items-center justify-between gap-2 border-b border-border bg-surface px-3 py-2.5">
        <div className="min-w-0">
          <h1 className="text-sm font-semibold">Kleidion</h1>
          {status?.unlocked && (
            <p className="truncate text-[11px] text-fg-muted">{status.email}</p>
          )}
        </div>
        {status?.unlocked && (
          <button
            type="button"
            onClick={() => void handleLock()}
            className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg"
          >
            Lock
          </button>
        )}
      </header>

      {error && (
        <p role="alert" className="border-b border-border px-3 py-2 text-xs text-danger">
          {error}
        </p>
      )}

      {!status ? (
        <p className="px-3 py-6 text-center text-fg-muted">Connecting…</p>
      ) : !status.unlocked ? (
        <SignInForm onUnlocked={refreshStatus} />
      ) : (
        <main className="max-h-[480px] overflow-y-auto">
          {host && <SitePanel host={host} tabId={tabId} />}
          <AllItems />
        </main>
      )}
    </div>
  );
}
