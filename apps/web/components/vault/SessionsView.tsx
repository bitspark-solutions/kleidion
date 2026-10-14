"use client";

// Active sessions (Settings): lists every live session for this account —
// device name/platform, User-Agent, created/last-used metadata — with a
// revoke button each. Revoking is server-side: the target session's bearer
// token stops working immediately. Signing out of this device hits the real
// POST /v1/auth/logout (revocation, not just a local lock).
//
// Privacy note: everything shown here is REQUEST-derived metadata (device
// name the client chose + the HTTP User-Agent + timestamps). Zero-knowledge
// is intact — the server never stored anything decryptable, not even the
// session token itself (only its SHA-256 hash).

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { listSessions, revokeSession, type SessionInfo } from "@/lib/vault-api";
import { signOutCurrentDevice } from "@/lib/sign-out";

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function SessionsView() {
  const router = useRouter();
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listSessions();
      setSessions(res.sessions);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleRevoke = useCallback(
    async (s: SessionInfo) => {
      setBusyId(s.id);
      setError(null);
      try {
        if (s.current) {
          // Revoking the session we are authenticated with == sign out.
          await signOutCurrentDevice();
          router.replace("/signin");
          return;
        }
        await revokeSession(s.id);
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to revoke session");
      } finally {
        setBusyId(null);
      }
    },
    [load, router],
  );

  const handleSignOut = useCallback(async () => {
    setBusyId("signout");
    await signOutCurrentDevice();
    router.replace("/signin");
  }, [router]);

  return (
    <section className="rounded-lg border border-border bg-surface p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-fg">Active sessions</h2>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading}
          className="rounded-md px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {error && (
        <p role="alert" className="mb-3 text-xs text-danger">
          {error}
        </p>
      )}

      {loading && sessions === null && (
        <p className="text-sm text-fg-muted">Loading sessions…</p>
      )}

      {sessions !== null && sessions.length === 0 && (
        <p className="text-sm text-fg-muted">No active sessions.</p>
      )}

      {sessions && sessions.length > 0 && (
        <ul className="divide-y divide-border">
          {sessions.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-fg">
                  {s.deviceName}
                  <span className="ml-2 text-[10px] uppercase tracking-wide text-fg-muted">
                    {s.devicePlatform}
                  </span>
                  {s.current && (
                    <span className="ml-2 rounded-full bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                      this device
                    </span>
                  )}
                </p>
                <p className="mt-0.5 truncate text-xs text-fg-muted" title={s.userAgent}>
                  {s.userAgent || "unknown client"}
                </p>
                <p className="mt-0.5 text-xs text-fg-muted">
                  Signed in {fmtTime(s.createdAt)} · used {fmtTime(s.lastUsedAt)} · expires{" "}
                  {fmtTime(s.expiresAt)}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleRevoke(s)}
                disabled={busyId !== null}
                className="shrink-0 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-danger transition-colors hover:bg-surface-hover disabled:opacity-50"
              >
                {busyId === s.id ? "…" : s.current ? "Sign out" : "Revoke"}
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 border-t border-border pt-3">
        <button
          type="button"
          onClick={() => void handleSignOut()}
          disabled={busyId !== null}
          className="w-full rounded-md bg-danger px-3 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          Sign out of this device
        </button>
        <p className="mt-2 text-[10px] leading-relaxed text-fg-muted">
          Logout revokes this session on the server — its access token stops
          working immediately, instead of lingering for 30 days. Revoke any
          other device from the list above.
        </p>
      </div>
    </section>
  );
}
