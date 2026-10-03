"use client";

// LockScreen — unlock form used when an existing session is locked (after
// auto-lock or reload). Requires password + Secret Key and performs a full
// SRP sign-in via lib/auth-client (the session store is memory-only, so
// "unlock" == "signin").

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { signin } from "@/lib/auth-client";
import { getLastEmail, useSession } from "@/lib/session";
import { ApiError } from "@/lib/api-base";

export interface LockScreenProps {
  /** Prefilled email (e.g. from the session store). Falls back to getLastEmail(). */
  email?: string;
  /** Where to go after unlock. */
  redirectTo?: string;
  /** Optional heading override. */
  title?: string;
}

export default function LockScreen({ email, redirectTo = "/vault", title = "Vault locked" }: LockScreenProps) {
  const router = useRouter();
  const session = useSession();

  const [mail, setMail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setMail(email || getLastEmail());
  }, [email]);

  // Already unlocked (e.g. another tab/component unlocked): go straight in.
  useEffect(() => {
    if (session.unlocked) router.replace(redirectTo);
  }, [session.unlocked, router, redirectTo]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await signin({ email: mail, password, secretKey });
      router.replace(redirectTo);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Invalid credentials — check your password and Secret Key.");
      } else if (err instanceof Error) {
        setError(err.message || "Unlock failed.");
      } else {
        setError("Unlock failed.");
      }
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  if (session.unlocked) return null;

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Your keys live in memory only. Enter your master password and Secret Key to unlock.
        </p>
      </div>

      {error && (
        <p role="alert" className="rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
          {error}
        </p>
      )}

      <div className="space-y-1.5">
        <label htmlFor="lock-email" className="text-xs uppercase tracking-wide text-fg-muted">
          Email
        </label>
        <input
          id="lock-email"
          type="email"
          required
          autoComplete="username"
          value={mail}
          onChange={(e) => setMail(e.target.value)}
          className="w-full rounded-xl border border-border bg-bg px-3.5 py-2.5 text-sm outline-none transition-colors placeholder:text-fg-muted/50 focus:border-accent"
          placeholder="you@example.com"
        />
      </div>

      <div className="space-y-1.5">
        <label htmlFor="lock-password" className="text-xs uppercase tracking-wide text-fg-muted">
          Master password
        </label>
        <input
          id="lock-password"
          type="password"
          required
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-xl border border-border bg-bg px-3.5 py-2.5 text-sm outline-none transition-colors placeholder:text-fg-muted/50 focus:border-accent"
          placeholder="••••••••••••"
        />
      </div>

      <div className="space-y-1.5">
        <label htmlFor="lock-secret" className="text-xs uppercase tracking-wide text-fg-muted">
          Secret Key
        </label>
        <input
          id="lock-secret"
          type="text"
          required
          autoComplete="off"
          spellCheck={false}
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          className="w-full rounded-xl border border-border bg-bg px-3.5 py-2.5 font-mono text-sm outline-none transition-colors placeholder:text-fg-muted/50 focus:border-accent"
          placeholder="KL-XXXXXX-XXXXXX-…"
        />
      </div>

      <button
        type="submit"
        disabled={busy}
        className="w-full rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-accent-fg transition-opacity disabled:cursor-not-allowed disabled:opacity-60"
      >
        {busy ? "Deriving keys…" : "Unlock"}
      </button>
    </form>
  );
}
