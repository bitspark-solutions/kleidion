import { useState, type FormEvent } from "react";
import { errMsg, send } from "./send";

export default function SignInForm({ onUnlocked }: { onUnlocked: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await send({ type: "signin", email, password, secretKey });
      setPassword("");
      setSecretKey("");
      onUnlocked();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3 p-3">
      <p className="text-xs text-fg-muted">
        Sign in with SRP — your password and Secret Key never leave this
        device in the clear.
      </p>
      <label className="block">
        <span className="text-xs text-fg-muted">Email</span>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-sm text-fg focus:border-accent focus:outline-none"
        />
      </label>
      <label className="block">
        <span className="text-xs text-fg-muted">Password</span>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-sm text-fg focus:border-accent focus:outline-none"
        />
      </label>
      <label className="block">
        <span className="text-xs text-fg-muted">Secret Key (Emergency Kit)</span>
        <input
          required
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          placeholder="KL-ACCOUNT-XXXX-…"
          className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-sm text-fg focus:border-accent focus:outline-none"
        />
      </label>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
      <button
        type="submit"
        disabled={busy || !email || !password || !secretKey}
        className="w-full rounded-md bg-accent px-3 py-2 text-sm font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
      >
        {busy ? "Signing in…" : "Sign in & unlock"}
      </button>
    </form>
  );
}
