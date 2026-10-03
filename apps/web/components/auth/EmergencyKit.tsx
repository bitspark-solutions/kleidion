"use client";

// Emergency Kit: shows the account email + Secret Key ONCE, with a print
// button and a MANDATORY "I have saved my Secret Key" checkbox that gates
// the continue button. There is no server-side reset — losing the Secret Key
// means permanent, unrecoverable data loss.

import { useState, type ReactNode } from "react";

export interface EmergencyKitProps {
  email: string;
  secretKey: string;
  accountId: string;
  /** Rendered as the gated continue button (parent handles navigation). */
  onContinue: () => void;
  continueLabel?: string;
  /** Optional extra content below the gate (e.g. status messages). */
  footer?: ReactNode;
}

export default function EmergencyKit({
  email,
  secretKey,
  accountId,
  onContinue,
  continueLabel = "Continue to my vault",
  footer,
}: EmergencyKitProps) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyKey() {
    try {
      await navigator.clipboard.writeText(secretKey);
      setCopied(true);
      // 30s auto-clear of the clipboard (best-effort) + visual state.
      setTimeout(async () => {
        try {
          const cur = await navigator.clipboard.readText();
          if (cur === secretKey) await navigator.clipboard.writeText("");
        } catch {
          /* clipboard read may be denied; ignore */
        }
        setCopied(false);
      }, 30_000);
    } catch {
      /* clipboard unavailable — user can still select manually */
    }
  }

  function printKit() {
    const w = window.open("", "_blank", "width=720,height=900");
    if (!w) return;
    w.document.write(`<!doctype html><html><head><title>Kleidion Emergency Kit</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #111; }
  .box { border: 2px solid #111; border-radius: 8px; padding: 1.5rem; max-width: 34rem; }
  .key { font-family: ui-monospace, monospace; font-size: 1.4rem; letter-spacing: 0.05em; word-break: break-all; }
  .warn { color: #b00020; font-weight: 600; }
  h1 { font-size: 1.2rem; } p { color: #444; }
</style></head><body>
<div class="box">
  <h1>Kleidion Emergency Kit</h1>
  <p>Account: <strong>${escapeHtml(email)}</strong><br/>Account ID: <strong>${escapeHtml(accountId)}</strong></p>
  <p>Secret Key:</p>
  <p class="key">${escapeHtml(secretKey)}</p>
  <p class="warn">Write this down and store it somewhere safe. Without your password AND this
  Secret Key, your data cannot be recovered — there is no reset. Never share it,
  and never store it on the same device as your password.</p>
</div>
</body></html>`);
    w.document.close();
    w.focus();
    w.print();
  }

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-danger/40 bg-surface p-6">
        <h2 className="text-lg font-semibold">Your Emergency Kit</h2>
        <p className="mt-1 text-sm text-fg-muted">
          This is the <strong className="text-fg">only time</strong> your Secret Key is shown.
          Kleidion is zero-knowledge: we cannot see it, store a copy, or reset it.
          <strong className="text-danger"> Lose it and your data is lost forever.</strong>
        </p>

        <dl className="mt-5 space-y-4">
          <div>
            <dt className="text-xs uppercase tracking-wide text-fg-muted">Email</dt>
            <dd className="mt-0.5 font-mono text-sm break-all">{email}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-fg-muted">Secret Key</dt>
            <dd className="mt-1 rounded-lg border border-border bg-bg p-3 font-mono text-base break-all tracking-wide select-all">
              {secretKey}
            </dd>
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                onClick={copyKey}
                className="rounded-lg border border-border px-3 py-1.5 text-xs text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
              >
                {copied ? "Copied (auto-clears in 30s)" : "Copy to clipboard"}
              </button>
              <button
                type="button"
                onClick={printKit}
                className="rounded-lg border border-border px-3 py-1.5 text-xs text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
              >
                Print
              </button>
            </div>
          </div>
        </dl>
      </div>

      <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border bg-surface p-4">
        <input
          type="checkbox"
          checked={saved}
          onChange={(e) => setSaved(e.target.checked)}
          className="mt-0.5 size-4 accent-[var(--color-accent)]"
          required
        />
        <span className="text-sm">
          I have <strong>saved my Secret Key</strong> (printed or written down) in a safe place.
          I understand that if I lose my password <em>and</em> this Secret Key,{" "}
          <strong className="text-danger">my data can never be recovered</strong> — there is no
          server-side reset.
        </span>
      </label>

      <button
        type="button"
        disabled={!saved}
        onClick={onContinue}
        className="w-full rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-accent-fg transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
      >
        {continueLabel}
      </button>

      {footer}
    </div>
  );
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
