"use client";

// ShareDialog — Phase 4 Step C. Client-side creation of a zero-knowledge
// share link: the item plaintext is re-encrypted with a fresh random link
// key; the server only ever sees that ciphertext, and the key travels to the
// recipient inside the URL fragment (never sent in any request).

import { useCallback, useState } from "react";
import { encryptItem, generateVaultKey, ready, toBase64 } from "@kleidion/crypto";
import { createShareLink } from "@/lib/vault-api";
import type { ItemPlain } from "@/lib/types";

const EXPIRY_CHOICES = [
  { label: "1 hour", secs: 3600 },
  { label: "24 hours", secs: 24 * 3600 },
  { label: "7 days", secs: 7 * 24 * 3600 },
] as const;

export default function ShareDialog({
  itemId,
  plain,
  onClose,
}: {
  itemId: string;
  plain: ItemPlain;
  onClose: () => void;
}) {
  const [expiryIdx, setExpiryIdx] = useState(1);
  const [maxViews, setMaxViews] = useState("");
  const [recipient, setRecipient] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const create = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await ready();
      const linkKey = await generateVaultKey();
      const enc = await encryptItem(linkKey, JSON.stringify(plain));
      const secs = EXPIRY_CHOICES[expiryIdx].secs;
      const views = maxViews.trim() === "" ? undefined : parseInt(maxViews, 10);
      if (views !== undefined && (!Number.isInteger(views) || views < 1)) {
        throw new Error("maxViews must be a positive integer");
      }
      const res = await createShareLink({
        itemId,
        wrappedItem: toBase64(enc.ciphertext),
        wrappedNonce: toBase64(enc.nonce),
        viewOnly: true,
        expiresAt: new Date(Date.now() + secs * 1000).toISOString(),
        maxViews: views,
        recipientEmail: recipient.trim() === "" ? undefined : recipient.trim(),
      });
      // token:linkKey — both live in the fragment only.
      setShareUrl(`${window.location.origin}/share#${res.token}:${toBase64(linkKey)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create share link");
    } finally {
      setBusy(false);
    }
  }, [itemId, plain, expiryIdx, maxViews, recipient]);

  return (
    <div
      role="dialog"
      aria-label="Share item"
      className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-border bg-bg p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold text-fg">Share &ldquo;{plain.title}&rdquo;</h2>
        <p className="mt-1 text-xs text-fg-muted">
          End-to-end encrypted for this link. The key is embedded in the URL fragment and never
          reaches the server.
        </p>

        {shareUrl ? (
          <div className="mt-4 space-y-3">
            <textarea
              readOnly
              value={shareUrl}
              rows={3}
              onFocus={(e) => e.target.select()}
              className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-fg"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard
                    .writeText(shareUrl)
                    .then(() => setCopied(true))
                    .catch(() => setCopied(false));
                }}
                className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg hover:opacity-90"
              >
                {copied ? "Copied" : "Copy link"}
              </button>
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-border px-3 py-1.5 text-sm text-fg-muted hover:text-fg"
              >
                Done
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-4 space-y-3 text-sm">
            <label className="block">
              <span className="text-xs text-fg-muted">Expires in</span>
              <select
                value={expiryIdx}
                onChange={(e) => setExpiryIdx(Number(e.target.value))}
                className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-fg"
              >
                {EXPIRY_CHOICES.map((c, i) => (
                  <option key={c.secs} value={i}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-xs text-fg-muted">Max views (optional)</span>
              <input
                type="number"
                min={1}
                value={maxViews}
                onChange={(e) => setMaxViews(e.target.value)}
                placeholder="Unlimited"
                className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-fg"
              />
            </label>
            <label className="block">
              <span className="text-xs text-fg-muted">Recipient email (optional)</span>
              <input
                type="email"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                placeholder="Anyone with the link"
                className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-fg"
              />
            </label>
            {error && (
              <p role="alert" className="text-xs text-danger">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-border px-3 py-1.5 text-fg-muted hover:text-fg"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void create()}
                disabled={busy}
                className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
              >
                {busy ? "Creating…" : "Create link"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
