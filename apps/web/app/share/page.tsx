"use client";

// Public share viewer — Phase 4 Step C. URL shape: /share#<token>:<linkKeyB64>
// Both parts live ONLY in the fragment (never sent to any server). We POST the
// token to /v1/public/share-links/:token (this spends one view), receive
// ciphertext, and decrypt locally with the fragment key. No login required.

import { useEffect, useState } from "react";
import Link from "next/link";
import { decryptItem, fromBase64, ready } from "@kleidion/crypto";
import { ApiError, redeemShareLink } from "@/lib/vault-api";
import type { ItemField, ItemPlain } from "@/lib/types";

type State =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "ready"; plain: ItemPlain; viewOnly: boolean };

function parsePlain(json: string): ItemPlain {
  const p = JSON.parse(json) as ItemPlain;
  if (typeof p.title !== "string") throw new Error("Malformed shared item");
  return p;
}

export default function SharePage() {
  const [state, setState] = useState<State>({ phase: "loading" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const hash = window.location.hash.replace(/^#/, "");
      const sep = hash.indexOf(":");
      if (sep <= 0) {
        setState({ phase: "error", message: "This share link is malformed — the key is missing from the URL." });
        return;
      }
      const token = hash.slice(0, sep);
      const keyB64 = hash.slice(sep + 1);
      try {
        await ready();
        const res = await redeemShareLink(token);
        const linkKey = fromBase64(keyB64);
        const json = await decryptItem(linkKey, {
          ciphertext: fromBase64(res.wrappedItem),
          nonce: fromBase64(res.wrappedNonce),
        });
        if (!cancelled) setState({ phase: "ready", plain: parsePlain(json), viewOnly: res.viewOnly });
      } catch (err) {
        if (cancelled) return;
        const msg =
          err instanceof ApiError && err.status === 404
            ? "This share link has expired, hit its view limit, or was revoked."
            : err instanceof ApiError
              ? err.message
              : "This share link could not be opened.";
        setState({ phase: "error", message: msg });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="flex min-h-[100dvh] flex-col items-center bg-bg px-4 py-10 text-fg">
      <p className="text-xs uppercase tracking-wider text-fg-muted">Kleidion share</p>
      {state.phase === "loading" && (
        <p className="mt-8 text-sm text-fg-muted">Opening secure link…</p>
      )}
      {state.phase === "error" && (
        <div className="mt-8 max-w-md text-center">
          <p role="alert" className="text-sm text-danger">{state.message}</p>
          <Link href="/" className="mt-4 inline-block text-sm text-accent underline">
            Go to Kleidion
          </Link>
        </div>
      )}
      {state.phase === "ready" && (
        <article className="mt-6 w-full max-w-md rounded-xl border border-border bg-surface p-5">
          <h1 className="text-lg font-semibold">{state.plain.title}</h1>
          {state.viewOnly && (
            <p className="mt-1 text-xs text-fg-muted">View-only link · content was decrypted in your browser</p>
          )}
          <dl className="mt-4">
            {(state.plain.fields ?? []).map((f: ItemField, i) => (
              <div key={`${f.label}-${i}`} className="flex items-baseline justify-between gap-3 border-b border-border py-2 last:border-b-0">
                <dt className="text-xs text-fg-muted">{f.label}</dt>
                <dd className={`min-w-0 truncate text-sm ${f.type === "password" || f.type === "totp" ? "font-mono" : ""}`}>
                  {f.value}
                </dd>
              </div>
            ))}
          </dl>
          {state.plain.notes && (
            <div className="mt-4">
              <p className="text-xs text-fg-muted">Notes</p>
              <p className="mt-1 whitespace-pre-wrap text-sm">{state.plain.notes}</p>
            </div>
          )}
        </article>
      )}
    </main>
  );
}
