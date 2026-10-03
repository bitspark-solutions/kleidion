"use client";

// Right pane: decrypts and renders one Item's ItemPlain — field rows with
// per-secret reveal toggles, copy with 30s auto-clear countdown, favorite
// toggle, edit / trash actions, and the version history list.

import { useCallback, useEffect, useState } from "react";
import {
  ITEM_TYPE_LABELS,
  type Item,
  type ItemField,
  type ItemPlain,
  type ItemVersionInfo,
} from "@/lib/types";
import {
  AUTO_CLEAR_SECONDS,
  useAutoClearCopy,
} from "@/lib/use-auto-clear-copy";

export interface ItemDetailProps {
  item: Item | null;
  /** Decrypted plaintext for `item` (null while decrypting or on failure). */
  plain: ItemPlain | null;
  decryptError: string | null;
  versions: ItemVersionInfo[];
  versionsLoading: boolean;
  busy: boolean;
  canWrite: boolean;
  onToggleFavorite: () => void;
  onEdit: () => void;
  onTrash: () => void;
  onClose: () => void;
}

function FieldRow({
  field,
  canCopy,
  copy,
  remaining,
  pendingValue,
}: {
  field: ItemField;
  canCopy: boolean;
  copy: (v: string) => Promise<void>;
  remaining: number | null;
  pendingValue: string | null;
}) {
  const secret = field.type === "password" || field.type === "totp";
  const [revealed, setRevealed] = useState(false);
  const isPending = pendingValue === field.value;

  if (field.type === "url") {
    return (
      <div className="flex items-center justify-between gap-3 border-b border-border py-2">
        <div className="min-w-0">
          <p className="text-xs text-fg-muted">{field.label}</p>
          <a
            href={field.value}
            target="_blank"
            rel="noreferrer noopener"
            className="block truncate text-sm text-accent underline-offset-2 hover:underline"
          >
            {field.value}
          </a>
        </div>
        {canCopy && (
          <CopyButton
            label={`Copy ${field.label}`}
            onClick={() => copy(field.value)}
            remaining={isPending ? remaining : null}
          />
        )}
      </div>
    );
  }

  const masked = secret && !revealed;
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border py-2">
      <div className="min-w-0">
        <p className="text-xs text-fg-muted">{field.label}</p>
        <p
          className={`block truncate text-sm text-fg ${masked ? "font-mono tracking-widest" : ""}`}
        >
          {masked ? "•".repeat(Math.min(field.value.length, 16)) : field.value}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {secret && (
          <button
            type="button"
            onClick={() => setRevealed((r) => !r)}
            aria-pressed={revealed}
            aria-label={revealed ? `Hide ${field.label}` : `Reveal ${field.label}`}
            className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg"
          >
            {revealed ? "Hide" : "Reveal"}
          </button>
        )}
        {canCopy && (
          <CopyButton
            label={`Copy ${field.label}`}
            onClick={() => copy(field.value)}
            remaining={isPending ? remaining : null}
          />
        )}
      </div>
    </div>
  );
}

function CopyButton({
  label,
  onClick,
  remaining,
}: {
  label: string;
  onClick: () => Promise<void>;
  remaining: number | null;
}) {
  const [failed, setFailed] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      title={
        remaining !== null
          ? `Clipboard clears in ${remaining}s`
          : `Copies and auto-clears after ${AUTO_CLEAR_SECONDS}s`
      }
      onClick={() => {
        onClick().catch(() => setFailed(true));
      }}
      className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg"
    >
      {failed ? "Failed" : remaining !== null ? `${remaining}s` : "Copy"}
    </button>
  );
}

export default function ItemDetail({
  item,
  plain,
  decryptError,
  versions,
  versionsLoading,
  busy,
  canWrite,
  onToggleFavorite,
  onEdit,
  onTrash,
  onClose,
}: ItemDetailProps) {
  const { copy, remaining, pendingValue } = useAutoClearCopy();

  // Reset per-item UI state when the selection changes.
  useEffect(() => {
    /* nothing to reset today; hook keeps a single pending copy by design */
  }, [item?.id]);

  const keyHandler = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose],
  );
  useEffect(() => {
    window.addEventListener("keydown", keyHandler);
    return () => window.removeEventListener("keydown", keyHandler);
  }, [keyHandler]);

  if (!item) {
    return (
      <aside
        aria-label="Item detail"
        className="hidden h-full w-full items-center justify-center bg-bg p-6 text-center text-sm text-fg-muted md:flex"
      >
        Select an item to view its details.
      </aside>
    );
  }

  const tags = plain?.tags ?? [];
  return (
    <aside
      aria-label="Item detail"
      className="flex h-full w-full flex-col overflow-y-auto bg-bg"
    >
      <header className="flex items-start justify-between gap-2 border-b border-border p-4">
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wider text-fg-muted">
            {ITEM_TYPE_LABELS[item.itemType] ?? `Type ${item.itemType}`}
            {item.deletedAt ? " · in trash" : ""}
          </p>
          <h2 className="truncate text-lg font-semibold text-fg">
            {plain?.title ?? (decryptError ? "Decryption failed" : "Decrypting…")}
          </h2>
          <p className="mt-0.5 text-xs text-fg-muted">
            v{item.version} · updated {new Date(item.updatedAt).toLocaleString()}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            onClick={onToggleFavorite}
            disabled={!canWrite}
            aria-pressed={item.favorite}
            aria-label={item.favorite ? "Remove from favorites" : "Add to favorites"}
            className={`rounded-md px-2 py-1 text-lg leading-none disabled:opacity-40 ${
              item.favorite ? "text-accent" : "text-fg-muted hover:text-fg"
            }`}
          >
            {item.favorite ? "★" : "☆"}
          </button>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close detail"
            className="rounded-md px-2 py-1 text-sm text-fg-muted hover:bg-surface-hover hover:text-fg"
          >
            ✕
          </button>
        </div>
      </header>

      {decryptError && (
        <p role="alert" className="border-b border-border px-4 py-2 text-xs text-danger">
          {decryptError}
        </p>
      )}

      <div className="flex-1 px-4">
        {plain?.fields && plain.fields.length > 0 && (
          <div className="mt-1">
            {plain.fields.map((f, i) => (
              <FieldRow
                key={`${f.label}-${i}`}
                field={f}
                canCopy
                copy={copy}
                remaining={remaining}
                pendingValue={pendingValue}
              />
            ))}
          </div>
        )}

        {plain?.notes && (
          <div className="mt-4">
            <p className="text-xs text-fg-muted">Notes</p>
            <p className="mt-1 whitespace-pre-wrap text-sm text-fg">{plain.notes}</p>
          </div>
        )}

        {tags.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-1.5">
            {tags.map((t) => (
              <span
                key={t}
                className="rounded-full border border-border bg-surface px-2 py-0.5 text-xs text-fg-muted"
              >
                #{t}
              </span>
            ))}
          </div>
        )}

        <section className="mt-6" aria-label="Version history">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
            Version history
          </h3>
          {versionsLoading ? (
            <p className="mt-2 text-sm text-fg-muted">Loading versions…</p>
          ) : versions.length === 0 ? (
            <p className="mt-2 text-sm text-fg-muted">
              No prior versions (current is v{item.version}).
            </p>
          ) : (
            <ul className="mt-2 space-y-1">
              {versions.map((v) => (
                <li
                  key={v.version}
                  className="flex items-center justify-between rounded-md border border-border bg-surface px-2 py-1.5 text-xs"
                >
                  <span className="text-fg">v{v.version}</span>
                  <span className="text-fg-muted">
                    {new Date(v.createdAt).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <footer className="flex items-center gap-2 border-t border-border p-4">
        {canWrite && !item.deletedAt && (
          <>
            <button
              type="button"
              onClick={onEdit}
              disabled={busy}
              className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={onTrash}
              disabled={busy}
              className="rounded-md border border-danger px-3 py-1.5 text-sm text-danger hover:bg-surface-hover disabled:opacity-50"
            >
              Move to trash
            </button>
          </>
        )}
        {item.deletedAt && (
          <p className="text-xs text-fg-muted">
            This item is in the trash. Restore/purge endpoints are not part of
            the Phase 3 contract.
          </p>
        )}
        {busy && <span className="text-xs text-fg-muted">Working…</span>}
      </footer>
    </aside>
  );
}
