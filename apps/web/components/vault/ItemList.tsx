"use client";

// Center pane: search box + item rows. Search filters client-side over
// decrypted titles (instant) AND fires the server-side searchHmac exact-match
// path (debounced) — server matches are merged in, since the client-side
// filter alone would miss items whose plaintext failed to decrypt.

import { useEffect, useState } from "react";
import { ITEM_TYPE_LABELS, type Item, type ItemPlain } from "@/lib/types";

export interface ItemListProps {
  items: Item[];
  /** Decrypted plaintext per item id (null = decrypt failed / pending). */
  plainMap: Record<string, ItemPlain | null>;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onToggleFavorite: (item: Item) => void;
  query: string;
  onQueryChange: (q: string) => void;
  /** Ids matched by the server-side searchHmac path (exact title match). */
  serverMatchIds: Set<string>;
  searching: boolean;
  loading: boolean;
  error: string | null;
  /** Extra ids to include even if the client-side filter drops them. */
  onNewItem: () => void;
  canWrite: boolean;
  emptyHint?: string;
}

const TYPE_GLYPHS: Record<number, string> = {
  1: "🔑",
  2: "📝",
  3: "💳",
  4: "🪪",
};

function subtitle(item: Item, plain: ItemPlain | null): string {
  if (!plain) return ITEM_TYPE_LABELS[item.itemType] ?? "Encrypted item";
  const first = plain.fields?.[0];
  if (first && first.value) return `${first.label}: ${first.value}`;
  if (plain.notes) return plain.notes.slice(0, 60);
  return ITEM_TYPE_LABELS[item.itemType] ?? "";
}

export default function ItemList({
  items,
  plainMap,
  selectedId,
  onSelect,
  onToggleFavorite,
  query,
  onQueryChange,
  serverMatchIds,
  searching,
  loading,
  error,
  onNewItem,
  canWrite,
  emptyHint,
}: ItemListProps) {
  const [localQuery, setLocalQuery] = useState(query);

  // Keep local input in sync when the shell resets the query (e.g. vault switch).
  useEffect(() => setLocalQuery(query), [query]);

  const q = localQuery.trim().toLowerCase();
  const visible =
    q === ""
      ? items
      : items.filter((it) => {
          if (serverMatchIds.has(it.id)) return true;
          const plain = plainMap[it.id];
          if (!plain) return false;
          return (
            plain.title.toLowerCase().includes(q) ||
            (plain.notes ?? "").toLowerCase().includes(q) ||
            (plain.tags ?? []).some((t) => t.toLowerCase().includes(q)) ||
            (plain.fields ?? []).some(
              (f) =>
                f.label.toLowerCase().includes(q) ||
                f.value.toLowerCase().includes(q),
            )
          );
        });

  return (
    <section
      aria-label="Items"
      className="flex h-full w-full flex-col border-r border-border bg-bg"
    >
      <div className="flex items-center gap-2 border-b border-border p-3">
        <div className="relative flex-1">
          <input
            type="search"
            value={localQuery}
            onChange={(e) => {
              setLocalQuery(e.target.value);
              onQueryChange(e.target.value);
            }}
            placeholder="Search items…"
            aria-label="Search items"
            className="w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none"
          />
          {searching && (
            <span className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-fg-muted">
              …
            </span>
          )}
        </div>
        {canWrite && (
          <button
            type="button"
            onClick={onNewItem}
            className="shrink-0 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg hover:opacity-90"
          >
            + New
          </button>
        )}
      </div>

      {error && (
        <p role="alert" className="border-b border-border px-3 py-2 text-xs text-danger">
          {error}
        </p>
      )}

      <div className="flex-1 overflow-y-auto">
        {loading && (
          <p className="p-4 text-sm text-fg-muted">Loading items…</p>
        )}
        {!loading && visible.length === 0 && (
          <p className="p-4 text-sm text-fg-muted">
            {emptyHint ?? (q ? "No items match your search." : "No items yet.")}
          </p>
        )}
        <ul>
          {visible.map((item) => {
            const plain = plainMap[item.id] ?? null;
            const selected = item.id === selectedId;
            return (
              <li key={item.id}>
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => onSelect(item.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect(item.id);
                    }
                  }}
                  aria-current={selected}
                  className={`flex cursor-pointer items-center gap-3 border-b border-border px-3 py-2.5 transition-colors hover:bg-surface ${
                    selected ? "bg-surface-hover" : ""
                  } ${item.deletedAt ? "opacity-60" : ""}`}
                >
                  <span aria-hidden className="text-lg">
                    {TYPE_GLYPHS[item.itemType] ?? "•"}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-baseline gap-2">
                      <span className="truncate text-sm font-medium text-fg">
                        {plain?.title ?? "Untitled"}
                      </span>
                      <span className="shrink-0 text-[10px] text-fg-muted">
                        v{item.version}
                      </span>
                      {item.deletedAt && (
                        <span className="shrink-0 rounded-full border border-border px-1.5 text-[10px] text-fg-muted">
                          trashed
                        </span>
                      )}
                    </span>
                    <span className="block truncate text-xs text-fg-muted">
                      {subtitle(item, plain)}
                    </span>
                  </span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleFavorite(item);
                    }}
                    disabled={!canWrite}
                    aria-label={item.favorite ? "Remove from favorites" : "Add to favorites"}
                    aria-pressed={item.favorite}
                    className={`shrink-0 text-base leading-none disabled:opacity-40 ${
                      item.favorite ? "text-accent" : "text-fg-muted hover:text-fg"
                    }`}
                  >
                    {item.favorite ? "★" : "☆"}
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
