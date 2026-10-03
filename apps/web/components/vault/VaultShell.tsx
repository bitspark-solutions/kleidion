"use client";

// Main vault screen: 3-pane layout (sidebar / item list / detail) with all
// Phase 3 data wiring — item load + delta merge, client-side decrypt cache,
// client-side + server-side (searchHmac) search, create/edit/trash/favorite
// mutations with client-side encryption, and version history.
//
// Data fetching is plain React state + useEffect against lib/vault-api.ts
// (no TanStack Query — deliberately; call sites are isolated in this file so
// a query library can replace them later).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  decryptItem,
  encryptItem,
  fromBase64,
  ready,
  searchHmac,
  toBase64,
  wrapVaultKey,
} from "@kleidion/crypto";
import {
  createItem,
  createVault,
  deleteItem,
  itemVersions,
  listItems,
  postCursor,
  updateItem,
} from "@/lib/vault-api";
import { useVault } from "@/lib/vault-context";
import {
  ITEM_TYPES,
  type Item,
  type ItemPlain,
  type ItemVersionInfo,
} from "@/lib/types";
import VaultSidebar, {
  CATEGORY_ITEM_TYPE,
  type VaultCategory,
} from "./VaultSidebar";
import ItemList from "./ItemList";
import ItemDetail from "./ItemDetail";
import ItemEditor from "./ItemEditor";

// In-memory per-tab device id for the sync cursor (best-effort; the contract
// requires a devices-table uuid, so failures are swallowed).
const DEVICE_ID =
  typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : "web-shell";

function parsePlain(json: string): ItemPlain {
  const p = JSON.parse(json) as ItemPlain;
  if (typeof p.title !== "string") throw new Error("Malformed item plaintext");
  return p;
}

export default function VaultShell() {
  const {
    vaultKey,
    sessionToken,
    masterPublicKey,
    vaults,
    vaultNames,
    loading: vaultsLoading,
    error: vaultsError,
    refresh: refreshVaults,
  } = useVault();

  const [selectedVaultId, setSelectedVaultId] = useState<string | null>(null);
  const [category, setCategory] = useState<VaultCategory>("all");
  const [items, setItems] = useState<Item[]>([]);
  const [itemsLoading, setItemsLoading] = useState(false);
  const [itemsError, setItemsError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [serverMatchIds, setServerMatchIds] = useState<Set<string>>(new Set());
  const [searching, setSearching] = useState(false);
  const [versions, setVersions] = useState<ItemVersionInfo[]>([]);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [editor, setEditor] = useState<
    | { mode: "create"; itemType: number }
    | { mode: "edit"; item: Item; plain: ItemPlain }
    | null
  >(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  // Responsive pane control (mobile shows one pane at a time).
  const [mobilePane, setMobilePane] = useState<"list" | "detail">("list");

  const selectedVault = useMemo(
    () => vaults.find((v) => v.id === selectedVaultId) ?? null,
    [vaults, selectedVaultId],
  );
  const canWrite = selectedVault ? selectedVault.role !== "read" : false;

  // ---------------------------------------------------------------- items

  /** Upsert incoming items by id, keeping whichever row has the higher version. */
  const applyItems = useCallback((incoming: Item[]) => {
    setItems((prev) => {
      const byId = new Map(prev.map((it) => [it.id, it]));
      for (const it of incoming) {
        const existing = byId.get(it.id);
        if (!existing || it.version >= existing.version) byId.set(it.id, it);
      }
      return Array.from(byId.values());
    });
  }, []);

  const loadItems = useCallback(
    async (vaultId: string) => {
      setItemsLoading(true);
      setItemsError(null);
      try {
        const res = await listItems({ vaultId });
        setItems(res.items);
        // Best-effort sync cursor; deviceId validation may reject — ignore.
        postCursor({
          vaultId,
          lastVersion: res.serverVersion,
          deviceId: DEVICE_ID,
        }).catch(() => undefined);
      } catch (err) {
        setItemsError(err instanceof Error ? err.message : "Failed to load items");
      } finally {
        setItemsLoading(false);
      }
    },
    [],
  );

  // Auto-select the first vault once loaded.
  useEffect(() => {
    if (vaults.length > 0 && !selectedVaultId) setSelectedVaultId(vaults[0].id);
  }, [vaults, selectedVaultId]);

  useEffect(() => {
    if (!selectedVaultId || !sessionToken) {
      setItems([]);
      return;
    }
    setSelectedId(null);
    setQuery("");
    setCategory("all");
    setMobilePane("list");
    loadItems(selectedVaultId).catch(() => undefined);
  }, [selectedVaultId, sessionToken, loadItems]);

  // ------------------------------------------------------------ decryption

  // Decrypt cache keyed by `${id}:${version}` so re-renders/mutations don't
  // redo work. Plain objects only live in component state (memory).
  const plainCache = useRef(new Map<string, ItemPlain | null>());
  const errCache = useRef(new Map<string, string>());
  const [plainMap, setPlainMap] = useState<Record<string, ItemPlain | null>>({});
  const [decryptErrors, setDecryptErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!vaultKey) {
      setPlainMap({});
      setDecryptErrors({});
      return;
    }
    let cancelled = false;
    (async () => {
      await ready();
      const todo = items.filter(
        (it) => !plainCache.current.has(`${it.id}:${it.version}`),
      );
      await Promise.all(
        todo.map(async (it) => {
          const key = `${it.id}:${it.version}`;
          try {
            const json = await decryptItem(vaultKey, {
              ciphertext: fromBase64(it.ciphertext),
              nonce: fromBase64(it.nonce),
            });
            plainCache.current.set(key, parsePlain(json));
          } catch (err) {
            plainCache.current.set(key, null);
            errCache.current.set(
              key,
              err instanceof Error ? err.message : "Decryption failed",
            );
          }
        }),
      );
      if (cancelled) return;
      const map: Record<string, ItemPlain | null> = {};
      const errs: Record<string, string> = {};
      for (const it of items) {
        const key = `${it.id}:${it.version}`;
        map[it.id] = plainCache.current.get(key) ?? null;
        const e = errCache.current.get(key);
        if (e) errs[it.id] = e;
      }
      setPlainMap(map);
      setDecryptErrors(errs);
    })().catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [vaultKey, items]);

  // ---------------------------------------------------------------- search

  // Server-side exact-title search via searchHmac, debounced. Results are
  // merged into the item set (tombstones included) and their ids whitelisted
  // so ItemList keeps them visible even if client-side filtering would drop
  // them (e.g. decrypt failure).
  useEffect(() => {
    const q = query.trim();
    if (!vaultKey || !selectedVaultId || q.length < 2) {
      setServerMatchIds(new Set());
      setSearching(false);
      return;
    }
    setSearching(true);
    const timer = setTimeout(() => {
      (async () => {
        try {
          await ready();
          const hmac = await searchHmac(vaultKey, q);
          const res = await listItems({
            vaultId: selectedVaultId,
            searchHmac: toBase64(hmac),
          });
          applyItems(res.items);
          setServerMatchIds(new Set(res.items.map((i) => i.id)));
        } catch {
          setServerMatchIds(new Set());
        } finally {
          setSearching(false);
        }
      })().catch(() => undefined);
    }, 300);
    return () => clearTimeout(timer);
  }, [query, vaultKey, selectedVaultId, applyItems]);

  // -------------------------------------------------------------- versions

  useEffect(() => {
    if (!selectedId) {
      setVersions([]);
      return;
    }
    let cancelled = false;
    setVersionsLoading(true);
    itemVersions(selectedId)
      .then((res) => {
        if (!cancelled) setVersions(res.versions);
      })
      .catch(() => {
        if (!cancelled) setVersions([]);
      })
      .finally(() => {
        if (!cancelled) setVersionsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, items]); // re-fetch after mutations bump versions

  // ------------------------------------------------------------- filtering

  const categoryItems = useMemo(() => {
    if (category === "trash") return items.filter((it) => it.deletedAt !== null);
    const live = items.filter((it) => it.deletedAt === null);
    if (category === "favorites") return live.filter((it) => it.favorite);
    const type = CATEGORY_ITEM_TYPE[category];
    if (type !== undefined) return live.filter((it) => it.itemType === type);
    return live;
  }, [items, category]);

  const counts = useMemo(() => {
    const live = items.filter((it) => it.deletedAt === null);
    return {
      all: live.length,
      logins: live.filter((it) => it.itemType === ITEM_TYPES.Login).length,
      notes: live.filter((it) => it.itemType === ITEM_TYPES.SecureNote).length,
      cards: live.filter((it) => it.itemType === ITEM_TYPES.Card).length,
      identities: live.filter((it) => it.itemType === ITEM_TYPES.Identity).length,
      favorites: live.filter((it) => it.favorite).length,
      trash: items.length - live.length,
    } satisfies Partial<Record<VaultCategory, number>>;
  }, [items]);

  const selectedItem = useMemo(
    () => items.find((it) => it.id === selectedId) ?? null,
    [items, selectedId],
  );

  // ------------------------------------------------------------- mutations

  const handleSave = useCallback(
    async (itemType: number, plain: ItemPlain) => {
      if (!vaultKey || !selectedVaultId) {
        setSaveError("Vault is locked.");
        return;
      }
      setSaving(true);
      setSaveError(null);
      try {
        await ready();
        const json = JSON.stringify(plain);
        const enc = await encryptItem(vaultKey, json);
        const hmac = await searchHmac(vaultKey, plain.title);
        const payload = {
          vaultId: selectedVaultId,
          itemType,
          ciphertext: toBase64(enc.ciphertext),
          nonce: toBase64(enc.nonce),
          searchHmac: toBase64(hmac),
        };
        let saved: Item;
        if (editor?.mode === "edit") {
          const res = await updateItem(editor.item.id, {
            ...payload,
            favorite: editor.item.favorite,
          });
          saved = res.item;
        } else {
          const res = await createItem(payload);
          saved = res.item;
        }
        applyItems([saved]);
        // Cache the plaintext we just wrote so the detail pane renders
        // instantly without a decrypt round-trip.
        plainCache.current.set(`${saved.id}:${saved.version}`, plain);
        setPlainMap((m) => ({ ...m, [saved.id]: plain }));
        setEditor(null);
        setSelectedId(saved.id);
        if (window.innerWidth < 768) setMobilePane("detail");
      } catch (err) {
        setSaveError(err instanceof Error ? err.message : "Save failed");
      } finally {
        setSaving(false);
      }
    },
    [vaultKey, selectedVaultId, editor, applyItems],
  );

  const handleToggleFavorite = useCallback(
    async (item: Item) => {
      if (!canWrite) return;
      setActionError(null);
      setBusy(true);
      try {
        const res = await updateItem(item.id, {
          vaultId: item.vaultId,
          itemType: item.itemType,
          ciphertext: item.ciphertext,
          nonce: item.nonce,
          searchHmac: item.searchHmac,
          favorite: !item.favorite,
        });
        applyItems([res.item]);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Failed to update favorite");
      } finally {
        setBusy(false);
      }
    },
    [canWrite, applyItems],
  );

  const handleTrash = useCallback(
    async (item: Item) => {
      if (!canWrite) return;
      setActionError(null);
      setBusy(true);
      try {
        const res = await deleteItem(item.id);
        applyItems([res.item]);
        setCategory("trash");
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Failed to trash item");
      } finally {
        setBusy(false);
      }
    },
    [canWrite, applyItems],
  );

  const handleCreateVault = useCallback(
    async (name: string) => {
      if (!vaultKey) throw new Error("Vault is locked");
      if (!masterPublicKey) throw new Error("Missing master public key — cannot seal the vault key");
      await ready();
      const enc = await encryptItem(vaultKey, JSON.stringify({ name }));
      // Per ADR-006 the Phase 3 vault key IS the account symKey, so seal that
      // same key to our own master public key for the vault_keys row.
      const wrapped = await wrapVaultKey(vaultKey, masterPublicKey);
      await createVault({
        kind: "personal",
        encryptedMeta: toBase64(enc.ciphertext),
        nonce: toBase64(enc.nonce),
        wrappedVaultKey: toBase64(wrapped),
      });
      await refreshVaults();
    },
    [vaultKey, masterPublicKey, refreshVaults],
  );

  // ---------------------------------------------------------------- render

  const sidebarVaults = useMemo(
    () =>
      vaults.map((v) => ({
        id: v.id,
        name: vaultNames[v.id] ?? "",
        kind: v.kind,
        role: v.role,
      })),
    [vaults, vaultNames],
  );

  const closeDetail = useCallback(() => {
    setSelectedId(null);
    setMobilePane("list");
  }, []);

  const selectItem = useCallback((id: string) => {
    setSelectedId(id);
    if (window.innerWidth < 768) setMobilePane("detail");
  }, []);

  const errorBanner = vaultsError ?? itemsError ?? actionError;

  return (
    <div className="flex h-[100dvh] flex-col overflow-hidden bg-bg text-fg">
      {errorBanner && (
        <p role="alert" className="border-b border-border bg-surface px-4 py-2 text-xs text-danger">
          {errorBanner}
        </p>
      )}
      <div className="flex min-h-0 flex-1">
        {/* Sidebar: always visible from md; drawer-ish full height on mobile via toggle pane. */}
        <div className="hidden w-60 shrink-0 md:block">
          <VaultSidebar
            vaults={sidebarVaults}
            selectedVaultId={selectedVaultId}
            onSelectVault={(id) => setSelectedVaultId(id)}
            category={category}
            onSelectCategory={(c) => {
              setCategory(c);
              setQuery("");
            }}
            counts={counts}
            onCreateVault={handleCreateVault}
            canWrite
          />
        </div>

        {/* Item list */}
        <div
          className={`min-w-0 flex-1 md:max-w-sm md:shrink-0 md:flex-none md:w-80 ${
            mobilePane === "list" ? "block" : "hidden md:block"
          }`}
        >
          <ItemList
            items={categoryItems}
            plainMap={plainMap}
            selectedId={selectedId}
            onSelect={selectItem}
            onToggleFavorite={(it) => handleToggleFavorite(it).catch(() => undefined)}
            query={query}
            onQueryChange={setQuery}
            serverMatchIds={serverMatchIds}
            searching={searching}
            loading={itemsLoading || vaultsLoading}
            error={null}
            onNewItem={() => {
              setSaveError(null);
              setEditor({
                mode: "create",
                itemType: CATEGORY_ITEM_TYPE[category] ?? ITEM_TYPES.Login,
              });
            }}
            canWrite={canWrite}
            emptyHint={
              selectedVaultId
                ? undefined
                : "Create a vault in the sidebar to get started."
            }
          />
        </div>

        {/* Detail pane */}
        <div
          className={`min-w-0 flex-1 ${
            mobilePane === "detail" ? "block" : "hidden md:block"
          }`}
        >
          <ItemDetail
            item={selectedItem}
            plain={selectedItem ? plainMap[selectedItem.id] ?? null : null}
            decryptError={selectedItem ? decryptErrors[selectedItem.id] ?? null : null}
            versions={versions}
            versionsLoading={versionsLoading}
            busy={busy}
            canWrite={canWrite}
            onToggleFavorite={() => {
              if (selectedItem)
                handleToggleFavorite(selectedItem).catch(() => undefined);
            }}
            onEdit={() => {
              if (!selectedItem) return;
              const plain = plainMap[selectedItem.id] ?? null;
              if (!plain) {
                setActionError("Cannot edit: item failed to decrypt.");
                return;
              }
              setSaveError(null);
              setEditor({ mode: "edit", item: selectedItem, plain });
            }}
            onTrash={() => {
              if (selectedItem) handleTrash(selectedItem).catch(() => undefined);
            }}
            onClose={closeDetail}
          />
        </div>
      </div>

      {editor && (
        <ItemEditor
          initial={editor.mode === "edit" ? editor.plain : null}
          initialItemType={
            editor.mode === "create" ? editor.itemType : editor.item.itemType
          }
          itemTypeLocked={editor.mode === "edit"}
          saving={saving}
          saveError={saveError}
          onSave={handleSave}
          onCancel={() => setEditor(null)}
        />
      )}
    </div>
  );
}
