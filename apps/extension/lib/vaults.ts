/**
 * Background-only vault index: unseals each vault key (ADR-006, mirroring the
 * web migration path), decrypts Login items into memory, and matches them to
 * a tab hostname. Plaintext lives in a short-TTL cache in the service worker
 * and is wiped on lock; passwords are only surfaced via the `credentials`
 * message for an explicitly matched origin.
 */
import {
  decryptItem,
  encryptItem,
  fromBase64,
  ready,
  searchHmac,
  unwrapVaultKey,
  wrapVaultKey,
  toBase64,
} from "@kleidion/crypto";
import { domainsEquivalent, type ItemField, type ItemPlain, type VaultMeta } from "@kleidion/core";
import { api } from "./api";
import type { MatchEntry, VaultOption } from "./messages";
import type { Session } from "./store";

/** A decrypted login. `password`/`totpValue` stay inside the background. */
export interface LoginEntry extends MatchEntry {
  password: string;
  totpValue: string | null;
  urls: string[];
}

interface Index {
  at: number;
  entries: LoginEntry[];
  vaults: VaultOption[];
  keys: Record<string, Uint8Array>;
  /** Vault key epoch at build time (ADR-008); detects a rotation elsewhere. */
  epochs: Record<string, number>;
}

let cache: Index | null = null;
const TTL_MS = 60_000;

export function invalidateIndex(): void {
  cache = null;
}

const LOGIN_ITEM_TYPE = 1;

/** Unseal every reachable vault key; personal vaults fall back to the symKey. */
async function unlockKeys(
  session: Session,
  vaults: VaultMeta[],
): Promise<Record<string, Uint8Array>> {
  await ready();
  const out: Record<string, Uint8Array> = {};
  for (const v of vaults) {
    let key: Uint8Array | null = null;
    if (v.wrappedVaultKey) {
      try {
        key = await unwrapVaultKey(
          fromBase64(v.wrappedVaultKey),
          session.masterPublicKey,
          session.privateKey,
        );
      } catch {
        key = null; // stale/wrong seal -> Phase 3 migration fallback (personal)
      }
    }
    if (!key) {
      if (v.kind !== "personal") continue; // shared vault stays locked
      key = session.symKey;
      try {
        const wrapped = await wrapVaultKey(session.symKey, session.masterPublicKey);
        await api.setWrappedKey(v.id, { wrappedVaultKey: toBase64(wrapped) });
      } catch {
        /* best effort; retried next unlock */
      }
    }
    out[v.id] = key;
  }
  return out;
}

async function decryptName(key: Uint8Array | undefined, v: VaultMeta): Promise<string> {
  if (!key) return "";
  try {
    const json = await decryptItem(key, {
      ciphertext: fromBase64(v.encryptedMeta),
      nonce: fromBase64(v.nonce),
    });
    const meta = JSON.parse(json) as { name?: unknown };
    return typeof meta.name === "string" ? meta.name : "";
  } catch {
    return "";
  }
}

function pickUsername(fields: ItemField[]): string {
  const byLabel = fields.find(
    (f) =>
      f.type !== "password" &&
      f.type !== "totp" &&
      f.type !== "url" &&
      /user|email|login|account/i.test(f.label),
  );
  if (byLabel) return byLabel.value;
  return fields.find((f) => f.type === "text")?.value ?? "";
}

export async function buildIndex(session: Session): Promise<Index> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache;

  const { vaults } = await api.listVaults();
  const keys = await unlockKeys(session, vaults);
  const names: Record<string, string> = {};
  const epochs: Record<string, number> = {};
  const options: VaultOption[] = [];
  for (const v of vaults) {
    names[v.id] = await decryptName(keys[v.id], v);
    epochs[v.id] = v.keyEpoch ?? 1;
    options.push({
      id: v.id,
      name: names[v.id],
      role: v.role,
      canWrite: v.role !== "read" && !!keys[v.id],
    });
  }

  await ready();
  const entries: LoginEntry[] = [];
  for (const v of vaults) {
    const key = keys[v.id];
    if (!key) continue;
    const { items } = await api.listItems({ vaultId: v.id });
    for (const it of items) {
      if (it.itemType !== LOGIN_ITEM_TYPE || it.deletedAt) continue;
      let plain: ItemPlain;
      try {
        const json = await decryptItem(key, {
          ciphertext: fromBase64(it.ciphertext),
          nonce: fromBase64(it.nonce),
        });
        plain = JSON.parse(json) as ItemPlain;
      } catch {
        continue; // decrypt failure: skip this item
      }
      const fields = plain.fields ?? [];
      const totpField = fields.find((f) => f.type === "totp");
      entries.push({
        itemId: it.id,
        vaultId: v.id,
        vaultName: names[v.id] ?? "",
        title: plain.title,
        username: pickUsername(fields),
        password: fields.find((f) => f.type === "password")?.value ?? "",
        hasTotp: !!totpField?.value,
        totpValue: totpField?.value ?? null,
        urls: fields.filter((f) => f.type === "url" && f.value).map((f) => f.value),
      });
    }
  }

  cache = { at: Date.now(), entries, vaults: options, keys, epochs };
  return cache;
}

/**
 * The key to encrypt a NEW item with, validated against the server's current
 * epoch. A rotation elsewhere (admin revoking a member, ADR-008) rewrites every
 * stored row under a fresh key — writing with our now-retired one would create
 * an item no remaining member can ever decrypt.
 */
async function writableKey(session: Session, vaultId: string): Promise<Uint8Array> {
  let idx = await buildIndex(session);
  const { vaults } = await api.listVaults();
  const live = vaults.find((v) => v.id === vaultId)?.keyEpoch ?? 1;
  if ((idx.epochs[vaultId] ?? 1) !== live) {
    invalidateIndex();
    idx = await buildIndex(session); // re-unwraps the new sealed key
  }
  const key = idx.keys[vaultId];
  if (!key) throw new Error("Vault is locked");
  if ((idx.epochs[vaultId] ?? 1) !== live) {
    throw new Error("This vault's key changed while you were signed in; lock and unlock again.");
  }
  return key;
}

export interface SaveLoginInput {
  vaultId: string;
  title: string;
  username: string;
  password: string;
  hostname: string;
}

/** Persist a newly captured login into a writable vault (client-side encrypt). */
export async function saveLogin(
  session: Session,
  input: SaveLoginInput,
): Promise<{ itemId: string }> {
  const idx = await buildIndex(session);
  const vault = idx.vaults.find((v) => v.id === input.vaultId);
  if (!vault?.canWrite) throw new Error("Vault is locked or read-only");
  const key = await writableKey(session, input.vaultId);
  const plain: ItemPlain = {
    title: input.title,
    fields: [
      { label: "Username", value: input.username, type: "text" },
      { label: "Password", value: input.password, type: "password" },
      { label: "Website", value: `https://${input.hostname}`, type: "url" },
    ],
  };
  const enc = await encryptItem(key, JSON.stringify(plain));
  const hmac = await searchHmac(key, plain.title);
  const { item } = await api.createItem({
    vaultId: input.vaultId,
    itemType: LOGIN_ITEM_TYPE,
    ciphertext: toBase64(enc.ciphertext),
    nonce: toBase64(enc.nonce),
    searchHmac: toBase64(hmac),
  });
  invalidateIndex();
  return { itemId: item.id };
}

/** Logins whose stored URLs (or domain-like title) match the tab host. */
export function matchForHost(entries: LoginEntry[], hostname: string): LoginEntry[] {
  return entries.filter(
    (e) =>
      e.urls.some((u) => domainsEquivalent(u, hostname)) ||
      domainsEquivalent(e.title, hostname),
  );
}

export function toMatchEntry(e: LoginEntry): MatchEntry {
  return {
    itemId: e.itemId,
    vaultId: e.vaultId,
    vaultName: e.vaultName,
    title: e.title,
    username: e.username,
    hasTotp: e.hasTotp,
  };
}
