"use client";

// Vault context — Phase 4 per-vault key model (ADR-006).
//
// The auth/session layer (apps/web/lib/session.ts) injects the unwrapped
// account key material into this provider as props; key material NEVER
// touches localStorage. On unlock we fetch the member's sealed vault keys
// (GET /v1/vaults -> wrappedVaultKey) and unwrap each with the X25519
// keypair, exposing getVaultKey(vaultId).
//
// Migration path for Phase 3 vaults (whose vault_keys row seals the account
// symKey, or predates wrapping): if unwrap fails or the row is missing we
// fall back to symKey and re-seal it for the keypair via
// PUT /v1/vaults/:id/wrapped-key. Items stay encrypted under the same bytes,
// so no item re-encryption is needed.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  decryptItem,
  fromBase64,
  toBase64,
  unwrapVaultKey,
  wrapVaultKey,
} from "@kleidion/crypto";
import { listVaults, setAuthTokenProvider, setWrappedKey } from "./vault-api";
import type { VaultMeta } from "./types";

export interface VaultContextValue {
  /** The selected vault's unlocked key (32 bytes), or null when unavailable. */
  getVaultKey: (vaultId: string) => Uint8Array | null;
  sessionToken: string | null;
  /** Authenticated user id — needed for member management (leave/remove). */
  userId: string | null;
  /** Real device id from SRP finish — required by POST /v1/sync/cursor. */
  deviceId: string | null;
  /** Master X25519 public key; needed to seal keys for new vaults/members. */
  masterPublicKey: Uint8Array | null;
  /** Account sym key; fallback key for Phase 3 vaults pre-re-wrap. */
  symKey: Uint8Array | null;
  /** Vaults as returned by the server (meta is encrypted). */
  vaults: VaultMeta[];
  /** Decrypted display name per vault id ("" until decrypted/failed). */
  vaultNames: Record<string, string>;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

const VaultContext = createContext<VaultContextValue | null>(null);

export interface VaultProviderProps {
  children: ReactNode;
  /** Bearer session token from the unlocked session. */
  sessionToken?: string | null;
  /** Authenticated user id from the unlocked session. */
  userId?: string | null;
  /** Device id returned by SRP finish. */
  deviceId?: string | null;
  /** X25519 private key (32-byte secret key) from KeyMaterial. */
  privateKey?: Uint8Array | null;
  /** X25519 master public key (32 bytes). */
  masterPublicKey?: Uint8Array | null;
  /** Account-wide symmetric key (Phase 3 vaults are encrypted under it). */
  symKey?: Uint8Array | null;
}

export function VaultProvider({
  children,
  sessionToken: initialToken = null,
  userId: initialUserId = null,
  deviceId: initialDeviceId = null,
  privateKey: initialPrivKey = null,
  masterPublicKey: initialPubKey = null,
  symKey: initialSymKey = null,
}: VaultProviderProps) {
  const sessionToken = initialToken;
  const userId = initialUserId;
  const deviceId = initialDeviceId;
  const privateKey = initialPrivKey;
  const masterPublicKey = initialPubKey;
  const symKey = initialSymKey;

  const [vaults, setVaults] = useState<VaultMeta[]>([]);
  const [vaultKeys, setVaultKeys] = useState<Record<string, Uint8Array>>({});
  const [vaultNames, setVaultNames] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);

  // Keep the API helper's token source in sync with the session token.
  useEffect(() => {
    setAuthTokenProvider(() => sessionToken);
  }, [sessionToken]);

  const refresh = useCallback(async () => {
    setReloadTick((t) => t + 1);
  }, []);

  // Load vaults whenever we have a token.
  useEffect(() => {
    if (!sessionToken) {
      setVaults([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    listVaults()
      .then((res) => {
        if (!cancelled) setVaults(res.vaults);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load vaults");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [sessionToken, reloadTick]);

  // Unseal every vault key for the current member (ADR-006 Phase 4 model).
  useEffect(() => {
    if (!sessionToken || !privateKey || !masterPublicKey || vaults.length === 0) {
      setVaultKeys({});
      return;
    }
    let cancelled = false;
    (async () => {
      const out: Record<string, Uint8Array> = {};
      await Promise.all(
        vaults.map(async (v) => {
          let key: Uint8Array | null = null;
          if (v.wrappedVaultKey) {
            try {
              key = await unwrapVaultKey(
                fromBase64(v.wrappedVaultKey),
                masterPublicKey,
                privateKey,
              );
            } catch {
              key = null; // wrong/corrupt seal -> migration fallback
            }
          }
          if (!key) {
            if (!symKey) return; // nothing sane to derive; vault stays locked
            // Phase 3 migration: the vault is encrypted under the account
            // symKey — re-seal it under this member's keypair (best effort).
            key = symKey;
            try {
              const wrapped = await wrapVaultKey(symKey, masterPublicKey);
              await setWrappedKey(v.id, toBase64(wrapped));
            } catch {
              /* cursor-style best effort; retried on next unlock */
            }
          }
          out[v.id] = key;
        }),
      );
      if (!cancelled) setVaultKeys(out);
    })().catch(() => {
      if (!cancelled) setVaultKeys({});
    });
    return () => {
      cancelled = true;
    };
  }, [sessionToken, vaults, privateKey, masterPublicKey, symKey]);

  const getVaultKey = useCallback(
    (vaultId: string) => vaultKeys[vaultId] ?? null,
    [vaultKeys],
  );

  // Decrypt vault names client-side (encryptedMeta holds {name,...}).
  useEffect(() => {
    if (Object.keys(vaultKeys).length === 0 || vaults.length === 0) {
      setVaultNames({});
      return;
    }
    let cancelled = false;
    (async () => {
      const names: Record<string, string> = {};
      await Promise.all(
        vaults.map(async (v) => {
          const key = vaultKeys[v.id];
          if (!key) {
            names[v.id] = "";
            return;
          }
          try {
            const json = await decryptItem(key, {
              ciphertext: fromBase64(v.encryptedMeta),
              nonce: fromBase64(v.nonce),
            });
            const meta = JSON.parse(json) as { name?: unknown };
            names[v.id] = typeof meta.name === "string" ? meta.name : "";
          } catch {
            names[v.id] = "";
          }
        }),
      );
      if (!cancelled) setVaultNames(names);
    })().catch(() => {
      /* decryption failures fall back to empty names */
    });
    return () => {
      cancelled = true;
    };
  }, [vaultKeys, vaults]);

  const value = useMemo<VaultContextValue>(
    () => ({
      getVaultKey,
      sessionToken,
      userId,
      deviceId,
      masterPublicKey,
      symKey,
      vaults,
      vaultNames,
      loading,
      error,
      refresh,
    }),
    [getVaultKey, sessionToken, userId, deviceId, masterPublicKey, symKey, vaults, vaultNames, loading, error, refresh],
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

/** Access the vault context; throws outside <VaultProvider>. */
export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used inside <VaultProvider>");
  return ctx;
}
