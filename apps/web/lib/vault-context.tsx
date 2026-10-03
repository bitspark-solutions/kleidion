"use client";

// Minimal vault context for the Phase 3 web UI.
//
// The unlocked vault key + session token live in the auth agent's in-memory
// session store (apps/web/lib/session.ts — owned elsewhere, deliberately NOT
// imported here to avoid a build race). Integration point: whoever unlocks
// the vault renders <VaultProvider vaultKey={...} sessionToken={...}> (or
// calls setVaultKey/setSessionToken). When no key is present, the UI shows a
// locked placeholder — key material NEVER touches localStorage.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { decryptItem, fromBase64 } from "@kleidion/crypto";
import { listVaults, setAuthTokenProvider } from "./vault-api";
import type { VaultMeta } from "./types";

export interface VaultContextValue {
  /** Unlocked vault key (32 bytes) or null when locked. */
  vaultKey: Uint8Array | null;
  setVaultKey: (key: Uint8Array | null) => void;
  sessionToken: string | null;
  setSessionToken: (token: string | null) => void;
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
  /** Initial unlocked vault key, injected by the session/auth layer. */
  vaultKey?: Uint8Array | null;
  /** Initial bearer session token for API calls. */
  sessionToken?: string | null;
}

export function VaultProvider({
  children,
  vaultKey: initialKey = null,
  sessionToken: initialToken = null,
}: VaultProviderProps) {
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(initialKey);
  const [sessionToken, setSessionToken] = useState<string | null>(initialToken);
  const [vaults, setVaults] = useState<VaultMeta[]>([]);
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

  // Decrypt vault names client-side (encryptedMeta holds {name,...}).
  useEffect(() => {
    if (!vaultKey || vaults.length === 0) {
      setVaultNames({});
      return;
    }
    let cancelled = false;
    (async () => {
      const names: Record<string, string> = {};
      await Promise.all(
        vaults.map(async (v) => {
          try {
            const json = await decryptItem(vaultKey, {
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
  }, [vaultKey, vaults]);

  const value = useMemo<VaultContextValue>(
    () => ({
      vaultKey,
      setVaultKey,
      sessionToken,
      setSessionToken,
      vaults,
      vaultNames,
      loading,
      error,
      refresh,
    }),
    [vaultKey, sessionToken, vaults, vaultNames, loading, error, refresh],
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

/** Access the vault context; throws outside <VaultProvider>. */
export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used inside <VaultProvider>");
  return ctx;
}
