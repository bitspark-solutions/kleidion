"use client";

// Client-side gate for /vault: mounts VaultProvider and shows the locked
// placeholder when there is no vault key in context. The unlocked vault key +
// session token are injected by the auth/session layer (apps/web/lib/session.ts,
// owned by another agent). Until that integration exists, nothing provides a
// key, so /vault renders the locked state with a link to /signin.
//
// INTEGRATION CONTRACT for the auth agent — either:
//   1) render <VaultProvider vaultKey={key} sessionToken={token}> above this
//      tree (e.g. in a client wrapper around the app), or
//   2) swap the `useSessionKeyMaterial()` call below for an import from
//      lib/session once that module lands.

import type { ReactNode } from "react";
import Link from "next/link";
import { VaultProvider, useVault } from "@/lib/vault-context";
import { useSession, requireSession, isUnlocked } from "@/lib/session";

// KEY MODEL — Phase 3 decision (documented deviation from the contract):
//   The contract (§3) specifies a per-vault random key wrapped with each
//   member's X25519 public key, which is what makes *shared* vaults possible.
//   The Phase 3 UI threads a SINGLE symmetric key through context
//   (VaultProvider vaultKey=...) and uses it to decrypt vault metadata and
//   item ciphertexts. Phase 3 ships personal vaults only (one member), so we
//   bridge by passing the account-wide `symKey` from the unlocked session.
//   Coherent end-to-end, all crypto stays in @kleidion/crypto.
//
//   TODO(Phase 4 — shared vaults): replace the single-key context with a
//   per-vault key map. On unlock, fetch vault_keys rows, unwrap each
//   wrapped_vault_key with crypto_box_seal_open, expose { [vaultId]: key },
//   and select by vaultId in item ops. The server already has the vault_keys
//   table plus role checks.

/**
 * Pull unlocked key material from the in-memory session store.
 * Returns null key/token while locked so the gate renders the locked screen.
 */
function useSessionKeyMaterial(): {
  vaultKey: Uint8Array | null;
  sessionToken: string | null;
} {
  // Subscribe so lock/unlock (incl. the 15-min idle auto-lock) re-renders.
  useSession();
  if (!isUnlocked()) return { vaultKey: null, sessionToken: null };
  try {
    // requireSession() throws when locked; guarded above, but stay defensive.
    const s = requireSession();
    return { vaultKey: s.keys.symKey, sessionToken: s.sessionToken };
  } catch {
    return { vaultKey: null, sessionToken: null };
  }
}

function LockedPlaceholder() {
  return (
    <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-4 px-6 text-center">
      <span
        aria-hidden
        className="grid size-12 place-items-center rounded-xl bg-surface text-2xl"
      >
        🔒
      </span>
      <h1 className="text-xl font-semibold text-fg">Vault is locked</h1>
      <p className="max-w-sm text-sm text-fg-muted">
        Unlock your vault to view your items. Your keys never leave this
        device — sign in to decrypt your vault key in memory.
      </p>
      <Link
        href="/signin"
        className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:opacity-90"
      >
        Go to sign in
      </Link>
    </main>
  );
}

function VaultGateInner({ children }: { children: ReactNode }) {
  const { vaultKey, sessionToken } = useVault();
  if (!vaultKey || !sessionToken) return <LockedPlaceholder />;
  return <>{children}</>;
}

export function VaultGate({ children }: { children: ReactNode }) {
  const { vaultKey, sessionToken } = useSessionKeyMaterial();
  return (
    <VaultProvider vaultKey={vaultKey} sessionToken={sessionToken}>
      <VaultGateInner>{children}</VaultGateInner>
    </VaultProvider>
  );
}
