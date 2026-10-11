"use client";

// Client-side gate for /vault: mounts VaultProvider with the unwrapped
// account key material from the in-memory session and shows the locked
// placeholder while no session exists. Phase 4 (ADR-006): the provider
// derives per-vault keys by unwrapping each vault's sealed key; the gate no
// longer passes a single vault key.

import type { ReactNode } from "react";
import Link from "next/link";
import { VaultProvider, useVault } from "@/lib/vault-context";
import { useSession, requireSession, isUnlocked } from "@/lib/session";

/**
 * Pull unlocked key material from the in-memory session store.
 * Returns nulls while locked so the gate renders the locked screen.
 */
function useSessionKeyMaterial(): {
  sessionToken: string | null;
  userId: string | null;
  deviceId: string | null;
  symKey: Uint8Array | null;
  privateKey: Uint8Array | null;
  masterPublicKey: Uint8Array | null;
} {
  // Subscribe so lock/unlock (incl. the 15-min idle auto-lock) re-renders.
  useSession();
  const none = {
    sessionToken: null,
    userId: null,
    deviceId: null,
    symKey: null,
    privateKey: null,
    masterPublicKey: null,
  };
  if (!isUnlocked()) return none;
  try {
    // requireSession() throws when locked; guarded above, but stay defensive.
    const s = requireSession();
    return {
      sessionToken: s.sessionToken,
      userId: s.userId,
      deviceId: s.deviceId,
      symKey: s.keys.symKey,
      privateKey: s.keys.privateKey,
      masterPublicKey: s.keys.masterPublicKey,
    };
  } catch {
    return none;
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
  const { sessionToken } = useVault();
  if (!sessionToken) return <LockedPlaceholder />;
  return <>{children}</>;
}

export function VaultGate({ children }: { children: ReactNode }) {
  const { sessionToken, userId, deviceId, symKey, privateKey, masterPublicKey } = useSessionKeyMaterial();
  return (
    <VaultProvider
      sessionToken={sessionToken}
      userId={userId}
      deviceId={deviceId}
      symKey={symKey}
      privateKey={privateKey}
      masterPublicKey={masterPublicKey}
    >
      <VaultGateInner>{children}</VaultGateInner>
    </VaultProvider>
  );
}
