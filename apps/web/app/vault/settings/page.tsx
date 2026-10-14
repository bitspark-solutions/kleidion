// /vault/settings — account settings. Currently one section: Active sessions
// (session management + real, revoking sign-out). The VaultGate layout on
// /vault keeps this locked until the vault is unlocked.

import Link from "next/link";
import SessionsView from "@/components/vault/SessionsView";

export const metadata = { title: "Settings — Kleidion" };

export default function VaultSettingsPage() {
  return (
    <main className="mx-auto flex min-h-[100dvh] w-full max-w-2xl flex-col gap-5 px-4 py-8 text-fg">
      <header>
        <Link
          href="/vault"
          className="text-xs text-fg-muted hover:text-fg"
        >
          ← Back to vault
        </Link>
        <h1 className="mt-1 text-xl font-semibold">Settings</h1>
      </header>
      <SessionsView />
    </main>
  );
}
