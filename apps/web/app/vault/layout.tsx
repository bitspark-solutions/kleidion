// /vault route layout. Wraps children in the vault context (in-memory key
// material only) and renders a locked placeholder when no vault key has been
// injected — the real lock/unlock screen belongs to the auth flow (/signin),
// owned by another agent.

import type { ReactNode } from "react";
import { VaultGate } from "./gate";

export const metadata = {
  title: "Vault — Kleidion",
};

export default function VaultLayout({ children }: { children: ReactNode }) {
  return <VaultGate>{children}</VaultGate>;
}
