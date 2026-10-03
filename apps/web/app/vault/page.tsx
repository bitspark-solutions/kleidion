// /vault — main vault screen (3-pane shell). The gate in layout.tsx handles
// the locked state; this page only renders when a vault key is in context.

import VaultShell from "@/components/vault/VaultShell";

export default function VaultPage() {
  return <VaultShell />;
}
