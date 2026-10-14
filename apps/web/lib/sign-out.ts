// Shared sign-out: POST /v1/auth/logout (server revokes THIS session, so the
// token dies immediately), then wipe the in-memory key material. Callers
// redirect to /signin afterwards. A failed logout call is swallowed — if the
// token is already dead/expired there is nothing left to revoke, and the
// local lock must still happen.

import { logout } from "@/lib/vault-api";
import { lock } from "@/lib/session";

export async function signOutCurrentDevice(): Promise<void> {
  try {
    await logout();
  } catch {
    // Token already invalid server-side (expired/revoked) — proceed to lock.
  }
  lock();
}
