/** API base for the extension. Dev default is the compose-published port. */
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:18080";

/** Idle auto-lock, mirroring the web session (15 minutes). */
export const AUTO_LOCK_MS = 15 * 60 * 1000;
