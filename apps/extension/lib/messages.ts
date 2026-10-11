/**
 * Typed message protocol between popup / content scripts and the background
 * service worker. Background always replies with Response<T> via
 * sendResponse; handlers must return true (async).
 */

export type BackgroundRequest =
  | { type: "status" }
  | { type: "signin"; email: string; password: string; secretKey: string }
  | { type: "lock" }
  | { type: "match"; hostname: string }
  | { type: "list" }
  | { type: "credentials"; itemId: string }
  | { type: "totp"; itemId: string }
  | {
      type: "save";
      vaultId: string;
      title: string;
      username: string;
      password: string;
      hostname: string;
    }
  | { type: "vaults" };

export type BackgroundResponse =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

export interface StatusData {
  unlocked: boolean;
  email: string | null;
}

/** One decrypted login visible to UI (password is NOT included here). */
export interface MatchEntry {
  itemId: string;
  vaultId: string;
  vaultName: string;
  title: string;
  username: string;
  hasTotp: boolean;
}

export interface CredentialsData {
  username: string;
  password: string;
}

export interface TotpData {
  code: string;
  secondsRemaining: number;
  period: number;
}

export interface VaultOption {
  id: string;
  name: string;
  role: "admin" | "write" | "read";
  canWrite: boolean;
}
