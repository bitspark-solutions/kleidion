/**
 * Unlocked-session persistence for the MV3 service worker.
 *
 * chrome.storage.session is the only sanctioned store: memory for the browser
 * session, wiped on browser exit. Firefox has no storage.session — we fall
 * back to module-scope memory, which is strictly weaker (the SW can be
 * recycled -> effectively a shorter session), never weaker on the disk axis.
 * Keys never touch storage.local/sync.
 */
import { fromBase64, toBase64 } from "@kleidion/crypto";
import { AUTO_LOCK_MS } from "./env";

export interface Session {
  sessionToken: string;
  userId: string;
  email: string;
  deviceId: string;
  masterPublicKey: Uint8Array;
  privateKey: Uint8Array;
  symKey: Uint8Array;
}

interface StoredSession {
  sessionToken: string;
  userId: string;
  email: string;
  deviceId: string;
  masterPublicKey: string;
  privateKey: string;
  symKey: string;
}

const SESSION_KEY = "kleidion.session";
const ACTIVITY_KEY = "kleidion.lastActivity";

/** Firefox fallback when storage.session is unavailable. */
let memoryFallback: StoredSession | null = null;
let memoryActivity = 0;

function hasStorageSession(): boolean {
  return typeof chrome !== "undefined" && !!chrome.storage?.session;
}

function serialize(s: Session): StoredSession {
  return {
    sessionToken: s.sessionToken,
    userId: s.userId,
    email: s.email,
    deviceId: s.deviceId,
    masterPublicKey: toBase64(s.masterPublicKey),
    privateKey: toBase64(s.privateKey),
    symKey: toBase64(s.symKey),
  };
}

function deserialize(w: StoredSession): Session {
  return {
    sessionToken: w.sessionToken,
    userId: w.userId,
    email: w.email,
    deviceId: w.deviceId,
    masterPublicKey: fromBase64(w.masterPublicKey),
    privateKey: fromBase64(w.privateKey),
    symKey: fromBase64(w.symKey),
  };
}

export async function storeSession(s: Session): Promise<void> {
  const w = serialize(s);
  if (hasStorageSession()) {
    await chrome.storage.session.set({ [SESSION_KEY]: w });
  } else {
    memoryFallback = w;
  }
  await touchActivity();
}

export async function loadStoredSession(): Promise<Session | null> {
  let w: StoredSession | undefined;
  if (hasStorageSession()) {
    const obj = await chrome.storage.session.get(SESSION_KEY);
    w = obj[SESSION_KEY] as StoredSession | undefined;
  } else {
    w = memoryFallback ?? undefined;
  }
  if (!w) return null;
  try {
    return deserialize(w);
  } catch {
    await clearStoredSession();
    return null;
  }
}

export async function clearStoredSession(): Promise<void> {
  if (hasStorageSession()) {
    await chrome.storage.session.remove(SESSION_KEY);
  } else {
    memoryFallback = null;
  }
  memoryActivity = 0;
}

/** Record user activity for the idle auto-lock (throttled to 5s). */
let lastTouchMs = 0;
export async function touchActivity(): Promise<void> {
  const now = Date.now();
  if (now - lastTouchMs < 5000) return;
  lastTouchMs = now;
  if (hasStorageSession()) {
    await chrome.storage.session.set({ [ACTIVITY_KEY]: now });
  } else {
    memoryActivity = now;
  }
}

/** Milliseconds since the last recorded activity. */
export async function idleMs(): Promise<number> {
  let last = 0;
  if (hasStorageSession()) {
    const obj = await chrome.storage.session.get(ACTIVITY_KEY);
    last = (obj[ACTIVITY_KEY] as number | undefined) ?? 0;
  } else {
    last = memoryActivity;
  }
  return last === 0 ? Infinity : Date.now() - last;
}

export function isExpired(idle: number): boolean {
  return idle > AUTO_LOCK_MS;
}
