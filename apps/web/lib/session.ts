// In-memory session store. Holds the session token, Account Unlock Key (AUK)
// and unwrapped key material in MODULE SCOPE ONLY — never localStorage/
// sessionStorage/cookies (zero-knowledge: a reload locks the vault).
//
// Also owns the 15-minute idle auto-lock timer. Callers start/stop it via
// startAutoLock()/stopAutoLock(); user activity resets it via touch()
// (activity listeners are attached while the timer runs).

"use client";

import { useSyncExternalStore } from "react";

/** Auto-lock after 15 minutes of idle. */
export const AUTO_LOCK_MS = 15 * 60 * 1000;

/** Unwrapped key material held in memory while unlocked. */
export interface KeyMaterial {
  /** X25519 master public key (32 bytes). */
  masterPublicKey: Uint8Array;
  /** X25519 seed (32 bytes) — keypair is re-derivable from it. */
  privateKeySeed: Uint8Array;
  /** X25519 private key (64 bytes, sodium layout). */
  privateKey: Uint8Array;
  /** Vault-independent symmetric key (32 bytes), AUK-wrapped at rest. */
  symKey: Uint8Array;
  /** Account Unlock Key (32 bytes). */
  auk: Uint8Array;
}

/** Full internal session (secrets). Never expose directly to React state. */
export interface Session {
  sessionToken: string;
  userId: string;
  email: string;
  keys: KeyMaterial;
  unlockedAt: number;
}

/** Public, non-secret snapshot for UI rendering. */
export interface SessionSnapshot {
  unlocked: boolean;
  userId: string | null;
  email: string | null;
  unlockedAt: number | null;
}

let session: Session | null = null;
let snapshot: SessionSnapshot = { unlocked: false, userId: null, email: null, unlockedAt: null };
/** Non-secret email remembered after lock, so the lock screen can prefill. */
let lastEmail = "";

type Listener = (s: SessionSnapshot) => void;
const listeners = new Set<Listener>();

function publish() {
  snapshot = session
    ? { unlocked: true, userId: session.userId, email: session.email, unlockedAt: session.unlockedAt }
    : { unlocked: false, userId: null, email: null, unlockedAt: null };
  for (const fn of listeners) fn(snapshot);
}

/** Subscribe to session changes. Returns an unsubscribe function. */
export function subscribeSession(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function getSessionSnapshot(): SessionSnapshot {
  return snapshot;
}

/** React hook re-rendering on unlock/lock transitions. */
export function useSession(): SessionSnapshot {
  return useSyncExternalStore(subscribeSession, getSessionSnapshot, () => EMPTY_SNAPSHOT);
}
const EMPTY_SNAPSHOT: SessionSnapshot = { unlocked: false, userId: null, email: null, unlockedAt: null };

/** Store a freshly-unlocked session and start the idle auto-lock timer. */
export function setSession(s: Session): void {
  session = s;
  lastEmail = s.email;
  publish();
  startAutoLock();
}

/** Access the secrets. Throws when locked — callers must handle the lock. */
export function requireSession(): Session {
  if (!session) throw new Error("Vault is locked");
  touch(); // any use of key material counts as activity
  return session;
}

/** True while unlocked. */
export function isUnlocked(): boolean {
  return session !== null;
}

/** Non-secret email of the last unlocked account (for lock-screen prefill). */
export function getLastEmail(): string {
  return lastEmail;
}

/** Wipe all secret material from memory and notify subscribers. */
export function lock(): void {
  stopAutoLock();
  if (session) {
    const k = session.keys;
    k.auk.fill(0);
    k.symKey.fill(0);
    k.privateKey.fill(0);
    k.privateKeySeed.fill(0);
    // masterPublicKey is not secret; wipe anyway for hygiene.
    k.masterPublicKey.fill(0);
  }
  session = null;
  publish();
}

// ---------------------------------------------------------------------------
// Idle auto-lock timer
// ---------------------------------------------------------------------------

let lockTimer: ReturnType<typeof setTimeout> | null = null;
let activityBound = false;
let lastTouch = 0;

const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"] as const;

function onActivity() {
  touch();
}

function bindActivity() {
  if (activityBound || typeof window === "undefined") return;
  for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, onActivity, { passive: true });
  activityBound = true;
}

function unbindActivity() {
  if (!activityBound || typeof window === "undefined") return;
  for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, onActivity);
  activityBound = false;
}

/** Reset the idle countdown (throttled to once per 5s). */
export function touch(): void {
  if (!session || !lockTimer) return;
  const now = Date.now();
  if (now - lastTouch < 5000) return;
  lastTouch = now;
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}

/** Start (or restart) the 15-minute idle auto-lock. */
export function startAutoLock(): void {
  if (lockTimer) clearTimeout(lockTimer);
  bindActivity();
  lastTouch = Date.now();
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}

/** Stop the auto-lock timer (e.g. tests, or explicit user preference). */
export function stopAutoLock(): void {
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = null;
  unbindActivity();
}
