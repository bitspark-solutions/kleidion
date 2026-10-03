"use client";

// Copy a secret to the clipboard and auto-clear it after a delay, exposing the
// remaining seconds so callers can render a countdown (contract: "copy to
// clipboard with 30s auto-clear + visual countdown").
//
// Only ONE pending copy is tracked: copying again replaces the timer. The
// clipboard is cleared only if it still contains the value we copied, so we
// never clobber something the user copied elsewhere.

import { useCallback, useEffect, useRef, useState } from "react";

export const AUTO_CLEAR_SECONDS = 30;

export interface AutoClearCopy {
  /** Copy `value` and start the auto-clear countdown. */
  copy: (value: string) => Promise<void>;
  /** Seconds remaining until the clipboard is cleared; null when idle. */
  remaining: number | null;
  /** The value currently pending auto-clear (null when idle). */
  pendingValue: string | null;
  /** Cancel the pending clear without wiping the clipboard. */
  cancel: () => void;
}

export function useAutoClearCopy(
  seconds: number = AUTO_CLEAR_SECONDS,
): AutoClearCopy {
  const [remaining, setRemaining] = useState<number | null>(null);
  const [pendingValue, setPendingValue] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pendingRef = useRef<string | null>(null);

  const stopTimer = useCallback(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const cancel = useCallback(() => {
    stopTimer();
    pendingRef.current = null;
    setPendingValue(null);
    setRemaining(null);
  }, [stopTimer]);

  const copy = useCallback(
    async (value: string) => {
      await navigator.clipboard.writeText(value);
      stopTimer();
      pendingRef.current = value;
      setPendingValue(value);
      setRemaining(seconds);
      intervalRef.current = setInterval(() => {
        setRemaining((prev) => {
          if (prev === null) return null;
          if (prev <= 1) {
            // Time's up: clear the clipboard if it still holds our secret.
            const secret = pendingRef.current;
            stopTimer();
            pendingRef.current = null;
            setPendingValue(null);
            if (secret !== null) {
              navigator.clipboard
                .readText()
                .then((current) => {
                  if (current === secret) return navigator.clipboard.writeText("");
                })
                .catch(() => {
                  // Clipboard read blocked (permissions/focus) — best effort:
                  // write empty only if we can't verify is unsafe, so skip.
                });
            }
            return null;
          }
          return prev - 1;
        });
      }, 1000);
    },
    [seconds, stopTimer],
  );

  // Clean up on unmount; do NOT clear the clipboard here (component unmount
  // shouldn't wipe a copy the user may still need within the window).
  useEffect(() => stopTimer, [stopTimer]);

  return { copy, remaining, pendingValue, cancel };
}
