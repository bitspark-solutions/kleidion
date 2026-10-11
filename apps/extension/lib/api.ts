/**
 * Singleton API client for the background worker. The token lives in the
 * unlocked session; content scripts never get it (they go through messaging).
 */
import { createApiClient } from "@kleidion/core";
import { API_BASE } from "./env";

let token = "";

export function setApiToken(t: string): void {
  token = t;
}

export const api = createApiClient({
  baseUrl: API_BASE,
  getToken: () => token,
});
