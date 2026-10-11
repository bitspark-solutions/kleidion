import type { BackgroundRequest, BackgroundResponse } from "../../lib/messages";

export async function send<T>(req: BackgroundRequest): Promise<T> {
  const res = (await chrome.runtime.sendMessage(req)) as
    | BackgroundResponse
    | undefined;
  if (!res) throw new Error("Kleidion background worker is not responding");
  if (!res.ok) throw new Error(res.error);
  return res.data as T;
}

export const errMsg = (e: unknown): string =>
  e instanceof Error ? e.message : String(e);
