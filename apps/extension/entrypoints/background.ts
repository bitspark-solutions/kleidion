/**
 * MV3 background service worker — owns the unlocked session, the decrypted
 * login index, the idle auto-lock, and the tab badge. Popup and content
 * scripts never hold keys; they ask the worker for exactly what a matched
 * origin needs, per the Phase 4 contract.
 */
import {
  generatePassphrase,
  generatePassword,
  parseOtpauthUri,
  totp,
} from "@kleidion/crypto";
import { setApiToken } from "../lib/api";
import { signin } from "../lib/auth";
import type {
  BackgroundRequest,
  BackgroundResponse,
  CredentialsData,
  MatchEntry,
  StatusData,
  TotpData,
  VaultOption,
} from "../lib/messages";
import {
  buildIndex,
  invalidateIndex,
  matchForHost,
  saveLogin,
  toMatchEntry,
} from "../lib/vaults";
import {
  clearStoredSession,
  idleMs,
  isExpired,
  loadStoredSession,
  storeSession,
  touchActivity,
  type Session,
} from "../lib/store";

let session: Session | null = null;
let restoring: Promise<void> | null = null;

const ok = (data: unknown): BackgroundResponse => ({ ok: true, data });
const fail = (error: string): BackgroundResponse => ({ ok: false, error });

/** Lazy-restore the session after a service-worker recycle (within the browser session). */
function ensureRestored(): Promise<void> {
  if (session) return Promise.resolve();
  restoring ??= (async () => {
    if (isExpired(await idleMs())) {
      await clearStoredSession();
      return;
    }
    const s = await loadStoredSession();
    if (s) {
      session = s;
      setApiToken(s.sessionToken);
    }
  })().finally(() => {
    restoring = null;
  });
  return restoring;
}

async function lock(): Promise<void> {
  session = null;
  setApiToken("");
  invalidateIndex();
  await clearStoredSession();
}

function requireSession(): Session {
  if (!session) throw new Error("Vault is locked");
  return session;
}

async function computeTotp(value: string): Promise<TotpData> {
  const v = value.trim();
  if (v.toLowerCase().startsWith("otpauth://")) {
    const p = parseOtpauthUri(v);
    const c = await totp(p.secret, { digits: p.digits, period: p.period, algorithm: p.algorithm });
    return { code: c.code, secondsRemaining: c.secondsRemaining, period: c.period };
  }
  const c = await totp(v);
  return { code: c.code, secondsRemaining: c.secondsRemaining, period: c.period };
}

async function handle(
  req: BackgroundRequest,
  sender: chrome.runtime.MessageSender,
): Promise<unknown> {
  await ensureRestored();
  switch (req.type) {
    case "status": {
      return { unlocked: !!session, email: session?.email ?? null } satisfies StatusData;
    }
    case "signin": {
      const s = await signin(req.email, req.password, req.secretKey);
      session = s;
      setApiToken(s.sessionToken);
      await storeSession(s);
      invalidateIndex();
      return { unlocked: true, email: s.email } satisfies StatusData;
    }
    case "lock": {
      await lock();
      return { unlocked: false, email: null } satisfies StatusData;
    }
    case "vaults": {
      const idx = await buildIndex(requireSession());
      return idx.vaults satisfies VaultOption[];
    }
    case "list": {
      const idx = await buildIndex(requireSession());
      return idx.entries.map(toMatchEntry) satisfies MatchEntry[];
    }
    case "match": {
      const idx = await buildIndex(requireSession());
      return matchForHost(idx.entries, req.hostname).map(toMatchEntry) satisfies MatchEntry[];
    }
    case "credentials": {
      const idx = await buildIndex(requireSession());
      const entry = idx.entries.find((e) => e.itemId === req.itemId);
      if (!entry) throw new Error("Item not found");
      // Content-script requests carry a tab origin: only reveal credentials
      // for an item that actually matches that page. Popup requests (no tab)
      // are user-initiated and always allowed.
      const tabUrl = sender.tab?.url;
      if (tabUrl) {
        let host = "";
        try {
          host = new URL(tabUrl).hostname;
        } catch {
          host = "";
        }
        const allowed = host
          ? matchForHost(idx.entries, host).some((e) => e.itemId === req.itemId)
          : false;
        if (!allowed) throw new Error("Origin does not match this item");
      }
      return { username: entry.username, password: entry.password } satisfies CredentialsData;
    }
    case "totp": {
      const idx = await buildIndex(requireSession());
      const entry = idx.entries.find((e) => e.itemId === req.itemId);
      if (!entry?.totpValue) throw new Error("No TOTP secret for this item");
      return computeTotp(entry.totpValue);
    }
    case "generate": {
      // Pure client-side CSPRNG work; no session or vault access needed.
      if (req.mode === "passphrase") {
        return {
          password: await generatePassphrase({
            words: req.words ?? 6,
            separator: "-",
            capitalize: true,
            includeNumber: false,
          }),
        };
      }
      return {
        password: await generatePassword({
          length: req.length ?? 20,
          upper: true,
          lower: true,
          digits: true,
          symbols: true,
          excludeAmbiguous: false,
        }),
      };
    }
    case "save": {
      return saveLogin(requireSession(), {
        vaultId: req.vaultId,
        title: req.title,
        username: req.username,
        password: req.password,
        hostname: req.hostname,
      });
    }
  }
}

export default defineBackground(() => {
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    let responded = false;
    const reply = (r: BackgroundResponse) => {
      if (responded) return;
      responded = true;
      try {
        sendResponse(r);
      } catch {
        /* receiver gone */
      }
    };
    void (async () => {
      try {
        await touchActivity();
        reply(ok(await handle(req as BackgroundRequest, sender)));
      } catch (err) {
        reply(fail(err instanceof Error ? err.message : String(err)));
      }
    })();
    return true; // keep the message channel open for the async reply
  });

  // Idle auto-lock via a persistent alarm (survives service-worker teardown).
  void chrome.alarms.create("kleidion-idle", { periodInMinutes: 1 });
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name !== "kleidion-idle") return;
    await ensureRestored();
    if (session && isExpired(await idleMs())) await lock();
  });

  // Badge: number of logins matching the active tab, when unlocked.
  const updateBadge = async (tabId: number, url?: string): Promise<void> => {
    try {
      await ensureRestored();
      const host = session && url ? safeHostname(url) : "";
      const n = host ? matchForHost((await buildIndex(session!)).entries, host).length : 0;
      await chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
      if (n) await chrome.action.setBadgeBackgroundColor({ tabId, color: "#2fbd8b" });
    } catch {
      /* badge is best-effort (private/incognito pages, unsupported URLs) */
    }
  };
  chrome.tabs.onUpdated.addListener((tabId, _info, tab) => {
    void updateBadge(tabId, tab.url);
  });
  chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
      const tab = await chrome.tabs.get(tabId);
      void updateBadge(tabId, tab.url);
    } catch {
      /* tab may have closed */
    }
  });
});

function safeHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}
