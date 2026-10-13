# Kleidion extension — build & manual E2E

## Build

```bash
npm install                 # workspace install; postinstall runs `wxt prepare`
npm run ext:dev             # watch build (Chrome)  -> .output/chrome-mv3
npm run ext:build           # prod Chrome build     -> .output/chrome-mv3
npm run ext:build:firefox   # prod Firefox build    -> .output/firefox-mv2
npm run compile -w @kleidion/extension   # tsc --noEmit
```

Load unpacked:
- Chrome: `chrome://extensions` → Developer mode → "Load unpacked" → `.output/chrome-mv3`
- Firefox: `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on" → `.output/firefox-mv2/manifest.json`

Requirements: server API reachable at `http://localhost:18080` (override with `VITE_API_BASE` at build time,
e.g. `VITE_API_BASE=http://localhost:18081 npm run ext:build` — the host API port is chosen by
`scripts/gen-env.sh` and changes between boots, so check `.env`).

## Firefox caveats

- Built as **MV2** (WXT default for Firefox). Background is a persistent page, so the
  in-memory session survives; on Chrome MV3 the service worker may sleep, but the session
  is restored from `chrome.storage.session`.
- `browser.storage.session` is unsupported on Firefox MV2 → the session key material falls
  back to module-memory only. It is cleared on browser restart and never written to disk
  (strictly weaker guarantee than Chrome; documented trade-off).
- Install-time data-consent: manifest declares `data_collection_permissions.required=["none"]`.

## Automated Chrome E2E

`.shots/ext-e2e.js` (gitignored scratch harness, puppeteer-core) drives the extension in a real
Chrome window against the live stack: it seeds an account + vault + two logins through the web app,
signs the extension in over SRP, then asserts autofill, quick-generate, save-on-submit, TOTP and
lock. Last run 2026-10-14: **30/30 green**. It caught two real content-script bugs (a stale blur
timer closing a newer menu, and the save prompt being torn down by the field menu it replaced).

Harness constraints worth knowing before you rewrite it:

- **Branded Chrome ignores `--load-extension`.** Use a Chrome-for-Testing build
  (`~/.cache/puppeteer/chrome/…`). The MV3 service worker also never appears in CDP
  `Target.getTargets`, so the extension id is derived the way Chromium derives it for unpacked
  loads: SHA-256 over the **UTF-16LE absolute path**, first 32 hex nibbles mapped `0-f → a-p`.
- **`chrome://` pages reject `page.evaluate`** (it returns empty), so `chrome://extensions` can
  only be inspected by screenshot or coordinate clicks.
- **The autofill menu lives in a closed shadow root**, so its rows are unreachable from page JS.
  Locate them with a piercing CDP DOM walk (`DOM.getDocument` with `pierce: true`) and click with
  real mouse events.
- Opening `popup.html` as a tab is fine for sign-in/list/TOTP/lock, but `sender.tab` is then set,
  so the background's origin guard refuses `credentials` — which is exactly how the guard is
  asserted. The real toolbar popup has no `sender.tab`.

Still manual only: autofill against the real `mail.google.com` DOM, comparing a code with
Google Authenticator on a phone, and clicking the toolbar icon to confirm the badge.

## E2E script (exit criteria)

Preconditions:
1. `docker compose up -d --build` (API 18080, web 13000, DB 15432).
2. Two accounts registered via the web app: **Alice** (alice@test.local) and **Bob** (bob@test.local).
   Record each account's secret key and master password — the extension signs in through SRP
   and needs the secret key on the sign-in screen.
3. In the web vault (as Alice): a **personal** vault with a login for `mail.google.com`,
   strong password, and a TOTP field containing an `otpauth://totp/...` URI (or raw base32 secret).

### 1. Sign-in + autofill on Gmail (< 2 clicks)
1. Load the extension, open the popup, sign in as Alice (email + password + secret key).
2. Open `https://mail.google.com` in a tab, click the email input.
3. Expect: Kleidion menu appears anchored above the field listing the matching login (1 click).
4. Click the entry (or press Enter). Expect: email + password both filled by the native-setter
   dispatch (React-compatible). Total interaction: focus → click entry = **< 2 clicks**.
5. Badge on the toolbar shows the green indicator while a match exists for the active tab.

### 2. TOTP matches Google Authenticator
1. In the popup, on the Gmail match row, expect the TOTP chip (6 digits, countdown bar).
2. Add the same secret to Google Authenticator on a phone.
3. Codes must match within the same 30 s window; chip refreshes automatically.
4. Also verify via `packages/crypto` test vectors: SHA1/6/30 defaults, and `digits`/`period`/
   `algorithm` params honored from the `otpauth://` URI.

### 3. Share login with Bob — share link
1. As Alice in the web app: create a share link for a login item, copy the token URL.
2. Sign out, sign in as Bob, redeem the link (web UI). Item decrypts in Bob's vault.
3. Extension (as Bob): the shared item's host appears in popup matches and autofills.

### 4. Shared vault member
1. Alice creates a **shared** vault, invites Bob by email via "Manage members" (role write).
2. Bob's wrapped vault key unwraps; both can add/edit items; read-only member gets no Save.
3. Extension as Alice or Bob: shared-vault logins match + autofill; popup Save offers only
   writable vaults.

### 5. Lock / idle
1. Popup "Lock" clears session keys; autofill menu shows "locked" state until re-signin.
2. No activity for 15 min → alarms tick auto-locks (`chrome.alarms`, storage `lastActivity`).

### 6. Origin guard (security)
1. Open `https://evil.example` while a Gmail login exists.
2. Even if content script asks for `credentials{itemId}`, the background re-checks the
   sender tab's host against the item's domains and **denies** the reveal.
3. `accounts.google.com` ↔ `mail.google.com` are treated equivalent (base-domain rule),
   so the login autofills on the Google sign-in page too.
