# Kleidion — Zero-Knowledge Password Manager: Master Implementation Plan

> **For Hermes:** Execute phase-by-phase with subagent-driven-development; each phase gets its own
> detailed task breakdown written before that phase starts (this document is the master plan).

**Goal:** Build a zero-knowledge, end-to-end-encrypted password manager (web, browser extension,
desktop, mobile, CLI) on a Go backend + Next.js frontend, fully containerized (Docker **and** Podman
compatible) and orchestrated in dev with Tilt.

**Architecture:** Zero-knowledge client-side encryption (all crypto happens on devices; server stores
only opaque ciphertext + SRP verifiers). SRP-6a password-authenticated key exchange, two-secret key
derivation (master password + Secret Key), Argon2id KDF, XChaCha20-Poly1305 item encryption,
per-vault symmetric keys wrapped with per-user public keys (standard hierarchical key wrapping).

**Tech Stack:** Go 1.26+ (Gin), PostgreSQL 17, Next.js 16 / React 19 / Tailwind 4, TypeScript,
libsodium-wrappers (WASM) for client crypto, WXT (extension), Tauri 2 (desktop), Expo SDK 57
(mobile), Docker/Podman, Tilt.

---

## 0. Naming Decision

**Chosen name: `Kleidion`** — from Greek *κλείδιον* (kleídion), "little key" (diminutive of
*kleis*, key). Short, brandable, pronounceable (KLY-dee-on), no existing software product with
this name.

Verified 2026-10-03 (RDAP registry lookups + package registry searches):

| Check | Result |
|---|---|
| `kleidion.com` (Verisign RDAP) | **AVAILABLE** (404 = unregistered) |
| `kleidion.io`, `kleidion.co` | **AVAILABLE** |
| npm `kleidion` | **FREE** (404) |
| PyPI `kleidion` | **FREE** (404) |
| GitHub repos named kleidion | 1 (a personal account, unrelated) |
| Web search for product named "Kleidion" | none (only a person's first name) |

⚠️ Minor collision: a Berlin infra-monitoring startup "Cledion" (cledion.com, 2025). Different
spelling/pronunciation, different industry — low trademark risk, but noted.

**Backup names, also verified .com-available:** `AnvilKey` (anvilkey.com), `KeyCitadel`
(keycitadel.com), `BulwarkKey` (bulwarkkey.com), `LockAnvil` (lockanvil.com), `AnvilPass`
(anvilpass.com). All checked clean on npm/PyPI as well.

**Decision needed from owner:** confirm **Kleidion** (or pick a backup) → then register
kleidion.com and rename the project folder `D:\projects\password-manager` →
`D:\projects\kleidion`. Everything below assumes `kleidion`.

---

## 1. How Zero-Knowledge Password Managers Work (Research Summary → Our Design Targets)

From published zero-knowledge password-manager security designs and common product surfaces
(researched 2026-10-03):

### 1.1 Security architecture we will replicate
1. **Zero-knowledge / E2EE:** all keys generated client-side; encryption/decryption only on user
   devices. Server can never read vault data. *Our rule: the Go server binary must never contain
   code paths that could produce plaintext item data.*
2. **Two secrets (2SKD):** account password (memorized) + **Secret Key** (128-bit random, generated
   at signup, stored only on devices / Emergency Kit). Both feed key derivation → stolen server DB
   is uncrackable without the Secret Key.
3. **Key hierarchy:**
   - `AUK` (Account Unlock Key) = Argon2id/PBKDF2(password + salt) XOR HKDF(SecretKey)
   - AUK encrypts the user's **private key** (RSA-2048-OAEP in 1P; we'll use **X25519** + Ed25519)
   - Each vault has a random 256-bit **vault key**; items are encrypted AES-256-GCM/XChaCha20-Poly1305
     with the vault key
   - Vault keys are wrapped with each member's **public key** → sharing = wrap the vault key for
     the recipient, no re-encryption of items needed
4. **SRP-6a authentication** (RFC 5054, 2048-bit group): mutual auth, no password/verifier leak in
   transit, replay-proof, establishes a session key. Verifier is stored server-side; 2SKD makes it
   uncrackable. SRP-6a is implemented in-repo (Go + TS) and cross-verified with golden vectors.
5. **Emergency Kit:** printable PDF with email + Secret Key; no server-side password reset exists.
   Account recovery flows must never weaken zero-knowledge (we'll add social/SRP-based recovery
   options in later phases, e.g., trusted-contact recovery like 1P).
6. **KDF hardness:** 1P uses 650k PBKDF2 rounds; we use **Argon2id** (OWASP-recommended: m=64 MiB,
   t=3, p=4 as baseline) — better GPU/ASIC resistance, tunable per-device on mobile.

### 1.2 Feature surface we will target (phased)
| Reference feature | Kleidion phase |
|---|---|
| Vaults (personal/shared), items (Login, Card, Identity, Secure Note, SSH key, Document) | P3 |
| Password/passphrase generator (recipes, history) | P3 |
| Autofill + inline menu in browsers | P4 |
| Encrypted sync across devices (delta sync, offline caches) | P3/P4 |
| Sharing (1:1, shared vaults, guest/time-limited links) | P4 |
| Passkeys (WebAuthn discoverable credentials) | P5 |
| Built-in TOTP (2FA codes next to passwords) | P4 |
| Security-health dashboard: breach (HIBP k-anonymity), reuse, weak-password audit | P6 |
| Travel masking (hide vaults at borders) | P6 |
| Desktop apps w/ biometric unlock, system tray, global hotkey | P5 |
| Mobile apps w/ OS autofill providers, biometric unlock | P5 |
| SSH agent + CLI (`op`) + service accounts | P7 |
| Teams/business: SSO, SCIM, activity log, admin console | P7+ |
| Emergency Kit PDF | P2 |

---

## 2. Monorepo Layout

Single git repo at `D:\projects\kleidion`, npm workspaces:

```
kleidion/
├── Tiltfile                     # dev orchestration (docker compose based, podman-aware)
├── docker-compose.yml           # works with `docker compose`, `podman compose`, `podman-compose`
├── docker-compose.test.yml      # CI/test stack
├── package.json                 # workspaces root (scripts only)
├── .gitignore / .editorconfig / README.md / SECURITY.md
├── apps/
│   ├── server/                  # Go backend (Gin) — module github.com/<org>/kleidion/server
│   │   ├── cmd/server/main.go
│   │   ├── internal/
│   │   │   ├── api/             # handlers, middleware, routes (v1)
│   │   │   ├── auth/            # SRP-6a flow, sessions, devices
│   │   │   ├── domain/          # entities: user, vault, item, share, device
│   │   │   ├── store/           # Postgres (pgx), repositories, migrations
│   │   │   ├── sync/            # delta-sync engine
│   │   │   └── config/          # env loading + validation
│   │   ├── migrations/          # golang-migrate SQL
│   │   └── Dockerfile           # multi-stage; runs as non-root (rootless-podman safe)
│   ├── web/                     # Next.js 16 (upgraded from current scaffold)
│   │   ├── app/                 # (auth)/signin, (auth)/signup, (vault)/..., settings
│   │   ├── components/          # shadcn/ui + Tailwind 4
│   │   ├── lib/                 # api client, session, storage adapters
│   │   └── Dockerfile           # dev: node:24-alpine `next dev`; prod: multi-stage build
│   ├── extension/               # WXT (Manifest V3, Chrome+Firefox)
│   │   ├── entrypoints/         # background, popup, content-scripts (autofill), options
│   │   └── Dockerfile           # dev image: wxt watch + zip output on volume
│   ├── desktop/                 # Tauri 2 shell around web UI
│   │   ├── src-tauri/           # Rust: tray, keyring (OS secure storage), autostart, updater
│   │   └── (frontend = shared web package in "desktop mode")
│   ├── mobile/                  # Expo SDK 57 (iOS + Android)
│   │   ├── app/                 # expo-router screens
│   │   ├── ios/autofill-ext/    # iOS AutoFill Credential Provider
│   │   └── android/autofill/    # Android Autofill Framework service
│   └── cli/                     # Go CLI `kleidion` (op-style) — P7
├── packages/
│   ├── crypto/                  # TS: libsodium-wrappers — key derivation, item crypto, SRP client
│   │   └── src/{kdf,srp,vault,item,secretkey,emergencykit}.ts + vitest tests
│   ├── core/                    # TS: zod schemas shared web/extension/mobile + API types
│   └── srp/                     # in-repo RFC 5054 SRP-6a (Go), golden-vector verified
└── infra/
    ├── postgres/initdb.sql      # dev bootstrap
    ├── docker/                  # per-app containerfiles if not colocated
    └── docs/adr/                # architecture decision records
```

**Rationale:** one repo → shared `packages/crypto` + `packages/core` (one implementation of the
security-critical code used by web, extension, desktop, mobile); Tilt + compose at root manage all
services; clients are versioned/released independently via tags (`web-vX.Y.Z`, etc.).

### 2.1 Backend framework decision (Go)
**Chosen: Gin v1.10+.** Most widely used Go web framework (48% adoption, JetBrains Go survey
2025), battle-tested, frozen stable API, rich middleware ecosystem (CORS, rate-limit, JWT,
request-id, recovery). Runner-up considered: `chi` (100% stdlib-compatible, leaner) — acceptable
fallback if Gin's context abstraction ever conflicts with a dependency; decision recorded as ADR-002.
Supporting libs: `pgx/v5` (Postgres), `golang-migrate` (migrations), SRP-6a implemented in-repo
(`internal/auth/srp`, RFC 5054), `golang.org/x/crypto` (argon2, hkdf, nacl), `go-playground/validator` (via Gin),
`rs/zerolog` (structured logs), `prometheus/client_golang` (metrics), `air` (dev hot-reload).

### 2.2 Frontend stack decisions
- **Next.js 14.2.3 → 16.3.8** (latest stable), React 18 → **19.3**, TypeScript → **5.x/7.x** (pin
  whatever `create-next-app@latest` ships; currently TS 7.0.2 exists — start with 5.9 for ecosystem
  compatibility, ADR-003).
- **Remove `next-auth` + `@next-auth/firebase-adapter` + `firebase`**: auth moves to our Go SRP
  backend; Firebase is dropped entirely (zero-knowledge server is ours). Existing
  `app/api/auth/[...nextauth]/route.ts`, `firebaseConfig.ts`, `types/next-auth.d.ts` deleted.
  The Firebase project `passwordmanager-b67a0` gets retired by the owner.
- **MUI → Tailwind CSS 4 + shadcn/ui.** MUI is currently installed but unused (zero MUI imports in
  the scaffold), so this is cost-free; shadcn gives us full control over the vault UI and bundles
  small (matters for extension content scripts). ADR-004.
- **State/data:** TanStack Query v5 + zod v4 (schemas shared from `packages/core`).

### 2.3 Container strategy (Docker AND Podman)
- Compose file kept in the **portable subset** both engines support: no `depends_on:
  condition:` beyond healthcheck (supported by podman-compose ≥1.2 and `podman compose`), no
  Docker-only fields (`init:` avoided; use explicit tini in images if needed), named volumes only,
  `userns_mode` not used.
- All Dockerfiles: **OCI-compatible classic syntax** (no BuildKit-only features like
  `RUN --mount=cache` in the default path; multi-stage + `--mount=type=cache` only behind a
  build-arg-gated stage so `podman build` works unmodified). Run as **non-root** (rootless podman).
- Verify both ways in CI and locally: `docker compose up` and
  `podman machine start && podman-compose up` (podman not yet installed on this Windows machine —
  Phase 1 installs it via `winget install RedHat.Podman` + `podman machine init`).
- Quadlet unit files (systemd) provided later for podman-native prod deployment (P7).

### 2.4 Tilt dev loop
`Tiltfile` at repo root drives `docker_compose()` resources with live update:
- **server:** `air` hot-reload inside the Go container (sync `apps/server/**` → rebuild binary)
- **web:** `next dev` (HMR via synced source; node_modules kept in image/volume)
- **extension:** `wxt --mode development` watcher; unzip to `dist/` volume, load unpacked in browser
- **db:** postgres 17 + pgAdmin-optional, mailpit for transactional email dev
- Podman support via `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock` (or
  `npipe:////./pipe/podman-machine-default` on Windows) — Tilt then builds through podman's
  Docker-compatible API; `ext://podman` helpers from tilt-extensions if native builds are needed.
- Tilt web UI at :10350; `tilt up` = whole stack, `tilt up server web db` = subset.

---

## 3. Data Model (Postgres, server-side — all secrets are opaque)

```
users            id uuid pk, email citext unique,
                 srp_salt bytea, srp_verifier bytea,        -- SRP-6a (2048-bit group, SHA-256)
                 kdf_algo text, kdf_params jsonb,           -- argon2id m/t/p for clients
                 master_public_key bytea,                   -- X25519 pub (vault-key wrapping)
                 encrypted_private_key bytea,               -- wrapped with AUK (client-side)
                 encrypted_sym_key bytea,                   -- legacy-compat slot for personal key set
                 created_at, updated_at, disabled_at
devices          id uuid pk, user_id fk, name, platform,
                 created_at, last_seen_at, trusted bool
sessions         id uuid pk, user_id fk, device_id fk,
                 token_hash bytea, created_at, expires_at, revoked_at
vaults           id uuid pk, owner_id fk(users), kind (personal|shared),
                 name text,                                  -- NOTE: vault names ARE encrypted client-side;
                                                             -- stored name is ciphertext too (see items pattern)
                 created_at, updated_at
vault_keys       vault_id fk, user_id fk,
                 wrapped_vault_key bytea,                    -- vault key encrypted with member's pub key
                 role (admin|write|read), created_at
items            id uuid pk, vault_id fk,
                 item_type int,                              -- enum on client; server sees int only
                 ciphertext bytea, nonce bytea,              -- XChaCha20-Poly1305 of full item JSON
                 search_hmac bytea,                          -- HMAC-SHA256(vault-key-derived, normalized-title)
                                                             -- enables server-side search w/o decryption (ADR-006)
                 version bigint, deleted_at,                 -- version drives delta sync
                 created_at, updated_at
sync_cursors     user_id fk, device_id fk, last_version bigint
share_links      id uuid pk, item_id fk, creator_id fk,
                 wrapped_item bytea, expires_at, max_views, views
totp_secrets     (folded into item ciphertext — no separate table; server never sees TOTP seeds)
audit_events     id, user_id, event_type, ip, user_agent, created_at   -- metadata only, never content
```

**Server knows:** emails, device names, timing metadata, ciphertext sizes. **Server never knows:**
passwords, item contents, vault names, TOTP seeds, Secret Key, master password.

**Sync protocol (P3):** clients poll/subscribe `GET /v1/sync/changes?since=<version>`; monotonic
per-vault version counter; conflicts resolved last-write-wins with client-side merge prompt for
item-level fields (v1: LWW + full-item conflict copy). WebSocket fan-out in P4 for push sync.

---

## 4. API Surface (v1, all JSON over HTTPS)

```
POST /v1/auth/enroll/start      {email}                → {salt, kdfParams, srpB...} (signup: creates user)
POST /v1/auth/enroll/finish     {verifier, pubKey, encPrivKey...} → {emergencyKitNonce...}
POST /v1/auth/srp/start         {email}                → {salt, kdfParams, B}      (SRP-6a step 1)
POST /v1/auth/srp/finish        {A, clientProof, deviceId, deviceName} → {sessionToken, serverProof, userKeyBundle}
POST /v1/auth/verify-2fa        (P6: TOTP/passkey second factor)
POST /v1/auth/logout            (revokes session/device)
GET  /v1/me                     → profile + devices + key bundle
GET  /v1/vaults                 → vault metadata (names encrypted) + wrapped keys
POST /v1/vaults                 (personal vault auto-created at enroll; shared vaults P4)
GET  /v1/items?vault=&since=    → items (ciphertext) + cursor
POST /v1/items                  {vaultId, type, ciphertext, nonce, searchHmac}
PUT  /v1/items/:id              (version bump, LWW)
DELETE /v1/items/:id            (soft delete → trash)
GET  /v1/sync/changes?since=    → delta feed
POST /v1/share-links            (P4) / POST /v1/vaults/:id/members (P4)
GET  /healthz  /readyz  /metrics
```
Rate limiting (per-IP + per-user token bucket in-memory → Redis when scaled), strict request
validation, no stack traces in prod, security headers (CSP w/ WASM allowance for libsodium,
HSTS, frame-deny), OpenAPI spec generated from handlers (swag or hand-written yaml in
`packages/core` → TS client codegen).

---

## 5. Client Crypto Package (`packages/crypto`) — the security core

One TS implementation, consumed by web/extension/desktop/mobile. Thin wrapper over
**libsodium-wrappers 0.8.4** (WASM). Mirror behaviors tested against Go test vectors for SRP.

```
generateSecretKey()             → "KL-A3-XXXXXX-XXXXXX-..." (128-bit CSPRNG, our alphabet, formatted)
deriveAUK(password, secretKey, salt, kdfParams)
    → argon2id(password, salt) ⊕ HKDF(secretKeyBytes, salt=accountId, info="kleidion-auk-v1")
deriveSrpX(password, secretKey, srpSalt, kdfParams)   → 2SKD, independent salt (auth vs unlock)
srpClientStart()/srpClientFinish(B)                   → {A, clientProof, sessionKey}  (SRP-6a, RFC5054 g14/SHA-256)
generateVaultKey()            → random 32B
wrapVaultKey(vaultKey, recipientPubKey) / unwrapVaultKey(...)   → X25519 sealed box
encryptItem(vaultKey, itemJson) → {ciphertext, nonce}   → XChaCha20-Poly1305
decryptItem(vaultKey, ciphertext, nonce) → itemJson
searchHmac(vaultKey, title)   → HMAC-SHA256(kdf=search, normalize(title))
generatePassword(recipe) / generatePassphrase(wordlist, n, sep)
totpNow(secret)               → RFC 6238 codes (P4)
emergencyKit(user)            → printable data (email + secretKey + QR)
```
**Testing:** property-based tests (fast-check), cross-language SRP test vectors (Go server test ↔
TS client test with fixed salt/verifier), KAT (known-answer tests) for derive/encrypt. This package
ships with 100% statement coverage requirement — it is the crown jewels.

---

## 6. Phased Roadmap (each phase = its own detailed plan before execution)

### Phase 0 — Foundation & rename (½ day)
- [ ] Owner confirms name (default **Kleidion**); register `kleidion.com` (owner action)
- [ ] `git init` in `D:\projects\kleidion` (rename folder), initial commit of current scaffold
- [ ] Create monorepo skeleton (dirs, root package.json workspaces, .gitignore, .editorconfig,
      README, SECURITY.md stub, ADR folder with ADR-001..004: stack, gin, ts-version, ui-lib)
- [ ] Move Next app → `apps/web`; delete firebase/next-auth files; npm workspaces install
- **Exit:** `git log` shows clean history; `npm ls` resolves workspaces.

### Windows host quirks discovered during Phase 1 (IMPORTANT)
- **Host port clashes:** other local projects (credivect, mediconyx, graphify) already bind
  5432/8080/3000/1025/8025. All compose host ports are now env-overridable and default to
  non-clashing values: db `15432`, api `18080`, web `13000`, mailpit `18025`/smtp `11025`.
  Server↔db use the internal `5432`/`8080` (container network); only host mappings changed.
- **Tilt UI port:** Tilt's default `:10350` is inside the WinNAT excluded range reserved by
  Hyper-V/WSL (`netsh interface ipv4 show excludedportrange protocol=tcp`). Always run
  `tilt up --port=11350` on this machine. Documented in the Tiltfile header.
- **Tilt `dc_resource`:** does NOT accept `trigger=`/`config_paths=`/`live_update=` in this
  version for compose resources (those are `k8s_resource`/`docker_build` concepts). Keep the
  Tiltfile minimal — `docker_compose()` auto-creates resources; rebuild-on-change works from
  compose build contexts. Next HMR handles web source without a rebuild.
- **Podman on Windows:** installs to `C:\Program Files\RedHat\Podman` (winget `RedHat.Podman`),
  not on PATH by default; machine uses WSL backend. `podman-compose` via `pip install`
  (lands in `~/AppData/Roaming/Python/Python311/Scripts`). Do **NOT** set
  `DOCKER_HOST=npipe://...` for podman-compose — podman CLI uses its native pipe; npipe schema
  is unsupported by the podman Go client. `podman compose` subcommand delegates to Docker's
  docker-compose provider — use the standalone `podman-compose` instead for true-podman testing.
- **git on D: drive:** "dubious ownership" (folder owned by a different SID) → needs
  `git config --global --add safe.directory D:/projects/kleidion`. `.gitattributes` added
  (`* text=auto eol=lf`) to stop CRLF-rewrite warnings.

### Phase 1 — Infrastructure first (user's directive) — ✅ DONE 2026-10-03
- [x] Next.js upgrade: → Next 16.3.8 / React 19.3 / TS 5.9; `next build` green
- [x] Tailwind 4 + themed shell; MUI/emotion removed; landing page "Kleidion — your keys, yours alone"
- [x] `apps/server`: `go mod init`, Gin skeleton, `/healthz` `/readyz` `/v1/status` `/metrics`, zerolog,
      config-from-env with validation, graceful shutdown, Dockerfile (multi-stage, non-root, distroless-style alpine)
- [x] Postgres 17 + golang-migrate wired into server boot (retry loop); migration 000001 = users/devices/sessions
- [x] `docker-compose.yml` (db, server, web, mailpit) — verified `docker compose up` AND
      `podman-compose up` (podman installed via winget); env-overridable host ports, no engine-specific fields,
      no `dockerfile:` keys (podman-compat)
- [x] `Tiltfile`: docker_compose resources; verified `tilt ci` → SUCCESS all workloads healthy (--port=11350)
- [x] CI workflow (GitHub Actions): Go build/vet/test -race, web typecheck/build, compose smoke on docker + podman
- **Exit criteria MET:** one command boots db+server+web with hot reload on BOTH Docker and Podman;
      web shows upgraded shell; `/healthz`+`/readyz` 200; migrations applied (dirty=f).

### Phase 2 — Auth & crypto core (the hard security part) (1–2 weeks)
- [ ] `packages/crypto`: full API from §5, TDD, cross-language SRP test vectors
- [ ] Go SRP-6a server endpoints (enroll/start+finish, srp/start+finish) using the in-repo SRP pkg,
      verifier storage, session tokens (random 256-bit, stored as SHA-256 hash), device registry
- [ ] Web: signup flow (password strength meter → zxcvbn, Secret Key generation, Emergency Kit
      display + PDF download/print, mandatory "I saved it" gate), signin flow (email + password +
      Secret Key first-device), session persistence, locked/unlocked app state machine
- [ ] Key bundle stored server-side (opaque), X25519/Ed25519 keypair generated client-side,
      private key wrapped with AUK before upload
- [ ] Security review checkpoint: threat-model doc + code review of all crypto before proceeding
- **Exit:** two devices can independently sign up/sign in; server DB contains only ciphertext and
      verifiers (verified by manual inspection); wrong password/secret-key fails SRP without leaking.

### Phase 3 — Vaults, items, sync + web vault UI (2–3 weeks)
- [ ] Personal vault auto-provisioned at enroll (vault key gen → wrapped → stored)
- [ ] Item CRUD (encrypted) + delta sync engine (version cursors, `since=` polling)
- [ ] Web vault UI: sidebar (vaults/categories/tags), item list w/ instant search (client-side
      decrypt-cache + server search_hmac), item detail/edit (Login, Secure Note, Card, Identity
      templates), favorites, trash, item history (previous ciphertext versions kept server-side)
- [ ] Password generator UI (recipe builder + passphrase mode + strength readout)
- [ ] Copy-to-clipboard with auto-clear (30s), reveal toggles, QR share for mobile handoff
- **Exit:** full daily-driver web experience; offline changes sync on reconnect; LWW conflicts
      produce a conflict copy, never data loss.

### Phase 4 — Extension + sharing + TOTP (2–3 weeks)
- [ ] `apps/extension` (WXT, MV3): popup vault, tab-aware suggestions (URL → item match incl.
      equivalent-domain rules), inline autofill menu, new-item capture on submit, lock/unlock
      (session in memory only, auto-lock timer), badge count
- [ ] Save/update flows write through the same `packages/crypto` + API client
- [ ] 1:1 encrypted share links (time/view limited), shared vaults + member invites (wrap vault key
      with invitee pub key), roles
- [ ] TOTP: item field renders live codes in web + extension
- [ ] Firefox parity pass (WXT multi-target build)
- **Exit:** autofill on gmail.com from a signed-in session in <2 clicks; share a login with a second
      account; TOTP codes match Google Authenticator.

### Phase 5 — Desktop (Tauri 2) + Mobile (Expo 57) (3–4 weeks)
- [ ] `apps/desktop`: Tauri 2 shell hosting the web UI in desktop mode; OS keychain integration
      (Secret Key/AUK cached encrypted in Windows Credential Manager / macOS Keychain /
      libsecret), biometric unlock (Windows Hello / Touch ID), tray, global hotkey, auto-update
      (signed), deep links (kleidion://)
- [ ] `apps/mobile`: Expo 57 app — signup/signin, vault browse/edit, generator, TOTP,
      expo-secure-store for keys, biometric unlock, offline cache (SQLite w/ encrypted blobs)
- [ ] iOS AutoFill Credential Provider extension; Android Autofill Framework service
- **Exit:** desktop installs on Windows with biometric unlock; mobile autofills into Safari/Chrome
      (iOS) and any app (Android).

### Phase 6 — Trust features (2 weeks)
- [ ] Security-health page: HIBP pwned-passwords k-anonymity check (range API, client-side), reused
      passwords, weak passwords, sites without HTTPS, 2FA-coverage nudges, overall score
- [ ] Passkeys: WebAuthn platform/authenticator credentials stored as items; extension + web
      conditional-UI autofill; desktop/mobile passkey provider where OS allows
- [ ] Travel masking: flag vaults safe-for-travel; devices enter travel state (flagged vaults' wrapped
      keys evicted from server responses + local caches wiped)
- [ ] Account recovery v1 (trusted contact / recovery kit re-enroll flow)
- **Exit:** security-health page flags a planted breached password; passkey signs into a demo RP; travel masking
      provably removes flagged vault bytes from device.

### Phase 7 — Scale-out & hardening (ongoing)
- [ ] CLI (`apps/cli`, Go, `op`-style: signin via SRP device flow, item get/create, inject secrets
      into env/commands) + SSH agent (desktop sidecar)
- [ ] Teams: org layer, SSO (OIDC bridge), admin console, audit log export, SCIM
- [ ] Prod deployment: Quadlet/systemd podman units or k8s manifests; backups (encrypted WAL-G to
      S3); observability (Prometheus+Grafana+Loki in compose profiles)
- [ ] **External security audit** (non-negotiable before public launch) + bug-bounty setup
- [ ] Public launch: marketing site on kleidion.com, docs site, import tools (Bitwarden JSON,
      browser CSV exports, generic JSON), pricing/free tier decisions

---

## 7. Cross-Cutting Requirements

- **TDD everywhere**; `packages/crypto` and `apps/server/internal/auth` at ≥95% coverage, property
  tests for crypto, Go `-race` in CI.
- **Zero-knowledge invariant tests:** an automated suite that asserts API responses and DB rows
  never contain plaintext fixtures (canary strings planted in items during e2e tests).
- **E2E:** Playwright against the tilt/compose stack (web + extension loaded unpacked).
- **Secrets hygiene:** no secrets in git; dev `.env.example` only; Tilt injects dev secrets;
  pre-commit hook (gitleaks).
- **One class/module per file convention; ADR for every stack decision.**
- **Versioning:** semver per app; API versioned by path (/v1); server↔client compat matrix in docs.

## 8. Risks & Open Questions

| Risk | Mitigation |
|---|---|
| Rolling own SRP/crypto is dangerous | Only vetted libs (libsodium, x/crypto); SRP-6a per RFC 5054 implemented in-repo and locked down by golden cross-language test vectors; external audit in P7 |
| Podman-on-Windows quirks (npipe socket, registries.conf) | Verified compose subset; Tilt DOCKER_HOST docs; CI tests podman on Linux runners regardless |
| Next 16 async-request-APIs breaking changes vs old scaffold | Scaffold is ~stock; codemod + rebuild is low-risk |
| Browser extension stores (MV3 CSP vs WASM) | libsodium-wrappers is MV3-compatible (no remote code, wasm allowed with 'wasm-unsafe-eval') |
| Secret Key loss = permanent data loss (by design) | Emergency Kit UX front-and-center; recovery flows P6; loud warnings at signup |
| Scope: 1P-parity is years of work | Phase gates; each phase independently shippable (web-only MVP at end of P3) |

**Open questions for owner:** (1) Confirm name Kleidion? (2) Target self-hosted, SaaS, or both?
(architecture assumes both: same server binary, deployment differs) (3) License: source-available
(e.g. FSL/BSL) vs fully open (AGPL) vs proprietary? (4) GitHub org/repo name for the module path.

---

## 9. Execution Order (immediate next steps after plan approval)

1. Owner: confirm name + register domain (parallel with #2)
2. Phase 0 → Phase 1 executed via subagent-driven-development (fresh subagent per task, two-stage
   review); Phase 1 gets its own granular task breakdown (exact files, commands, verification per
   the writing-plans skill) before execution starts
3. Stop-and-review gate at end of Phase 1 (demo: `tilt up` on Docker **and** Podman)
4. Phase 2 detailed plan → security checkpoint before any feature work resumes
