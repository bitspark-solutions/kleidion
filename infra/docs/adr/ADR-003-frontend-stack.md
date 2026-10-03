# ADR-003: Frontend stack — Next.js 16, React 19, TypeScript 5.9, Tailwind 4, shadcn/ui

Date: 2026-10-03 · Status: accepted

## Decision
- Upgrade the scaffold from Next 14.2.3/React 18 to **Next.js 16.3.8 / React 19.3** (latest stable
  at 2026-10-03), TypeScript **5.9** (not TS 7 yet — ecosystem type packages still catching up;
  revisit when @types/* are all TS7-native).
- Replace MUI v5 (installed but never imported) with **Tailwind CSS 4 + shadcn/ui**.
- Drop NextAuth, Firebase and the Firestore adapter entirely: auth is our own SRP flow against the
  Go server; no third-party identity provider stores anything about users.

## Rationale
- Tailwind/shadcn: smaller bundles (critical for MV3 extension content scripts), full styling
  control for the vault UI, zero runtime CSS-in-JS (CSP-friendly — MV3 forbids unsafe-eval).
- Next 16: stable React 19, async request APIs, Turbopack default dev.
- Firebase in a zero-knowledge product would put user identifiers/session data on Google infra —
  against the privacy-by-design principle.

## Migration notes
- Old `app/api/auth/[...nextauth]/route.ts`, `firebaseConfig.ts`, `types/next-auth.d.ts` deleted in
  Phase 0 (no runtime code referenced them besides themselves).
- `npx @next/codemod@latest upgrade latest` handles async-request-API rewrites when upgrading.
