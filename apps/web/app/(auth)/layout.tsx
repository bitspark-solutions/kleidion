// Shared layout for the auth routes (/signin, /signup): centered card on the
// dark theme, matching the marketing page's tone.

import Link from "next/link";

export default function AuthLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 py-12">
      <Link href="/" className="mb-8 flex items-center gap-3">
        <span
          aria-hidden
          className="grid size-10 place-items-center rounded-xl bg-accent text-lg font-bold text-accent-fg"
        >
          K
        </span>
        <span className="text-2xl font-semibold tracking-tight">Kleidion</span>
      </Link>
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-6 sm:p-8">
        {children}
      </div>
      <p className="mt-8 max-w-md text-center text-xs text-fg-muted">
        Zero-knowledge by design — your password and Secret Key never leave this browser.
      </p>
    </main>
  );
}
