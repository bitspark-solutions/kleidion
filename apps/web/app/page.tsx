export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 px-6">
      <div className="flex items-center gap-3">
        <span
          aria-hidden
          className="grid size-10 place-items-center rounded-xl bg-accent text-lg font-bold text-accent-fg"
        >
          K
        </span>
        <h1 className="text-3xl font-semibold tracking-tight">Kleidion</h1>
      </div>
      <p className="max-w-md text-center text-fg-muted">
        Your keys, yours alone. Zero-knowledge password manager — end-to-end
        encrypted vaults for passwords, passkeys, cards and secure notes.
      </p>
      <div className="flex items-center gap-3">
        <a
          href="/signup"
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg hover:opacity-90"
        >
          Create account
        </a>
        <a
          href="/signin"
          className="rounded-md border border-border px-4 py-2 text-sm text-fg hover:text-accent"
        >
          Sign in
        </a>
      </div>
      <p className="rounded-full border border-border px-4 py-1.5 text-xs text-fg-muted">
        Zero-knowledge: passwords, shared vaults, TOTP and browser autofill —
        your keys never leave your devices.
      </p>
    </main>
  );
}
