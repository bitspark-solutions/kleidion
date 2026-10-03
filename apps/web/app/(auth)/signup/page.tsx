"use client";

// /signup — the real enrollment wizard:
//   1. email -> 2. password (strength meter) -> 3. key generation + enroll ->
//   4. Emergency Kit with mandatory "I saved it" gate -> 5. sign in -> /vault.
//
// All key material is generated locally in step 3 (Secret Key, salts, SRP
// verifier, X25519 keypair, AUK-wrapped blobs); only ciphertext reaches the
// server. The Secret Key is shown ONCE in step 4.

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import EmergencyKit from "@/components/auth/EmergencyKit";
import PasswordStrength, { evaluatePassword } from "@/components/auth/PasswordStrength";
import { signup, signin, type SignupResult } from "@/lib/auth-client";
import { ApiError } from "@/lib/api-base";

type Step = "email" | "password" | "creating" | "kit" | "done";

const inputCls =
  "w-full rounded-xl border border-border bg-bg px-3.5 py-2.5 text-sm outline-none transition-colors placeholder:text-fg-muted/50 focus:border-accent";

export default function SignupPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [result, setResult] = useState<SignupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const strength = evaluatePassword(password);

  function onNextEmail(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setStep("password");
  }

  function onNextPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (strength.score < 2) {
      setError("Please choose a stronger password (Fair or better).");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    void createAccount();
  }

  async function createAccount() {
    setBusy(true);
    setError(null);
    setStep("creating");
    try {
      const res = await signup({ email, password });
      setResult(res);
      setStep("kit");
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError("That email is already registered. Try signing in instead.");
        setStep("email");
      } else if (err instanceof Error) {
        setError(err.message || "Signup failed.");
        setStep("password");
      } else {
        setError("Signup failed.");
        setStep("password");
      }
    } finally {
      setBusy(false);
    }
  }

  async function finishAndEnter() {
    if (!result) return;
    setBusy(true);
    setError(null);
    setStep("done");
    try {
      // Enroll returns no session; unlock via a real SRP sign-in so the vault
      // starts in the same unlocked state as any other device.
      await signin({ email: result.email, password, secretKey: result.secretKey });
      router.replace("/vault");
    } catch (err) {
      setError(
        err instanceof Error
          ? `Account created, but unlocking failed: ${err.message}. You can sign in from the sign-in page.`
          : "Account created, but unlocking failed. Please sign in.",
      );
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {step === "email" && (
        <form onSubmit={onNextEmail} className="space-y-5">
          <Header
            title="Create your account"
            sub="Step 1 of 3 — your email. Nothing you type here is ever stored on our servers in a readable form."
          />
          <ErrorBanner error={error} />
          <div className="space-y-1.5">
            <label htmlFor="su-email" className="text-xs uppercase tracking-wide text-fg-muted">
              Email
            </label>
            <input
              id="su-email"
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={inputCls}
              placeholder="you@example.com"
            />
          </div>
          <PrimaryButton type="submit">Continue</PrimaryButton>
          <SignInLink />
        </form>
      )}

      {step === "password" && (
        <form onSubmit={onNextPassword} className="space-y-5">
          <Header
            title="Choose your master password"
            sub="Step 2 of 3 — this encrypts your vault. It never leaves your browser, and we cannot reset it for you."
          />
          <ErrorBanner error={error} />
          <div className="space-y-1.5">
            <label htmlFor="su-pw" className="text-xs uppercase tracking-wide text-fg-muted">
              Master password
            </label>
            <input
              id="su-pw"
              type="password"
              required
              minLength={8}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputCls}
              placeholder="••••••••••••"
            />
            {password && <PasswordStrength password={password} />}
          </div>
          <div className="space-y-1.5">
            <label htmlFor="su-pw2" className="text-xs uppercase tracking-wide text-fg-muted">
              Confirm password
            </label>
            <input
              id="su-pw2"
              type="password"
              required
              minLength={8}
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={inputCls}
              placeholder="••••••••••••"
            />
          </div>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => setStep("email")}
              className="rounded-xl border border-border px-4 py-2.5 text-sm text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
            >
              Back
            </button>
            <PrimaryButton type="submit">Create account</PrimaryButton>
          </div>
          <SignInLink />
        </form>
      )}

      {step === "creating" && (
        <div className="space-y-4 py-6 text-center">
          <p className="text-sm text-fg-muted">
            {busy ? "Generating your Secret Key and deriving encryption keys…" : "Working…"}
          </p>
          <p className="text-xs text-fg-muted">
            This runs Argon2id locally and can take a few seconds.
          </p>
        </div>
      )}

      {step === "kit" && result && (
        <div className="space-y-4">
          <Header
            title="Step 3 of 3 — save your Emergency Kit"
            sub="Your account is created. Before you continue, save your Secret Key — you will never see it again."
          />
          <ErrorBanner error={error} />
          <EmergencyKit
            email={result.email}
            accountId={result.accountId}
            secretKey={result.secretKey}
            onContinue={finishAndEnter}
            continueLabel="I saved it — unlock my vault"
          />
        </div>
      )}

      {step === "done" && (
        <div className="space-y-4 py-6 text-center">
          <p className="text-sm text-fg-muted">Unlocking your vault…</p>
          <ErrorBanner error={error} />
          {error && (
            <Link
              href="/signin"
              className="inline-block rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-accent-fg"
            >
              Go to sign in
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

function Header({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-1 text-sm text-fg-muted">{sub}</p>
    </div>
  );
}

function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
      {error}
    </p>
  );
}

function PrimaryButton({ children, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className="w-full rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-accent-fg transition-opacity disabled:cursor-not-allowed disabled:opacity-60"
    >
      {children}
    </button>
  );
}

function SignInLink() {
  return (
    <p className="text-center text-sm text-fg-muted">
      Already have an account?{" "}
      <Link href="/signin" className="font-medium text-accent hover:underline">
        Sign in
      </Link>
    </p>
  );
}
