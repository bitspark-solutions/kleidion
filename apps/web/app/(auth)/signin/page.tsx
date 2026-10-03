"use client";

// /signin — email + password + Secret Key -> SRP unlock -> /vault.
// Thin wrapper around LockScreen (same flow: the session is memory-only, so
// sign-in IS the unlock).

import Link from "next/link";
import LockScreen from "@/components/auth/LockScreen";

export default function SigninPage() {
  return (
    <div className="space-y-6">
      <LockScreen title="Sign in" redirectTo="/vault" />
      <p className="text-center text-sm text-fg-muted">
        No account yet?{" "}
        <Link href="/signup" className="font-medium text-accent hover:underline">
          Create one
        </Link>
      </p>
    </div>
  );
}
