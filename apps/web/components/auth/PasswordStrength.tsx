"use client";

// Password strength meter: length + character classes + a short common-
// password check. No new dependencies.

import { useMemo } from "react";

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
  "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
  "letmein", "football", "shadow", "123123", "654321", "superman",
  "qazwsx", "michael", "password1", "password123", "admin", "welcome",
  "hello", "charlie", "donald", "login", "princess", "starwars", "solo",
  "passw0rd", "000000", "1234567", "123456789", "1234567890", "zaq1zaq1",
]);

export interface Strength {
  /** 0..4 */
  score: number;
  label: string;
  /** Tailwind color class for the bar segments. */
  color: string;
  hints: string[];
}

export function evaluatePassword(pw: string): Strength {
  if (!pw) return { score: 0, label: "Empty", color: "bg-border", hints: [] };

  const hints: string[] = [];
  const lower = pw.toLowerCase();

  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(lower.replace(/\d+$/, ""))) {
    return {
      score: 0,
      label: "Too common",
      color: "bg-danger",
      hints: ["This is a well-known password — attackers try it first."],
    };
  }

  let score = 0;
  if (pw.length >= 10) score++;
  if (pw.length >= 14) score++;
  if (pw.length >= 20) score++;

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 2) score++;
  if (classes >= 3) score++;
  if (classes >= 4) score++;

  // Penalize weak structure.
  if (pw.length < 8) score -= 2;
  if (/^(.)\1+$/.test(pw)) score -= 2; // all same char
  if (/^(012|123|234|345|456|567|678|789|abc|qwe|asd)/i.test(lower)) score -= 1;

  score = Math.max(0, Math.min(4, Math.floor(score / 1.5)));

  if (pw.length < 10) hints.push("Use at least 10 characters (14+ is better).");
  if (classes < 3) hints.push("Mix uppercase, lowercase, digits and symbols.");

  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  const colors = ["bg-danger", "bg-danger", "bg-amber-500", "bg-accent", "bg-accent"];
  return { score, label: labels[score], color: colors[score], hints };
}

export default function PasswordStrength({ password }: { password: string }) {
  const strength = useMemo(() => evaluatePassword(password), [password]);

  return (
    <div className="space-y-1.5" aria-live="polite">
      <div className="flex gap-1" role="img" aria-label={`Password strength: ${strength.label}`}>
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors ${
              i < strength.score || (strength.score > 0 && i === 0) ? strength.color : "bg-border"
            }`}
          />
        ))}
      </div>
      <div className="flex items-baseline justify-between">
        <span className="text-xs font-medium text-fg-muted">{strength.label}</span>
      </div>
      {strength.hints.map((h) => (
        <p key={h} className="text-xs text-fg-muted">
          {h}
        </p>
      ))}
    </div>
  );
}
