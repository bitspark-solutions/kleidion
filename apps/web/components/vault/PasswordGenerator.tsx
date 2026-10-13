"use client";

// Password generator panel for the item editor. All randomness comes from
// @kleidion/crypto (libsodium CSPRNG); nothing here talks to the server.

import { useState } from "react";
import {
  generatePassphrase,
  generatePassword,
  passphraseEntropyBits,
  passwordEntropyBits,
  strengthLabel,
  type PassphraseRecipe,
  type PasswordRecipe,
} from "@kleidion/crypto";

export interface GeneratorResult {
  value: string;
  entropyBits: number;
}

type Mode = "password" | "passphrase";

const PASSWORD_DEFAULTS = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

const PASSPHRASE_DEFAULTS = {
  words: 6,
  separator: "-",
  capitalize: true,
  includeNumber: false,
};

function passwordRecipe(length: number, digits: boolean, symbols: boolean, excludeAmbiguous: boolean): PasswordRecipe {
  return { ...PASSWORD_DEFAULTS, length, digits, symbols, excludeAmbiguous };
}

function defaultPasswordRecipe(): PasswordRecipe {
  return passwordRecipe(
    PASSWORD_DEFAULTS.length,
    PASSWORD_DEFAULTS.digits,
    PASSWORD_DEFAULTS.symbols,
    PASSWORD_DEFAULTS.excludeAmbiguous,
  );
}

/** One-shot generation used by ItemEditor to pre-fill new Login items. */
export async function generateDefaultPassword(): Promise<string> {
  return generatePassword(defaultPasswordRecipe());
}

export default function PasswordGenerator({
  onGenerate,
}: {
  /** Called after every successful generation (initial open and each regenerate). */
  onGenerate: (result: GeneratorResult) => void;
}) {
  const [mode, setMode] = useState<Mode>("password");
  const [length, setLength] = useState(PASSWORD_DEFAULTS.length);
  const [digits, setDigits] = useState(PASSWORD_DEFAULTS.digits);
  const [symbols, setSymbols] = useState(PASSWORD_DEFAULTS.symbols);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(
    PASSWORD_DEFAULTS.excludeAmbiguous,
  );
  const [words, setWords] = useState(PASSPHRASE_DEFAULTS.words);
  const [capitalize, setCapitalize] = useState(PASSPHRASE_DEFAULTS.capitalize);
  const [includeNumber, setIncludeNumber] = useState(PASSPHRASE_DEFAULTS.includeNumber);
  const [busy, setBusy] = useState(false);
  const [bits, setBits] = useState<number | null>(null);

  function currentPasswordRecipe(): PasswordRecipe {
    return passwordRecipe(length, digits, symbols, excludeAmbiguous);
  }
  function currentPassphraseRecipe(): PassphraseRecipe {
    return { ...PASSPHRASE_DEFAULTS, words, capitalize, includeNumber };
  }

  async function run() {
    setBusy(true);
    try {
      if (mode === "password") {
        const recipe = currentPasswordRecipe();
        const value = await generatePassword(recipe);
        const e = passwordEntropyBits(recipe);
        setBits(e);
        onGenerate({ value, entropyBits: e });
      } else {
        const recipe = currentPassphraseRecipe();
        const value = await generatePassphrase(recipe);
        const e = passphraseEntropyBits(recipe);
        setBits(e);
        onGenerate({ value, entropyBits: e });
      }
    } finally {
      setBusy(false);
    }
  }

  const previewBits =
    mode === "password"
      ? passwordEntropyBits(currentPasswordRecipe())
      : passphraseEntropyBits(currentPassphraseRecipe());

  return (
    <div className="rounded-md border border-border bg-surface p-2.5 text-xs">
      <div className="flex items-center gap-2">
        <div className="flex rounded-md border border-border overflow-hidden">
          {(["password", "passphrase"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              aria-pressed={mode === m}
              className={`px-2 py-1 ${mode === m ? "bg-accent text-accent-fg" : "text-fg-muted hover:text-fg"}`}
            >
              {m === "password" ? "Chars" : "Words"}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => void run()}
          disabled={busy}
          className="rounded-md bg-accent px-2.5 py-1 font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "…" : "Regenerate"}
        </button>
        <span className="ml-auto text-fg-muted" aria-live="polite">
          ~{Math.round(previewBits)} bits · {strengthLabel(bits ?? previewBits)}
        </span>
      </div>

      {mode === "password" ? (
        <div className="mt-2 space-y-2">
          <label className="flex items-center gap-2">
            <span className="w-12 text-fg-muted">Length</span>
            <input
              type="range"
              min={8}
              max={64}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="flex-1 accent-accent"
              aria-label="Password length"
            />
            <span className="w-6 text-right tabular-nums text-fg">{length}</span>
          </label>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={digits} onChange={(e) => setDigits(e.target.checked)} className="accent-accent" />
              Digits
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} className="accent-accent" />
              Symbols
            </label>
            <label className="flex items-center gap-1.5">
              <input
                type="checkbox"
                checked={excludeAmbiguous}
                onChange={(e) => setExcludeAmbiguous(e.target.checked)}
                className="accent-accent"
              />
              No look-alikes (Il1O0)
            </label>
          </div>
        </div>
      ) : (
        <div className="mt-2 space-y-2">
          <label className="flex items-center gap-2">
            <span className="w-12 text-fg-muted">Words</span>
            <input
              type="range"
              min={3}
              max={8}
              value={words}
              onChange={(e) => setWords(Number(e.target.value))}
              className="flex-1 accent-accent"
              aria-label="Passphrase word count"
            />
            <span className="w-6 text-right tabular-nums text-fg">{words}</span>
          </label>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={capitalize} onChange={(e) => setCapitalize(e.target.checked)} className="accent-accent" />
              Capitalize
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={includeNumber} onChange={(e) => setIncludeNumber(e.target.checked)} className="accent-accent" />
              Add number
            </label>
          </div>
        </div>
      )}
    </div>
  );
}
