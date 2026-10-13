/**
 * Minimal password generator panel (Phase 5 contract A.3): mode + length,
 * generation happens in the background worker (libsodium CSPRNG).
 */
import { useState } from "react";
import type { GeneratedData } from "../../lib/messages";
import { errMsg, send } from "./send";

type Mode = "password" | "passphrase";

export default function GeneratorPanel() {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("password");
  const [length, setLength] = useState(20);
  const [words, setWords] = useState(6);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function run() {
    try {
      const d = await send<GeneratedData>(
        mode === "passphrase" ? { type: "generate", mode, words } : { type: "generate", length },
      );
      setValue(d.password);
      setError(null);
      setCopied(false);
    } catch (e) {
      setError(errMsg(e));
    }
  }

  return (
    <section className="border-b border-border">
      <button
        type="button"
        onClick={() => {
          setOpen((o) => !o);
          if (!open && !value) void run();
        }}
        aria-expanded={open}
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold uppercase tracking-wider text-fg-muted hover:bg-surface-hover"
      >
        <span>Generator</span>
        <span>{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="space-y-2 px-3 pb-3">
          <div className="flex items-center gap-2">
            <div className="flex overflow-hidden rounded-md border border-border">
              {(["password", "passphrase"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMode(m)}
                  aria-pressed={mode === m}
                  className={`px-2 py-1 text-xs ${mode === m ? "bg-accent text-accent-fg" : "text-fg-muted"}`}
                >
                  {m === "password" ? "Chars" : "Words"}
                </button>
              ))}
            </div>
            <label className="flex items-center gap-1 text-xs text-fg-muted">
              {mode === "password" ? "Length" : "Words"}
              <select
                value={mode === "password" ? length : words}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (mode === "password") setLength(n);
                  else setWords(n);
                }}
                className="rounded-md border border-border bg-bg px-1.5 py-1 text-xs text-fg"
              >
                {mode === "password"
                  ? [16, 20, 24, 32].map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))
                  : [4, 6, 8].map((n) => (
                      <option key={n} value={n}>{n}</option>
                    ))}
              </select>
            </label>
            <button
              type="button"
              onClick={() => void run()}
              className="ml-auto rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-fg hover:opacity-90"
            >
              Regenerate
            </button>
          </div>
          <div className="flex items-center gap-2">
            <output className="min-w-0 flex-1 truncate rounded-md border border-border bg-bg px-2 py-1.5 font-mono text-xs text-fg">
              {value || "…"}
            </output>
            <button
              type="button"
              disabled={!value}
              onClick={() => {
                void navigator.clipboard?.writeText(value).then(() => setCopied(true));
              }}
              className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg disabled:opacity-40"
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          {error && <p role="alert" className="text-xs text-danger">{error}</p>}
        </div>
      )}
    </section>
  );
}
