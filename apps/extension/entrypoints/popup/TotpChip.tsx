import { useEffect, useState } from "react";
import type { TotpData } from "../../lib/messages";
import { send } from "./send";

/** Live TOTP code for an item; recomputed in the background, refreshed here. */
export default function TotpChip({ itemId }: { itemId: string }) {
  const [data, setData] = useState<TotpData | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const d = await send<TotpData>({ type: "totp", itemId });
        if (!alive) return;
        setData(d);
        timer = setTimeout(tick, d.secondsRemaining * 1000 + 60);
      } catch {
        if (alive) setData(null);
      }
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [itemId]);

  if (!data) return null;
  const mid = data.code.length >= 8 ? 4 : 3;
  const display = `${data.code.slice(0, mid)} ${data.code.slice(mid)}`;
  const frac = data.secondsRemaining / data.period;

  return (
    <button
      type="button"
      title={`Expires in ${data.secondsRemaining}s — click to copy`}
      onClick={() => {
        void navigator.clipboard.writeText(data.code).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      className="flex items-center gap-2 rounded-md border border-border bg-surface px-2 py-1 text-xs text-fg hover:bg-surface-hover"
    >
      <span className="font-mono tabular-nums tracking-wider">
        {copied ? "Copied" : display}
      </span>
      <span className="relative h-1.5 w-10 overflow-hidden rounded-full bg-bg">
        <span
          className="absolute inset-y-0 left-0 bg-accent"
          style={{ width: `${Math.max(0, Math.min(1, frac)) * 100}%` }}
        />
      </span>
    </button>
  );
}
