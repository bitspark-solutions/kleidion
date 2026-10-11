/**
 * Pure host/title helpers shared by web + extension for autofill URL -> item
 * matching. No platform dependencies (safe in service workers and content
 * scripts).
 */

/** Title normalization identical to @kleidion/crypto's searchHmac input. */
export function normalizeTitle(title: string): string {
  return title.trim().toLowerCase().replace(/\s+/g, " ");
}

/** Extract a lowercase hostname from a full URL, "host:port", or bare host. */
export function hostnameFrom(input: string): string {
  let host = input.trim().toLowerCase();
  if (!host) return "";
  if (host.includes("://")) {
    try {
      host = new URL(host).hostname;
    } catch {
      host = host.replace(/^[^:/?#]+:\/\//, "");
    }
  }
  host = host.split("/")[0] ?? "";
  const colon = host.lastIndexOf(":");
  // Strip a trailing numeric port; leave bracketed IPv6 literals alone.
  if (colon > -1 && !host.includes("]")) {
    const maybePort = host.slice(colon + 1);
    if (/^\d*$/.test(maybePort)) host = host.slice(0, colon);
  }
  return host;
}

// Common two-level public suffixes so baseDomain keeps "shop.co.uk" intact.
// Not a full PSL — enough to avoid the worst over/under-matching.
const TWO_LEVEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.br", "co.za", "com.cn", "net.cn", "org.cn",
  "co.in", "com.mx", "com.tr", "com.tw", "co.kr", "com.sg", "com.hk",
]);

/**
 * Registrable domain of a host: the last two labels, or three when the parent
 * is a known two-level public suffix ("mail.google.com" -> "google.com",
 * "www.shop.co.uk" -> "shop.co.uk"). "localhost" and single-label hosts return
 * themselves.
 */
export function baseDomain(input: string): string {
  let host = hostnameFrom(input);
  if (host.startsWith("www.")) host = host.slice(4);
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  const take = TWO_LEVEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  return parts.slice(-take).join(".");
}

function stripWww(host: string): string {
  return host.startsWith("www.") ? host.slice(4) : host;
}

/**
 * True when a page host and an item host should be treated as the same site:
 * an exact match after www-normalization, or the same registrable (base)
 * domain. This covers subdomains and sibling subdomains — a "Google" login
 * stored with accounts.google.com autofills on mail.google.com — while still
 * rejecting unrelated domains (evil-google.com vs google.com).
 *
 * Limitation: hosts under a shared two-level suffix (e.g. *.blogspot.com)
 * compare equal; real deployments rely on the item's stored URL list, so this
 * heuristic is the safety net, not the sole matcher.
 */
export function domainsEquivalent(a: string, b: string): boolean {
  const ha = stripWww(hostnameFrom(a));
  const hb = stripWww(hostnameFrom(b));
  if (!ha || !hb) return false;
  if (ha === hb) return true;
  return baseDomain(ha) === baseDomain(hb);
}
