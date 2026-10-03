// API base URL + minimal JSON fetch helper with server-error extraction.
// The Go server answers errors uniformly as {"error": "..."} (see
// apps/server/internal/api/auth_handlers.go respondError).

/** Base URL of the Kleidion API. */
export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:18080";

/** Error carrying the HTTP status so callers can branch on 401/409. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface FetchJsonOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  /** Bearer token (session auth). */
  token?: string;
  signal?: AbortSignal;
}

/**
 * fetch + JSON with uniform error handling. Throws ApiError on non-2xx with
 * the server's {"error"} message when present.
 */
export async function fetchJson<T>(path: string, opts: FetchJsonOptions = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    });
  } catch {
    throw new ApiError(0, "Cannot reach the Kleidion server. Is it running?");
  }

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      // Non-JSON body (proxy error page etc.) — fall through to status text.
    }
  }

  if (!res.ok) {
    const msg =
      data && typeof data === "object" && "error" in data
        ? String((data as { error: unknown }).error)
        : `Request failed with status ${res.status}`;
    throw new ApiError(res.status, msg);
  }

  return data as T;
}
