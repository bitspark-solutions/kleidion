/**
 * Tiny fetch-based client for the Kleidion Phase 3 REST API (/v1).
 * Native fetch only; attaches `Authorization: Bearer <token>` from getToken().
 * Non-2xx -> ApiError carrying status + the server's {"error"} message.
 * Responses are validated against the contract zod schemas; parse failures
 * surface as ApiError with status 0 and a clear message.
 */
import { z } from "zod";
import {
  CreateVaultResponseSchema,
  ItemResponseSchema,
  ItemVersionsResponseSchema,
  ListItemsResponseSchema,
  ListVaultsResponseSchema,
  PostCursorResponseSchema,
  SyncChangesResponseSchema,
  type CreateItemInput,
  type CreateVaultInput,
  type CreateVaultResponse,
  type ItemResponse,
  type ItemVersionsResponse,
  type ListItemsParams,
  type ListItemsResponse,
  type ListVaultsResponse,
  type PostCursorInput,
  type PostCursorResponse,
  type SyncChangesParams,
  type SyncChangesResponse,
  type UpdateItemInput,
} from "./schemas.js";

/** Error thrown by the API client for HTTP failures and response-shape failures. */
export class ApiError extends Error {
  /** HTTP status; 0 when the server returned 2xx but the body failed validation. */
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Error thrown when a 2xx response body fails contract validation. */
export class ApiResponseError extends ApiError {
  constructor(message: string) {
    super(message, 0);
    this.name = "ApiResponseError";
  }
}

export interface ApiClientOptions {
  /** e.g. "http://localhost:8080" — no trailing path; "/v1" is appended per route. */
  baseUrl: string;
  /** Returns the current session token (sent as `Authorization: Bearer <token>`). */
  getToken: () => string;
  /** Override fetch (for tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined) continue;
    qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `?${s}` : "";
}

function zodErrorMessage(err: unknown): string {
  if (err instanceof z.ZodError) {
    const first = err.issues[0];
    const path = first?.path.length ? ` at "${first.path.join(".")}"` : "";
    return `response validation failed${path}: ${first?.message ?? "invalid"} (${err.issues.length} issue(s))`;
  }
  return `response validation failed: ${err instanceof Error ? err.message : String(err)}`;
}

export function createApiClient(options: ApiClientOptions) {
  const { baseUrl, getToken } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  const root = baseUrl.replace(/\/+$/, "");

  async function request<T>(
    method: string,
    path: string,
    responseSchema: z.ZodType<T>,
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${getToken()}`,
      Accept: "application/json",
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    let res: Response;
    try {
      res = await fetchImpl(`${root}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      throw new ApiError(
        `network error calling ${method} ${path}: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const text = await res.text();

    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      if (text) {
        try {
          const parsed = JSON.parse(text) as { error?: unknown };
          if (typeof parsed.error === "string" && parsed.error.length > 0) {
            message = parsed.error;
          } else {
            message = `HTTP ${res.status}: ${text}`;
          }
        } catch {
          message = `HTTP ${res.status}: ${text}`;
        }
      }
      throw new ApiError(message, res.status);
    }

    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      throw new ApiResponseError(
        `${method} ${path} returned a non-JSON body`,
      );
    }

    const result = responseSchema.safeParse(json);
    if (!result.success) {
      throw new ApiResponseError(
        `${method} ${path}: ${zodErrorMessage(result.error)}`,
      );
    }
    return result.data;
  }

  return {
    /** GET /v1/vaults -> {vaults:[VaultMeta]} */
    listVaults(): Promise<ListVaultsResponse> {
      return request("GET", "/v1/vaults", ListVaultsResponseSchema);
    },

    /** POST /v1/vaults -> {vault:VaultMeta} */
    createVault(input: CreateVaultInput): Promise<CreateVaultResponse> {
      return request("POST", "/v1/vaults", CreateVaultResponseSchema, input);
    },

    /** GET /v1/items?vaultId=&since=&searchHmac= -> {items:[Item], serverVersion:int} */
    listItems(params: ListItemsParams): Promise<ListItemsResponse> {
      return request(
        "GET",
        `/v1/items${buildQuery(params)}`,
        ListItemsResponseSchema,
      );
    },

    /** POST /v1/items -> {item:Item} */
    createItem(input: CreateItemInput): Promise<ItemResponse> {
      return request("POST", "/v1/items", ItemResponseSchema, input);
    },

    /** PUT /v1/items/:id -> {item:Item} */
    updateItem(id: string, input: UpdateItemInput): Promise<ItemResponse> {
      return request(
        "PUT",
        `/v1/items/${encodeURIComponent(id)}`,
        ItemResponseSchema,
        input,
      );
    },

    /** DELETE /v1/items/:id -> {item:Item} (soft delete; bumps version) */
    deleteItem(id: string): Promise<ItemResponse> {
      return request(
        "DELETE",
        `/v1/items/${encodeURIComponent(id)}`,
        ItemResponseSchema,
      );
    },

    /** GET /v1/items/:id/versions -> {versions:[{version,createdAt}]} */
    itemVersions(id: string): Promise<ItemVersionsResponse> {
      return request(
        "GET",
        `/v1/items/${encodeURIComponent(id)}/versions`,
        ItemVersionsResponseSchema,
      );
    },

    /** GET /v1/sync/changes?vaultId=&since= -> {changes:[Item], latestVersion:int, hasMore:bool} */
    syncChanges(params: SyncChangesParams): Promise<SyncChangesResponse> {
      return request(
        "GET",
        `/v1/sync/changes${buildQuery(params)}`,
        SyncChangesResponseSchema,
      );
    },

    /** POST /v1/sync/cursor (body: {vaultId,lastVersion,deviceId}) -> {ok:true} */
    postCursor(input: PostCursorInput): Promise<PostCursorResponse> {
      return request("POST", "/v1/sync/cursor", PostCursorResponseSchema, input);
    },
  };
}

export type KleidionApiClient = ReturnType<typeof createApiClient>;
