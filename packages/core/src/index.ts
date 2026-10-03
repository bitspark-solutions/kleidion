/**
 * @kleidion/core — Phase 3 contract: zod schemas, inferred TS types,
 * and a fetch-based API client. Authoritative spec:
 * .hermes/plans/phase3-contract.md
 */
export * from "./schemas.js";
export {
  ApiError,
  ApiResponseError,
  createApiClient,
  type ApiClientOptions,
  type KleidionApiClient,
} from "./api.js";
