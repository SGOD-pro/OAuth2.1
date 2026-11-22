/**
 * Database State & Persistence Facade
 * Re-exports partitioned database operations for indexes, audit events,
 * rate limiting, origin cache state, token families, and OAuth transactions.
 */

export { ensureTtlIndexes } from "./indexes";

export {
  type AdminAuditEvent,
  type AuthEventOutcome,
  type AuthEventType,
  type AuthAuditEvent,
  sanitizeAuthEvent,
  recordAuthEvent,
  recordAdminAudit,
  __simulateAuthEventStoreFailure,
} from "./audit-events";

export {
  type RateLimitEntry,
  type RateLimitDoc,
  incrementRateLimit,
  __simulateRateLimitStoreFailure,
} from "./rate-limits";

export {
  type OriginCacheDoc,
  getOriginCache,
  putOriginCache,
  invalidateOriginCache,
  getNextAuthoritativeVersion,
  incrementCacheVersionMongo,
  markSharedRedisOutage,
  getSharedRedisOutage,
} from "./origin-state";

export {
  type TokenFamilyDoc,
  registerTokenFamily,
  verifyAndRotateTokenFamily,
} from "./token-families";

export {
  type OAuthTransactionDoc,
  createOAuthTransaction,
  getOAuthTransaction,
  consumeOAuthTransaction,
} from "./oauth-transactions";
