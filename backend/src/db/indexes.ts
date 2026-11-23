import { getDb } from "./mongo";
import { selfHealAppAdmins } from "../utils/admin-sync";

let indexPromise: Promise<void> | null = null;

export async function ensureTtlIndexes(): Promise<void> {
  indexPromise ??= (async () => {
    const db = await getDb();

    const safeIndex = async (col: string, spec: any, options?: any) => {
      try {
        await db.collection(col).createIndex(spec, options);
      } catch (err: any) {
        // Code 85: IndexOptionsConflict / IndexKeySpecsConflict - ignore if already exists
        if (err?.code !== 85 && err?.codeName !== "IndexOptionsConflict" && err?.code !== 86) {
          console.warn(`[INDEX] Warning creating index on ${col}:`, err?.message || err);
        }
      }
    };

    await Promise.all([
      safeIndex("rate_limits", { createdAt: 1 }, { expireAfterSeconds: 60 }),
      safeIndex("origin_cache", { cachedAt: 1 }, { expireAfterSeconds: 300 }),
      safeIndex("oauth_token_families", { familyId: 1 }, { unique: true }),
      safeIndex("oauth_token_families", { activeTokenHash: 1 }),
      safeIndex("oauth_token_families", { consumedTokenHashes: 1 }),
      safeIndex("oauth_token_families", { clientId: 1, activeTokenHash: 1 }),
      safeIndex("oauthClient", { clientId: 1 }),
      safeIndex("oauthRefreshToken", { token: 1 }),
      safeIndex("oauthAccessToken", { token: 1 }),
      safeIndex("oauthAuthorizationCode", { code: 1 }),
      safeIndex("oauthAuthorizationCode", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("admin_audit", { timestamp: -1 }),
      safeIndex("auth_events", { timestamp: 1 }, { expireAfterSeconds: 90 * 24 * 3600 }),
      safeIndex("auth_events", { timestamp: -1 }),
      safeIndex("auth_events", { eventType: 1, timestamp: -1 }),
      safeIndex("auth_events", { outcome: 1, timestamp: -1 }),
      safeIndex("auth_events", { clientId: 1, timestamp: -1 }),
      safeIndex("auth_events", { userId: 1, timestamp: -1 }),
      safeIndex("auth_events", { sessionId: 1, timestamp: -1 }),
      safeIndex("user_app_registrations", { clientId: 1, userId: 1 }, { unique: true }),
      safeIndex("oauthClient", { allowedOrigins: 1, disabled: 1 }),
      safeIndex("oauthClient", { allowed_origins: 1, disabled: 1 }),
      safeIndex("oauthClient", { redirectUris: 1, disabled: 1 }),
      safeIndex("oauthClient", { redirect_uris: 1, disabled: 1 }),
      safeIndex("user", { email: 1 }),
      safeIndex("session", { token: 1 }),
      safeIndex("session", { userId: 1 }),
      safeIndex("session", { createdAt: -1 }),
      safeIndex("oauth_transactions", { expiresAt: 1 }, { expireAfterSeconds: 0 }),
      safeIndex("oauth_transactions", { transactionId: 1 }, { unique: true }),
      safeIndex("oauth_transactions", { state: 1 }),
    ]);

    // Automatically synchronize app administrators into centralized user & account collections
    try {
      await selfHealAppAdmins(db);
    } catch (healErr: any) {
      console.warn("[INDEX] Warning during self-healing app_admins sync:", healErr?.message || healErr);
    }
  })();

  return indexPromise;
}
