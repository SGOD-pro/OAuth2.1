import { getDb } from "./mongo";
import { ensureTtlIndexes } from "./indexes";

export interface AdminAuditEvent {
  actorUserId?: string;
  actorEmail?: string;
  actorScope?: string | null;
  action: string;
  targetClientId?: string;
  targetUserId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  timestamp: Date;
}

export type AuthEventOutcome = "success" | "failure" | "denied";

export type AuthEventType =
  | "sign_in"
  | "sign_up"
  | "oauth_authorize"
  | "oauth_token"
  | "two_factor_challenge"
  | "two_factor_verify"
  | "recovery_code_verify"
  | "sign_out"
  | "password_reset"
  | "account_lockout"
  | "device_risk_elevated"
  | "device_risk_high";

export interface AuthAuditEvent {
  _id?: any;
  timestamp: Date;
  eventType: AuthEventType;
  outcome: AuthEventOutcome;
  sessionId?: string | null;
  userId?: string | null;
  targetIdentifier?: string | null;
  clientId?: string | null;
  clientName?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  reason?: string | null;
  details?: Record<string, unknown>;
}

const FORBIDDEN_EVENT_KEYS = new Set([
  "password",
  "newpassword",
  "currentpassword",
  "secret",
  "clientsecret",
  "token",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "code",
  "authorizationcode",
  "totp",
  "otp",
  "cookie",
  "sessiontoken",
  "credentials",
]);

export function sanitizeAuthEvent(event: Partial<AuthAuditEvent>): AuthAuditEvent {
  const now = new Date();
  const rawTs = event.timestamp ? new Date(event.timestamp) : now;
  const timestamp = isNaN(rawTs.getTime()) ? now : rawTs;

  const validOutcomes: AuthEventOutcome[] = ["success", "failure", "denied"];
  const outcome: AuthEventOutcome = validOutcomes.includes(event.outcome as any)
    ? (event.outcome as AuthEventOutcome)
    : "failure";

  const validTypes: AuthEventType[] = [
    "sign_in",
    "sign_up",
    "oauth_authorize",
    "oauth_token",
    "two_factor_challenge",
    "two_factor_verify",
    "recovery_code_verify",
    "sign_out",
    "password_reset",
    "account_lockout",
  ];
  const eventType: AuthEventType = validTypes.includes(event.eventType as any)
    ? (event.eventType as AuthEventType)
    : "sign_in";

  let safeSessionId: string | null = null;
  if (typeof event.sessionId === "string") {
    const trimmed = event.sessionId.trim();
    if (trimmed.length > 0 && trimmed.length <= 128 && !trimmed.startsWith("$")) {
      safeSessionId = trimmed;
    }
  }

  let safeTarget: string | null = null;
  if (typeof event.targetIdentifier === "string") {
    const trimmed = event.targetIdentifier.trim();
    if (trimmed.length > 0 && trimmed.length <= 256) {
      safeTarget = trimmed;
    }
  }

  let safeClientId: string | null = null;
  if (typeof event.clientId === "string") {
    const trimmed = event.clientId.trim();
    if (trimmed.length > 0 && trimmed.length <= 128 && !trimmed.startsWith("$")) {
      safeClientId = trimmed;
    }
  }

  let safeClientName: string | null = null;
  if (typeof event.clientName === "string") {
    const trimmed = event.clientName.trim();
    if (trimmed.length > 0 && trimmed.length <= 128) {
      safeClientName = trimmed;
    }
  }

  let safeUserId: string | null = null;
  if (typeof event.userId === "string") {
    const trimmed = event.userId.trim();
    if (trimmed.length > 0 && trimmed.length <= 128 && !trimmed.startsWith("$")) {
      safeUserId = trimmed;
    }
  }

  let safeIp: string | null = null;
  if (typeof event.ipAddress === "string") {
    const trimmed = event.ipAddress.trim();
    if (trimmed.length > 0 && trimmed.toLowerCase() !== "unknown" && trimmed.length <= 64) {
      safeIp = trimmed;
    }
  }

  let safeUserAgent: string | null = null;
  if (typeof event.userAgent === "string") {
    const trimmed = event.userAgent.trim();
    if (trimmed.length > 0) {
      safeUserAgent = trimmed.slice(0, 128);
    }
  }

  let safeReason: string | null = null;
  if (typeof event.reason === "string") {
    const trimmed = event.reason.trim();
    if (trimmed.length > 0) {
      safeReason = trimmed.slice(0, 128);
    }
  }

  const safeDetails: Record<string, unknown> = {};
  if (event.details && typeof event.details === "object" && !Array.isArray(event.details)) {
    for (const [key, val] of Object.entries(event.details)) {
      const lower = key.toLowerCase();
      if (FORBIDDEN_EVENT_KEYS.has(lower)) continue;
      if (typeof val === "string" || typeof val === "number" || typeof val === "boolean" || val === null) {
        safeDetails[key] = val;
      }
    }
  }

  return {
    timestamp,
    eventType,
    outcome,
    sessionId: safeSessionId,
    userId: safeUserId,
    targetIdentifier: safeTarget,
    clientId: safeClientId,
    clientName: safeClientName,
    ipAddress: safeIp,
    userAgent: safeUserAgent,
    reason: safeReason,
    ...(Object.keys(safeDetails).length > 0 ? { details: safeDetails } : {}),
  };
}

let authEventStoreFailureSimulated = false;

export function __simulateAuthEventStoreFailure(enable: boolean): void {
  authEventStoreFailureSimulated = enable;
}

export async function recordAuthEvent(event: Partial<AuthAuditEvent>): Promise<void> {
  if (authEventStoreFailureSimulated) {
    console.warn("[AUTH_EVENT] Simulated auth event store failure");
    return;
  }
  try {
    await ensureTtlIndexes();
    const db = await getDb();
    const sanitized = sanitizeAuthEvent(event);
    await db.collection<AuthAuditEvent>("auth_events").insertOne(sanitized);
  } catch (err) {
    console.error("[AUTH_EVENT] Failed to record auth event:", err);
  }
}

export async function recordAdminAudit(event: AdminAuditEvent): Promise<void> {
  try {
    await ensureTtlIndexes();
    const db = await getDb();
    await db.collection<AdminAuditEvent>("admin_audit").insertOne({
      ...event,
      timestamp: event.timestamp || new Date(),
    });
  } catch (err) {
    console.error("[AUDIT] Failed to record admin audit event:", err);
  }
}
