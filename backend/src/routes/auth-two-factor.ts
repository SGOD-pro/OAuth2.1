import type { Context } from "hono";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { recordAuthEvent } from "../db/state";
import { getTrustedClientIp } from "../utils/security";
import { config } from "../config";
import {
    resolveValidatedMfaOauthContext,
    resolveCandidateMfaUser,
    recordMfaPublicAppMembership,
    resolveVerifiedMfaSession,
} from "./auth-two-factor-context";

export * from "./auth-two-factor-context";

/**
 * Handle TOTP verification endpoint (/two-factor/verify-totp).
 */
export async function handleVerifyTotp(c: Context) {
    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
    const userAgent = c.req.header("user-agent");
    const safeUserAgent = userAgent ? userAgent.slice(0, 128) : null;

    const validatedContext = await resolveValidatedMfaOauthContext(c);
    const candidateUser = await resolveCandidateMfaUser(c);

    const res = await authProvider.handler(c.req.raw);
    const isSuccess = res.status < 400;

    let sessionId: string | null = null;
    let completedUserId: string | null = null;
    let actor: string | null = null;

    if (isSuccess) {
        const verified = await resolveVerifiedMfaSession(res);
        sessionId = verified.sessionId;
        completedUserId = verified.completedUserId;
        actor = verified.actor;

        if (completedUserId) {
            try {
                const database = await getDb();
                await recordMfaPublicAppMembership(database, completedUserId, validatedContext);
            } catch (err) {
                console.error("[TWO_FACTOR] Failed to record public app registration:", err);
            }
        }
    }

    await recordAuthEvent({
        eventType: "two_factor_verify",
        outcome: isSuccess ? "success" : "failure",
        sessionId,
        userId: isSuccess ? completedUserId : (candidateUser?.id || null),
        targetIdentifier: actor || candidateUser?.email || null,
        clientId: validatedContext?.clientId || null,
        clientName: validatedContext?.clientName || null,
        ipAddress: safeIp,
        userAgent: safeUserAgent,
        reason: isSuccess ? null : "invalid_totp_code",
        details: { method: "totp" },
    });

    return res;
}

/**
 * Handle recovery/backup code verification endpoint (/two-factor/verify-backup-code).
 */
export async function handleVerifyBackupCode(c: Context) {
    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
    const userAgent = c.req.header("user-agent");
    const safeUserAgent = userAgent ? userAgent.slice(0, 128) : null;

    const validatedContext = await resolveValidatedMfaOauthContext(c);
    const candidateUser = await resolveCandidateMfaUser(c);

    const res = await authProvider.handler(c.req.raw);
    const isSuccess = res.status < 400;

    let sessionId: string | null = null;
    let completedUserId: string | null = null;
    let actor: string | null = null;

    if (isSuccess) {
        const verified = await resolveVerifiedMfaSession(res);
        sessionId = verified.sessionId;
        completedUserId = verified.completedUserId;
        actor = verified.actor;

        if (completedUserId) {
            try {
                const database = await getDb();
                await recordMfaPublicAppMembership(database, completedUserId, validatedContext);
            } catch (err) {
                console.error("[TWO_FACTOR] Failed to record public app registration:", err);
            }
        }
    }

    await recordAuthEvent({
        eventType: "recovery_code_verify",
        outcome: isSuccess ? "success" : "failure",
        sessionId,
        userId: isSuccess ? completedUserId : (candidateUser?.id || null),
        targetIdentifier: actor || candidateUser?.email || null,
        clientId: validatedContext?.clientId || null,
        clientName: validatedContext?.clientName || null,
        ipAddress: safeIp,
        userAgent: safeUserAgent,
        reason: isSuccess ? null : "invalid_backup_code",
        details: { method: "backup_code" },
    });

    return res;
}
