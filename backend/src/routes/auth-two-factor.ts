import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { recordAuthEvent } from "../db/state";
import { getTrustedClientIp } from "../utils/security";
import { config } from "../config";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { attachOrdinaryBrowserSessionToResponse } from "../identity/session-adapter";
import { claimMatchedTotpStep, releaseTotpTimeStep, TotpReplayError } from "../identity/totp-replay-guard";
import {
    resolveValidatedMfaOauthContext,
    resolveCandidateMfaUser,
    recordMfaPublicAppMembership,
    resolveVerifiedMfaSession,
} from "./auth-two-factor-context";

export * from "./auth-two-factor-context";

function buildIsolatedTwoFactorRequest(c: Context): Request {
    const hasChallengeCookie = Boolean(getCookie(c, "better-auth.two_factor"));
    if (!hasChallengeCookie) return c.req.raw;
    const rawCookie = c.req.header("cookie");
    if (!rawCookie) return c.req.raw;
    const filteredCookie = rawCookie
        .split(";")
        .map((part) => part.trim())
        .filter((part) => part && !/^(?:__Secure-)?better-auth\.session_token=/.test(part))
        .join("; ");
    const headers = new Headers(c.req.raw.headers);
    if (filteredCookie) headers.set("cookie", filteredCookie);
    else headers.delete("cookie");
    return new Request(c.req.raw, { headers });
}

async function findUserById(database: any, userId: string) {
    const filters: any[] = [{ id: userId }, { _id: userId }];
    if (ObjectId.isValid(userId) && userId.length === 24) filters.push({ _id: new ObjectId(userId) });
    return database.collection("user").findOne({ $or: filters });
}

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
    const database = await getDb();

    let claimedStep: number | null = null;
    if (candidateUser?.id) {
        const body = await c.req.raw.clone().json().catch(() => null);
        const code = typeof body?.code === "string" ? body.code.trim() : "";
        if (code) {
            const uFilters: any[] = [{ userId: candidateUser.id }];
            if (ObjectId.isValid(candidateUser.id) && candidateUser.id.length === 24) {
                uFilters.push({ userId: new ObjectId(candidateUser.id) });
            }
            const twoFactorDoc = await database.collection("twoFactor").findOne({ $or: uFilters }).catch(() => null);
            // Skip replay-guard for enrollment verification (verified === false). The guard's purpose
            // is to prevent a stolen sign-in challenge code from being replayed. Enrollment just
            // confirms the user can generate a valid code from their own freshly-issued secret;
            // applying the guard here would cause the subsequent sign-in challenge to fail with 409
            // when both calls land in the same 30-second TOTP window.
            const isEnrollmentVerify = twoFactorDoc && twoFactorDoc.verified === false;
            if (twoFactorDoc?.secret && !isEnrollmentVerify) {
                try {
                    const ctx = await authProvider.$context;
                    claimedStep = await claimMatchedTotpStep({
                        database,
                        userId: candidateUser.id,
                        code,
                        encryptedSecret: twoFactorDoc.secret,
                        engineSecret: (ctx as any).secretConfig || ctx.secret,
                    });
                } catch (err) {
                    if (err instanceof TotpReplayError) {
                        return c.json({ error: "conflict", code: err.code, message: err.message }, 409);
                    }
                    throw err;
                }
            }
        }
    }

    let res = await authProvider.handler(buildIsolatedTwoFactorRequest(c));
    const isSuccess = res.status < 400;

    let sessionId: string | null = null;
    let completedUserId: string | null = null;
    let actor: string | null = null;
    let capacityDenied = false;

    if (!isSuccess && candidateUser?.id && claimedStep !== null) {
        await releaseTotpTimeStep(database, candidateUser.id, claimedStep);
    }

    if (isSuccess) {
        const verified = await resolveVerifiedMfaSession(res);
        sessionId = verified.sessionId;
        completedUserId = verified.completedUserId;
        actor = verified.actor;

        if (completedUserId) {
            try {
                await recordMfaPublicAppMembership(database, completedUserId, validatedContext);
                const userDoc = await findUserById(database, completedUserId);
                const attached = await attachOrdinaryBrowserSessionToResponse({
                    database,
                    res,
                    rawBrowserProof: getCookie(c, getBrowserSessionCookieName()),
                    userDoc,
                });
                res = attached.response;
                if (attached.capacityExceeded) {
                    capacityDenied = true;
                    sessionId = null;
                }
            } catch (err) {
                console.error("[TWO_FACTOR] Failed to finalize MFA session:", err);
            }
        }
    }

    await recordAuthEvent({
        eventType: "two_factor_verify",
        outcome: capacityDenied ? "denied" : isSuccess ? "success" : "failure",
        sessionId,
        userId: isSuccess ? completedUserId : (candidateUser?.id || null),
        targetIdentifier: actor || candidateUser?.email || null,
        clientId: validatedContext?.clientId || null,
        clientName: validatedContext?.clientName || null,
        ipAddress: safeIp,
        userAgent: safeUserAgent,
        reason: capacityDenied ? "session_set_full" : isSuccess ? null : "invalid_totp_code",
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
    const database = await getDb();

    let res = await authProvider.handler(buildIsolatedTwoFactorRequest(c));
    const isSuccess = res.status < 400;

    let sessionId: string | null = null;
    let completedUserId: string | null = null;
    let actor: string | null = null;
    let capacityDenied = false;

    if (isSuccess) {
        const verified = await resolveVerifiedMfaSession(res);
        sessionId = verified.sessionId;
        completedUserId = verified.completedUserId;
        actor = verified.actor;

        if (completedUserId) {
            try {
                await recordMfaPublicAppMembership(database, completedUserId, validatedContext);
                const userDoc = await findUserById(database, completedUserId);
                const attached = await attachOrdinaryBrowserSessionToResponse({
                    database,
                    res,
                    rawBrowserProof: getCookie(c, getBrowserSessionCookieName()),
                    userDoc,
                });
                res = attached.response;
                if (attached.capacityExceeded) {
                    capacityDenied = true;
                    sessionId = null;
                }
            } catch (err) {
                console.error("[TWO_FACTOR] Failed to finalize MFA backup session:", err);
            }
        }
    }

    await recordAuthEvent({
        eventType: "recovery_code_verify",
        outcome: capacityDenied ? "denied" : isSuccess ? "success" : "failure",
        sessionId,
        userId: isSuccess ? completedUserId : (candidateUser?.id || null),
        targetIdentifier: actor || candidateUser?.email || null,
        clientId: validatedContext?.clientId || null,
        clientName: validatedContext?.clientName || null,
        ipAddress: safeIp,
        userAgent: safeUserAgent,
        reason: capacityDenied ? "session_set_full" : isSuccess ? null : "invalid_backup_code",
        details: { method: "backup_code" },
    });

    return res;
}
