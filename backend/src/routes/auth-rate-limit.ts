import crypto from "crypto";
import { incrementRateLimit, recordAuthEvent } from "../db/state";
import { rateLimiters, checkRateLimit } from "../cache/redis";

/**
 * Enforce target-keyed rate limiting (IP-rotation resistant credential stuffing defense).
 */
export async function enforceTargetRateLimit(
    normalizedEmail: string,
    context: {
        targetIdentifier: string | null;
        clientId: string | null;
        clientName: string | null;
        ipAddress: string | null;
        userAgent: string | null;
    }
): Promise<{ allowed: boolean; errorResponse?: { error: string; message: string; status: number } }> {
    let targetAllowed = true;
    const targetHash = crypto.createHash("sha256").update(normalizedEmail).digest("hex");
    const targetKey = `TARGET#${targetHash}`;
    const targetWindowMs = 300 * 1000;
    const targetLimit = 15;

    let redisEvaluated = false;
    if (rateLimiters?.credentialStuffingTarget) {
        const targetResult = await checkRateLimit(
            rateLimiters.credentialStuffingTarget,
            `email:${normalizedEmail}`
        );
        if (targetResult.remaining !== -1) {
            redisEvaluated = true;
            if (!targetResult.allowed) {
                targetAllowed = false;
            }
        }
    }

    if (!redisEvaluated) {
        try {
            const entry = await incrementRateLimit(targetKey, Date.now(), targetWindowMs);
            if (entry.count > targetLimit) {
                targetAllowed = false;
            }
        } catch (mongoErr) {
            console.error("[AUTH] Target rate limit store error, failing closed:", mongoErr);
            targetAllowed = false;
        }
    }

    if (!targetAllowed) {
        await recordAuthEvent({
            eventType: "account_lockout",
            outcome: "denied",
            targetIdentifier: context.targetIdentifier,
            clientId: context.clientId,
            clientName: context.clientName,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            reason: "rate_limit_exceeded",
            details: { threshold: 15, windowSeconds: 300 },
        });
        return {
            allowed: false,
            errorResponse: {
                error: "too_many_requests",
                message: "Too many sign-in attempts for this account. Please try again later.",
                status: 429,
            },
        };
    }

    return { allowed: true };
}
