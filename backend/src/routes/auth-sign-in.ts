import { getCookie } from "hono/cookie";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import {
    getOAuthTransaction,
    recordAuthEvent,
} from "../db/state";
import {
    getTrustedClientIp,
    resolveOAuthClient,
    checkUserAppRegistration,
    checkUserHasAppAccess,
    hasDangerousMongoKeys,
} from "../utils/security";
import { config } from "../config";
import { extractClientContext, executeDummyHash } from "./auth-client-context";
import { enforceTargetRateLimit } from "./auth-rate-limit";

/**
 * Handle password sign-in (/sign-in/email).
 * Enforces rate limiting, dummy timing equalization, private application membership checks,
 * MFA challenge interception, and public application registration.
 */
export async function handleSignInEmail(c: any): Promise<Response> {
    const body = await c.req.raw.clone().json().catch(() => null);

    // Defense against NoSQL operator injection and prototype pollution
    if (body && hasDangerousMongoKeys(body)) {
        return c.json(
            {
                status: false,
                error: "invalid_input",
                message: "Invalid input: operator injection and prototype modification rejected",
            },
            400
        );
    }

    if (body && (body.email !== undefined && typeof body.email !== "string")) {
        return c.json(
            {
                status: false,
                error: "invalid_input",
                message: "Email must be a primitive string",
            },
            400
        );
    }

    const clientCtx = await extractClientContext(c, body);
    const clientId = clientCtx.clientId;
    const database = await getDb();

    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
    const safeUserAgent = c.req.header("user-agent") ? c.req.header("user-agent")!.slice(0, 128) : null;
    const targetIdentifier = typeof body?.email === "string" ? body.email.toLowerCase().trim().slice(0, 256) : null;

    // STRICT FAIL-CLOSED: Validate client identifier FIRST whenever provided
    let clientDoc: any = null;
    let canonicalClientId: string | null = null;
    if (clientId) {
        clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
            await recordAuthEvent({
                eventType: "sign_in",
                outcome: "denied",
                clientId,
                targetIdentifier,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: clientDoc?.disabled ? "client_disabled" : (clientDoc?.isAmbiguous ? "client_ambiguous" : "invalid_client"),
            });
            return c.json(
                {
                    status: false,
                    error: "invalid_client",
                    message: "Client application not found, disabled, or ambiguous",
                },
                400
            );
        }
        canonicalClientId = clientDoc.clientId;
    }

    const boundClientId = (clientCtx.isBoundOAuthFlow && canonicalClientId) ? canonicalClientId : null;
    const boundClientName = (clientCtx.isBoundOAuthFlow && clientDoc) ? (clientDoc.client_name || clientDoc.name || null) : null;

    if (body?.email && typeof body.email === "string") {
        const normalizedEmail = body.email.toLowerCase().trim();

        const rateLimitResult = await enforceTargetRateLimit(normalizedEmail, {
            targetIdentifier,
            clientId: boundClientId,
            clientName: boundClientName,
            ipAddress: safeIp,
            userAgent: safeUserAgent,
        });

        if (!rateLimitResult.allowed && rateLimitResult.errorResponse) {
            return c.json(
                {
                    error: rateLimitResult.errorResponse.error,
                    message: rateLimitResult.errorResponse.message,
                },
                rateLimitResult.errorResponse.status
            );
        }

        const user = await database.collection("user").findOne({ email: normalizedEmail });
        if (!user) {
            // Equalize CPU timing with real password verification
            await executeDummyHash();
        } else if (user.disabled === true || user.isActive === false || user.banned === true) {
            await executeDummyHash();
            await recordAuthEvent({
                eventType: "sign_in",
                outcome: "denied",
                userId: String(user.id || user._id),
                targetIdentifier,
                clientId: boundClientId,
                clientName: boundClientName,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: "account_disabled",
            });
            return c.json(
                {
                    status: false,
                    error: "access_denied",
                    message: "This account has been deactivated or disabled",
                },
                401
            );
        } else if (clientDoc && (clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false)) && canonicalClientId && clientCtx.isBoundOAuthFlow) {
            // Private application: verify authorization boundary before proceeding
            const hasAccess = await checkUserHasAppAccess(database, user, canonicalClientId);

            if (!hasAccess) {
                await recordAuthEvent({
                    eventType: "sign_in",
                    outcome: "denied",
                    userId: String(user.id || user._id),
                    targetIdentifier,
                    clientId: canonicalClientId,
                    clientName: clientDoc.client_name || clientDoc.name || null,
                    ipAddress: safeIp,
                    userAgent: safeUserAgent,
                    reason: "private_app_unauthorized",
                });
                return c.json(
                    {
                        status: false,
                        error: "access_denied",
                        message: "Access restricted: This application is in private mode and your account has not been authorized. Please contact an administrator.",
                    },
                    403
                );
            }
        }
    }

    // Forward authentication request to Better Auth
    const res = await authProvider.handler(c.req.raw);

    // CRITICAL SECURITY INVARIANT: Application membership MUST NEVER mutate before successful authentication
    if (res.status >= 200 && res.status < 300) {
        let authUserId: string | null = null;
        if (body?.email) {
            try {
                const normalizedEmail = body.email.toLowerCase().trim();
                const authUser = await database.collection("user").findOne({ email: normalizedEmail });
                if (authUser) {
                    authUserId = String(authUser.id || authUser._id);
                }
            } catch (err) {
                console.error("[SIGNIN] Failed to find user for audit:", err);
            }
        }

        const resClone = res.clone();
        const resJson = await resClone.json().catch(() => null);
        const isTwoFactorRequired = Boolean(resJson?.twoFactorRedirect);

        if (isTwoFactorRequired) {
            if (clientCtx.isBoundOAuthFlow && authUserId) {
                const txIdCookie = getCookie(c, "oauth_transaction_id");
                const txIdQuery = c.req.query("transaction_id");
                const state = c.req.query("state");
                const candidateTxId = txIdCookie || txIdQuery;
                if (candidateTxId || state) {
                    try {
                        const tx = await getOAuthTransaction({ transactionId: candidateTxId || undefined, state: state || undefined });
                        if (tx && tx.status === "pending") {
                            await database.collection("oauth_transactions").updateOne(
                                { transactionId: tx.transactionId, status: "pending" },
                                { $set: { userId: authUserId } }
                            );
                        }
                    } catch {}
                }
            }

            await recordAuthEvent({
                eventType: "two_factor_challenge",
                outcome: "success",
                userId: authUserId,
                targetIdentifier,
                clientId: boundClientId,
                clientName: boundClientName,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: "two_factor_required",
                details: { stage: "two_factor_challenge" },
            });
            return res;
        }

        // Single-factor completed login: extract established session ID
        let sessionId: string | null = null;
        try {
            const setCookieList: string[] = (res.headers as any).getSetCookie
                ? (res.headers as any).getSetCookie()
                : [res.headers.get("set-cookie") || ""];
            for (const header of setCookieList) {
                const match = header.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
                if (match) {
                    const rawToken = decodeURIComponent(match[1]);
                    const token = rawToken.split(".")[0];
                    const sessionDoc = await database.collection("session").findOne({ token });
                    if (sessionDoc) {
                        sessionId = String(sessionDoc._id || sessionDoc.id);
                        break;
                    }
                }
            }
        } catch {}

        const isOpen = clientDoc?.accessPolicy === "open" || clientDoc?.isPublic === true;
        if (authUserId && clientDoc && isOpen && canonicalClientId && !config.openAppMembershipBypassEnabled) {
            try {
                const isRegistered = await checkUserAppRegistration(database, authUserId, canonicalClientId);
                if (!isRegistered) {
                    await database.collection("user_app_registrations").insertOne({
                        userId: authUserId,
                        clientId: canonicalClientId,
                        registeredAt: new Date(),
                    }).catch((err: any) => {
                        if (err?.code === 11000) return;
                        throw err;
                    });
                }
            } catch (err) {
                console.error("[SIGNIN] Failed to record public app registration:", err);
            }
        }

        await recordAuthEvent({
            eventType: "sign_in",
            outcome: "success",
            sessionId,
            userId: authUserId,
            targetIdentifier,
            clientId: boundClientId,
            clientName: boundClientName,
            ipAddress: safeIp,
            userAgent: safeUserAgent,
        });
    } else {
        await recordAuthEvent({
            eventType: "sign_in",
            outcome: "failure",
            targetIdentifier,
            clientId: boundClientId,
            clientName: boundClientName,
            ipAddress: safeIp,
            userAgent: safeUserAgent,
            reason: "invalid_credentials",
        });
    }

    return res;
}
