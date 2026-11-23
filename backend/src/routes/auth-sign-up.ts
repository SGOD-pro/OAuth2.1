import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { recordAuthEvent } from "../db/state";
import {
    getTrustedClientIp,
    resolveOAuthClient,
    hasDangerousMongoKeys,
} from "../utils/security";
import { config } from "../config";
import { extractClientContext } from "./auth-client-context";

/**
 * Handle user registration (/sign-up/email).
 * Enforces input sanitization, client resolution, private app registration restrictions,
 * and privilege stripping on newly registered user documents.
 */
export async function handleSignUpEmail(c: any): Promise<Response> {
    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
    const userAgent = c.req.header("user-agent");
    const safeUserAgent = userAgent ? userAgent.slice(0, 128) : null;
    const body = await c.req.raw.clone().json().catch(() => null);
    const targetIdentifier = typeof body?.email === "string" ? body.email.trim() : null;

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

    // STRICT FAIL-CLOSED: Validate client identifier FIRST whenever provided
    let canonicalClientId: string | null = null;
    let clientDoc: any = null;
    if (clientId) {
        clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
            await recordAuthEvent({
                eventType: "sign_up",
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
        if (!clientDoc.isPublic && clientCtx.isBoundOAuthFlow) {
            await recordAuthEvent({
                eventType: "sign_up",
                outcome: "denied",
                clientId: canonicalClientId,
                clientName: clientDoc.client_name || clientDoc.name || null,
                targetIdentifier,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: "private_app_registration_disabled",
            });
            return c.json(
                {
                    status: false,
                    error: "registration_disabled",
                    message: "Self-registration is disabled for this private application. An administrator must provision your account.",
                },
                403
            );
        }
    }

    // Explicit sanitized payload to prevent mass assignment / privilege injection
    const sanitizedBody: Record<string, any> = {};
    if (body?.email && typeof body.email === "string") sanitizedBody.email = body.email.trim();
    if (body?.password && typeof body.password === "string") sanitizedBody.password = body.password;
    if (body?.name && typeof body.name === "string") sanitizedBody.name = body.name.trim();
    if (body?.callbackURL && typeof body.callbackURL === "string") sanitizedBody.callbackURL = body.callbackURL;

    const reqHeaders = new Headers(c.req.raw.headers);
    reqHeaders.set("content-type", "application/json");
    const sanitizedReq = new Request(c.req.raw.url, {
        method: c.req.raw.method,
        headers: reqHeaders,
        body: JSON.stringify(sanitizedBody),
    });

    const res = await authProvider.handler(sanitizedReq);
    const isSuccess = res.status >= 200 && res.status < 300;
    let createdUserId: string | null = null;

    if (isSuccess && body?.email) {
        try {
            const email = String(body.email).toLowerCase().trim();
            // Invariant: New user must NEVER possess admin or scoped privileges
            const updatedResult = await database.collection("user").findOneAndUpdate(
                { email },
                {
                    $unset: {
                        isSuperAdmin: "",
                        scopedClientId: "",
                        admin: "",
                        permissions: "",
                        clientId: "",
                        clientSecret: "",
                    },
                    $set: { role: "user" },
                },
                { returnDocument: "after" }
            );

            const createdUser = updatedResult?.value || updatedResult;
            if (createdUser) {
                createdUserId = String(createdUser.id || createdUser._id);
                if (canonicalClientId && clientDoc?.isPublic) {
                    await database.collection("user_app_registrations").updateOne(
                        { userId: createdUserId, clientId: canonicalClientId },
                        { $setOnInsert: { userId: createdUserId, clientId: canonicalClientId, registeredAt: new Date() } },
                        { upsert: true }
                    );
                }
            }
        } catch (err) {
            console.error("[SIGNUP] Failed to record app registration:", err);
        }
    }

    await recordAuthEvent({
        eventType: "sign_up",
        outcome: isSuccess ? "success" : "failure",
        userId: createdUserId,
        targetIdentifier,
        clientId: (clientCtx.isBoundOAuthFlow && canonicalClientId) ? canonicalClientId : null,
        clientName: (clientCtx.isBoundOAuthFlow && clientDoc) ? (clientDoc.client_name || clientDoc.name || null) : null,
        ipAddress: safeIp,
        userAgent: safeUserAgent,
        reason: isSuccess ? null : "registration_failed",
    });

    return res;
}
