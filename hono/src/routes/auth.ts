import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOriginCache, putOriginCache, registerTokenFamily, verifyAndRotateTokenFamily } from "../db/state";
import { getTrustedClientIp } from "../utils/security";
import { config } from "../config";

export const auth = new Hono();

// Helper to extract clientId from various locations
function extractClientId(c: any, body?: any): string | null {
    const query = c.req.query("client_id");
    if (query) return query;

    if (body?.clientId) return body.clientId;
    if (body?.client_id) return body.client_id;

    const cookieVal = getCookie(c, "current_client_id");
    if (cookieVal) return cookieVal;

    return null;
}

// Constant-time dummy hash computation to prevent login timing enumeration (Fix B10)
async function executeDummyHash(): Promise<void> {
    return new Promise((resolve) => {
        crypto.scrypt("DummyPassword@123!", "dummy_salt_constant_time_98234", 64, { N: 16384, r: 8, p: 1 }, () => {
            resolve();
        });
    });
}

// 1. Initiate OAuth Flow
auth.get("/oauth/initiate", async (c) => {
    const clientId = c.req.query("client_id");
    const redirect_uri = c.req.query("redirect_uri") || "/";

    if (clientId) {
        setCookie(c, "current_client_id", clientId, {
            path: "/",
            httpOnly: true,
            secure: config.env === "production",
            sameSite: "Lax",
            maxAge: 60 * 10,
        });
    }

    return c.json({ success: true, redirect_uri });
});

// 2. Sign-In App-Isolation Check + Constant-Time Protection (Fix B10)
auth.post("/sign-in/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = extractClientId(c, body);
    const database = await getDb();

    if (body?.email) {
        const user = await database.collection("user").findOne({ email: body.email.toLowerCase().trim() });
        if (!user) {
            // Equalize CPU timing with real password verification (Fix B10)
            await executeDummyHash();
        } else if (clientId) {
            const reg = await database.collection("user_app_registrations").findOne({
                $or: [
                    { userId: String(user._id), clientId },
                    { userId: user._id, clientId },
                    ...(user.id ? [{ userId: user.id, clientId }] : []),
                ],
            });

            if (!reg) {
                return c.json(
                    {
                        status: false,
                        message: "User is not registered for this application. Please register first.",
                    },
                    400
                );
            }
        }
    }

    return authProvider.handler(c.req.raw);
});

// 3. Sign-Up App-Isolation Registration
auth.post("/sign-up/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = extractClientId(c, body);
    const database = await getDb();

    if (body?.email) {
        const email = body.email.toLowerCase().trim();
        const existingUser = await database.collection("user").findOne({ email });

        if (existingUser && clientId) {
            const reg = await database.collection("user_app_registrations").findOne({
                $or: [
                    { userId: String(existingUser._id), clientId },
                    { userId: existingUser._id, clientId },
                    ...(existingUser.id ? [{ userId: existingUser.id, clientId }] : []),
                ],
            });

            if (reg) {
                return c.json(
                    {
                        status: false,
                        message: "User is already registered for this application. Please login instead.",
                    },
                    400
                );
            }

            // Register existing user for new application
            await database.collection("user_app_registrations").insertOne({
                userId: String(existingUser.id || existingUser._id),
                clientId,
                registeredAt: new Date(),
            });

            return c.json({
                status: true,
                message: "Existing user linked to new application successfully. Please login.",
                linked: true,
            });
        }
    }

    const res = await authProvider.handler(c.req.raw);

    if (res.status >= 200 && res.status < 300 && clientId && body?.email) {
        try {
            const email = body.email.toLowerCase().trim();
            const createdUser = await database.collection("user").findOne({ email });
            if (createdUser) {
                await database.collection("user_app_registrations").insertOne({
                    userId: String(createdUser.id || createdUser._id),
                    clientId,
                    registeredAt: new Date(),
                });
            }
        } catch (err) {
            console.error("[SIGNUP] Failed to record app registration:", err);
        }
    }

    return res;
});

// 4. OAuth Authorize Endpoint (Mandatory State + PKCE)
auth.get("/oauth2/authorize", async (c) => {
    const state = c.req.query("state");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");

    if (!state || state.trim() === "") {
        const errorRedirect = new URL(`${config.frontendUrl}/auth`);
        if (clientId) errorRedirect.searchParams.set("client_id", clientId);
        if (redirectUri) errorRedirect.searchParams.set("redirect_uri", redirectUri);
        errorRedirect.searchParams.set("response_type", c.req.query("response_type") || "code");
        errorRedirect.searchParams.set("error", "state_required");
        errorRedirect.searchParams.set("error_description", "The state parameter is required to prevent CSRF attacks");
        return c.redirect(errorRedirect.toString(), 302);
    }

    return authProvider.handler(c.req.raw);
});

// 5. OAuth Token Endpoint with Multi-Generational Family Revocation (Fix B2)
auth.post("/oauth2/token", async (c) => {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);
    const grantType = params.get("grant_type");
    const refreshToken = params.get("refresh_token");
    const clientId = params.get("client_id") || "";

    // -- B2: Token Rotation & Theft Detection ---------------------------
    if (grantType === "refresh_token" && refreshToken) {
        const incomingHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

        // Forward to Better Auth for rotation
        const res = await authProvider.handler(c.req.raw);

        if (res.status === 200) {
            const tokenData = await res.clone().json().catch(() => null);
            if (tokenData && tokenData.refresh_token) {
                const newHash = crypto.createHash("sha256").update(tokenData.refresh_token).digest("hex");
                const rotationResult = await verifyAndRotateTokenFamily(incomingHash, newHash);

                if (rotationResult.replayed) {
                    // Theft Detected: Cascade-revoke and return 401
                    return c.json(
                        {
                            error: "invalid_grant",
                            error_description: "Refresh token has been revoked due to replay detection",
                        },
                        401
                    );
                }
            }
        } else {
            // Check if failure was due to replaying an already consumed token
            const check = await verifyAndRotateTokenFamily(incomingHash, "dummy");
            if (check.replayed) {
                return c.json(
                    {
                        error: "invalid_grant",
                        error_description: "Refresh token has been revoked due to replay detection",
                    },
                    401
                );
            }
        }

        return res;
    }

    // Initial Token Issuance (grant_type=authorization_code)
    const res = await authProvider.handler(c.req.raw);

    if (res.status === 200 && grantType === "authorization_code") {
        try {
            const tokenData = await res.clone().json().catch(() => null);
            if (tokenData && tokenData.refresh_token) {
                const initialHash = crypto.createHash("sha256").update(tokenData.refresh_token).digest("hex");
                const familyId = crypto.randomUUID();
                await registerTokenFamily(familyId, clientId, undefined, initialHash);
            }
        } catch (err) {
            console.error("[TOKEN_FAMILY] Error registering initial family:", err);
        }
    }

    return res;
});

// 6. UserInfo Interceptor (RFC 6750 §3.1 HTTP 401 Normalization)
auth.get("/oauth2/userinfo", async (c) => {
    try {
        const res = await authProvider.handler(c.req.raw);
        if (res.status >= 500) {
            return c.json(
                { error: "invalid_token", error_description: "Invalid or unsupported access token" },
                401,
                { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid or unsupported access token"' }
            );
        }
        return res;
    } catch {
        return c.json(
            { error: "invalid_token", error_description: "Invalid or unsupported access token" },
            401,
            { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid or unsupported access token"' }
        );
    }
});

// Catch-all delegate to Better Auth
auth.all("/*", async (c) => {
    return authProvider.handler(c.req.raw);
});

export default auth;
