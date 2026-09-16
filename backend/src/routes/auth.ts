import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOriginCache, putOriginCache, registerTokenFamily, verifyAndRotateTokenFamily, incrementRateLimit } from "../db/state";
import { rateLimiters, checkRateLimit } from "../cache/redis";
import { getTrustedClientIp, getHeaders, resolveOAuthClient, isRegisteredRedirectUri, checkUserAppRegistration } from "../utils/security";
import { config } from "../config";

export const auth = new Hono();

// Helper to extract clientId from various locations
function extractClientId(c: any, body?: any): string | null {
    const query = c.req.query("client_id");
    if (query) return query;

    if (body?.clientId) return body.clientId;
    if (body?.client_id) return body.client_id;

    if (body?.callbackURL && typeof body.callbackURL === "string") {
        try {
            const url = new URL(body.callbackURL, "http://localhost");
            const cid = url.searchParams.get("client_id");
            if (cid) return cid;
        } catch {}
    }

    const callbackQuery = c.req.query("callbackURL");
    if (callbackQuery) {
        try {
            const url = new URL(callbackQuery, "http://localhost");
            const cid = url.searchParams.get("client_id");
            if (cid) return cid;
        } catch {}
    }

    const cookieVal = getCookie(c, "current_client_id");
    if (cookieVal) return cookieVal;

    return null;
}

// Constant-time dummy hash computation to prevent login timing enumeration (Fix B10)
// Uses exact Better-Auth scrypt parameters: N=16384, r=16, p=1, dkLen=64, maxmem=67108864
async function executeDummyHash(): Promise<void> {
    return new Promise((resolve, reject) => {
        crypto.scrypt(
            "DummyPassword@123!".normalize("NFKC"),
            "dummy_salt_constant_time_98234",
            64,
            { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 },
            (err) => {
                if (err) reject(err);
                else resolve();
            }
        );
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

// 2. Sign-In App-Isolation Check + Target-Keyed Rate Limit + Constant-Time Protection (Fix B10 & Part 2)
auth.post("/sign-in/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = extractClientId(c, body);
    const database = await getDb();

    if (body?.email && typeof body.email === "string") {
        const normalizedEmail = body.email.toLowerCase().trim();

        // 1. Target-Keyed Rate Limiting (IP-Rotation Resistant Defense)
        if (rateLimiters?.credentialStuffingTarget) {
            const targetResult = await checkRateLimit(
                rateLimiters.credentialStuffingTarget,
                `email:${normalizedEmail}`
            );
            if (targetResult.remaining !== -1 && !targetResult.allowed) {
                return c.json(
                    {
                        error: "too_many_requests",
                        message: "Too many sign-in attempts for this account. Please try again later.",
                    },
                    429
                );
            }
        } else {
            // MongoDB fallback (graceful degradation)
            const targetKey = `TARGET#${crypto.createHash("sha256").update(normalizedEmail).digest("hex")}`;
            const entry = await incrementRateLimit(targetKey, Date.now(), 300 * 1000);
            if (entry.count > 15) {
                return c.json(
                    {
                        error: "too_many_requests",
                        message: "Too many sign-in attempts for this account. Please try again later.",
                    },
                    429
                );
            }
        }

        const user = await database.collection("user").findOne({ email: normalizedEmail });
        if (!user) {
            // Equalize CPU timing with real password verification (Fix B10)
            await executeDummyHash();
        } else if (clientId && user.role !== "admin") {
            const clientDoc = await resolveOAuthClient(database, clientId);
            const isPublic = clientDoc ? clientDoc.isPublic : true;
            const canonicalClientId = clientDoc ? clientDoc.clientId : clientId;
            const userId = String(user.id || user._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (!isPublic) {
                // Private application: strict registration required
                if (!isRegistered) {
                    return c.json(
                        {
                            status: false,
                            error: "access_denied",
                            message: "Access restricted: This application is in private mode and your account has not been authorized. Please contact an administrator.",
                        },
                        403
                    );
                }
            } else {
                // Public application: auto-record app registration on sign-in if not yet recorded
                if (!isRegistered) {
                    await database.collection("user_app_registrations").insertOne({
                        userId,
                        clientId: canonicalClientId,
                        registeredAt: new Date(),
                    }).catch((err: any) => {
                        if (err?.code === 11000) return;
                        throw err;
                    });
                }
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

    // If client is in private mode, block public self-registration
    let canonicalClientId = clientId;
    if (clientId) {
        const clientDoc = await resolveOAuthClient(database, clientId);
        if (clientDoc) {
            canonicalClientId = clientDoc.clientId;
            if (!clientDoc.isPublic) {
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
    }

    if (body?.email) {
        const email = body.email.toLowerCase().trim();
        const existingUser = await database.collection("user").findOne({ email });

        if (existingUser && canonicalClientId) {
            const userId = String(existingUser.id || existingUser._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (isRegistered) {
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
                userId,
                clientId: canonicalClientId,
                registeredAt: new Date(),
            }).catch((err: any) => {
                if (err?.code === 11000) return;
                throw err;
            });

            return c.json({
                status: true,
                message: "Existing user linked to new application successfully. Please login.",
                linked: true,
            });
        }
    }

    const res = await authProvider.handler(c.req.raw);

    if (res.status >= 200 && res.status < 300 && canonicalClientId && body?.email) {
        try {
            const email = body.email.toLowerCase().trim();
            const createdUser = await database.collection("user").findOne({ email });
            if (createdUser) {
                const userId = String(createdUser.id || createdUser._id);
                await database.collection("user_app_registrations").insertOne({
                    userId,
                    clientId: canonicalClientId,
                    registeredAt: new Date(),
                }).catch((err: any) => {
                    if (err?.code === 11000) return;
                    throw err;
                });
            }
        } catch (err) {
            console.error("[SIGNUP] Failed to record app registration:", err);
        }
    }

    return res;
});

// 4. OAuth Authorize Endpoint (Mandatory State + Canonical Client & Redirect URI Validation + Private-App Authorization Boundary)
auth.get("/oauth2/authorize", async (c) => {
    const state = c.req.query("state");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");

    // A. CSRF State parameter requirement
    if (!state || state.trim() === "") {
        const errorRedirect = new URL(`${config.frontendUrl}/auth`);
        if (clientId) errorRedirect.searchParams.set("client_id", clientId);
        if (redirectUri) errorRedirect.searchParams.set("redirect_uri", redirectUri);
        errorRedirect.searchParams.set("response_type", c.req.query("response_type") || "code");
        errorRedirect.searchParams.set("error", "state_required");
        errorRedirect.searchParams.set("error_description", "The state parameter is required to prevent CSRF attacks");
        return c.redirect(errorRedirect.toString(), 302);
    }

    if (!clientId) {
        return c.json({ error: "invalid_request", error_description: "client_id is required" }, 400);
    }

    const database = await getDb();
    const client = await resolveOAuthClient(database, clientId);

    // B. Resolve canonical OAuth client & verify not deleted
    if (!client) {
        return c.json({ error: "invalid_client", error_description: "Client application not found" }, 401);
    }

    // C. Verify client is not suspended/deactivated
    if (client.disabled) {
        return c.json({ error: "unauthorized_client", error_description: "Client application is suspended or deactivated" }, 403);
    }

    // D. Validate requested redirect URI against registered client redirect URI list
    if (!redirectUri) {
        return c.json({ error: "invalid_request", error_description: "redirect_uri is required" }, 400);
    }

    const isValidRedirect = isRegisteredRedirectUri(client, redirectUri);
    if (!isValidRedirect) {
        return c.json({ error: "invalid_request", error_description: "The redirect_uri is not registered for this application" }, 400);
    }

    const canonicalClientId = client.clientId;

    // E. Determine authenticated user from session
    let sessionUser: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        sessionUser = sessionResult?.user ?? null;
    } catch {
        sessionUser = null;
    }

    // F. Enforce Private Application Mode at OAuth Boundary
    if (!client.isPublic) {
        if (sessionUser) {
            // User is already authenticated with a valid global session
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (!isRegistered && sessionUser.role !== "admin") {
                // Deny authorization immediately! Do NOT issue code or continue to token issuance.
                const errorUrl = new URL(redirectUri);
                errorUrl.searchParams.set("error", "access_denied");
                errorUrl.searchParams.set("error_description", "Access restricted: Your account is not authorized for this private application");
                errorUrl.searchParams.set("state", state);
                return c.redirect(errorUrl.toString(), 302);
            }
        } else {
            // User does not have an active session yet: bind canonical client ID to cookie
            setCookie(c, "current_client_id", canonicalClientId, {
                path: "/",
                httpOnly: true,
                secure: config.env === "production",
                sameSite: "Lax",
                maxAge: 60 * 10,
            });
            // Delegate to Better Auth which will redirect to loginPage
            return authProvider.handler(c.req.raw);
        }
    } else {
        // Public Application Mode:
        if (sessionUser) {
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);
            if (!isRegistered) {
                await database.collection("user_app_registrations").insertOne({
                    userId,
                    clientId: canonicalClientId,
                    registeredAt: new Date(),
                }).catch((err: any) => {
                    if (err?.code === 11000) return;
                    throw err;
                });
            }
        }
    }

    // Bind canonical client ID to current_client_id cookie
    setCookie(c, "current_client_id", canonicalClientId, {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax",
        maxAge: 60 * 10,
    });

    // Continue normal Better Auth OAuth flow
    return authProvider.handler(c.req.raw);
});

// 5. OAuth Token Endpoint with Multi-Generational Family Revocation (Fix B2)
auth.post("/oauth2/token", async (c) => {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);
    const grantType = params.get("grant_type");
    const refreshToken = params.get("refresh_token");
    const clientId = params.get("client_id") || "";
    const clientSecret = params.get("client_secret");

    // Ensure strictly ONE client authentication method is forwarded to Better Auth
    let reqToForward = c.req.raw;
    if (!c.req.header("authorization") && clientId && clientSecret) {
        // Adapt client_secret_post to client_secret_basic
        const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
        const headers = new Headers(c.req.raw.headers);
        headers.set("Authorization", `Basic ${basicAuth}`);
        
        params.delete("client_secret");
        params.delete("client_id");
        const updatedBody = params.toString();

        reqToForward = new Request(c.req.raw.url, {
            method: c.req.raw.method,
            headers,
            body: updatedBody,
        });
    } else if (c.req.header("authorization") && (params.has("client_secret") || params.has("client_id"))) {
        // Client provided Authorization header: strip body credentials to prevent dual-auth rejection
        params.delete("client_secret");
        params.delete("client_id");
        const updatedBody = params.toString();

        reqToForward = new Request(c.req.raw.url, {
            method: c.req.raw.method,
            headers: c.req.raw.headers,
            body: updatedBody,
        });
    }

    // -- B2: Token Rotation & Theft Detection ---------------------------
    if (grantType === "refresh_token" && refreshToken) {
        const incomingHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

        // Forward to Better Auth for rotation
        const res = await authProvider.handler(reqToForward);

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
    const res = await authProvider.handler(reqToForward);

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

// 6. UserInfo Interceptor (RFC 6750 Section 3.1 HTTP 401 Normalization)
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
