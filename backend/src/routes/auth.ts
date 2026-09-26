import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";
import {
    getOriginCache,
    putOriginCache,
    registerTokenFamily,
    verifyAndRotateTokenFamily,
    incrementRateLimit,
    createOAuthTransaction,
    getOAuthTransaction,
    consumeOAuthTransaction,
} from "../db/state";
import { rateLimiters, checkRateLimit } from "../cache/redis";
import { getTrustedClientIp, getHeaders, resolveOAuthClient, isRegisteredRedirectUri, checkUserAppRegistration } from "../utils/security";
import { config } from "../config";

export const auth = new Hono();

export function isSuperAdmin(user: any): boolean {
    return Boolean(
        user &&
        user.role === "admin" &&
        (user.scopedClientId == null || user.scopedClientId === "")
    );
}

export function hasAppAccessBypass(user: any, canonicalClientId: string): boolean {
    if (!user || user.role !== "admin") return false;
    if (isSuperAdmin(user)) return true;
    return user.scopedClientId === canonicalClientId;
}

// Helper to extract clientId from various locations with authoritative transaction state resolution
async function extractClientId(c: any, body?: any): Promise<string | null> {
    const query = c.req.query("client_id");
    if (query) return query;

    if (body?.clientId) return body.clientId;
    if (body?.client_id) return body.client_id;

    let state: string | null = c.req.query("state") || null;

    if (body?.callbackURL && typeof body.callbackURL === "string") {
        try {
            const url = new URL(body.callbackURL, "http://localhost");
            const cid = url.searchParams.get("client_id");
            if (cid) return cid;
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    const callbackQuery = c.req.query("callbackURL");
    if (callbackQuery) {
        try {
            const url = new URL(callbackQuery, "http://localhost");
            const cid = url.searchParams.get("client_id");
            if (cid) return cid;
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    // Authoritative server-side transaction lookup by state or cookie
    if (state) {
        const tx = await getOAuthTransaction({ state });
        if (tx?.clientId) return tx.clientId;
    }

    const txIdCookie = getCookie(c, "oauth_transaction_id");
    if (txIdCookie) {
        const tx = await getOAuthTransaction({ transactionId: txIdCookie });
        if (tx?.clientId) return tx.clientId;
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

    if (!clientId || clientId.trim() === "") {
        return c.json(
            {
                status: false,
                error: "invalid_request",
                message: "client_id is required",
            },
            400
        );
    }

    const database = await getDb();
    const clientDoc = await resolveOAuthClient(database, clientId);
    if (!clientDoc || clientDoc.disabled) {
        return c.json(
            {
                status: false,
                error: "invalid_client",
                message: "Client application not found or disabled",
            },
            400
        );
    }

    setCookie(c, "current_client_id", clientDoc.clientId, {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax",
        maxAge: 60 * 10,
    });

    return c.json({ success: true, redirect_uri });
});

// 2. Sign-In App-Isolation Check + Target-Keyed Rate Limit + Constant-Time Protection (Fix B10 & Part 2)
auth.post("/sign-in/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = await extractClientId(c, body);
    const database = await getDb();

    // STRICT FAIL-CLOSED: Validate client identifier FIRST whenever provided
    let clientDoc: any = null;
    let canonicalClientId: string | null = null;
    if (clientId) {
        clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled) {
            return c.json(
                {
                    status: false,
                    error: "invalid_client",
                    message: "Client application not found or disabled",
                },
                400
            );
        }
        canonicalClientId = clientDoc.clientId;
    }

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
        } else if (user.disabled === true || user.isActive === false || user.banned === true) {
            await executeDummyHash();
            return c.json(
                {
                    status: false,
                    error: "access_denied",
                    message: "This account has been deactivated or disabled",
                },
                401
            );
        } else if (clientDoc && !clientDoc.isPublic && canonicalClientId) {
            // Private application: verify authorization boundary before proceeding
            const userId = String(user.id || user._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (!isRegistered && !hasAppAccessBypass(user, canonicalClientId)) {
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

    // CRITICAL SECURITY INVARIANT:
    // Application membership MUST NEVER mutate before successful authentication!
    // Only if credentials were valid (res.status 2xx) and application is public, record registration.
    if (res.status >= 200 && res.status < 300 && clientDoc && clientDoc.isPublic && canonicalClientId && body?.email) {
        try {
            const normalizedEmail = body.email.toLowerCase().trim();
            const authUser = await database.collection("user").findOne({ email: normalizedEmail });
            if (authUser) {
                const userId = String(authUser.id || authUser._id);
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
        } catch (err) {
            console.error("[SIGNIN] Failed to record public app registration:", err);
        }
    }

    return res;
});

// 3. Sign-Up App-Isolation Registration
auth.post("/sign-up/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = await extractClientId(c, body);
    const database = await getDb();

    // STRICT FAIL-CLOSED: Validate client identifier FIRST whenever provided
    let canonicalClientId: string | null = null;
    let clientDoc: any = null;
    if (clientId) {
        clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled) {
            return c.json(
                {
                    status: false,
                    error: "invalid_client",
                    message: "Client application not found or disabled",
                },
                400
            );
        }
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

    // Explicit sanitized payload to prevent mass assignment / privilege injection
    // Allowed fields ONLY: email, password, name, callbackURL
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

    // Only upon successful user creation (res.status 2xx), ensure no privilege fields and record public app registration
    if (res.status >= 200 && res.status < 300 && body?.email) {
        try {
            const email = String(body.email).toLowerCase().trim();
            // Invariant: New user must NEVER possess admin or scoped privileges
            await database.collection("user").updateOne(
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
                }
            );

            if (canonicalClientId && clientDoc?.isPublic) {
                const createdUser = await database.collection("user").findOne({ email });
                if (createdUser) {
                    const userId = String(createdUser.id || createdUser._id);
                    await database.collection("user_app_registrations").updateOne(
                        { userId, clientId: canonicalClientId },
                        { $setOnInsert: { userId, clientId: canonicalClientId, registeredAt: new Date() } },
                        { upsert: true }
                    );
                }
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

    // Create server-side OAuth transaction record for multi-tab isolation & tampering prevention
    const transactionId = crypto.randomUUID();
    const codeChallenge = c.req.query("code_challenge");
    const codeChallengeMethod = c.req.query("code_challenge_method");

    await createOAuthTransaction({
        transactionId,
        clientId: canonicalClientId,
        redirectUri,
        state,
        codeChallenge,
        codeChallengeMethod,
    });

    setCookie(c, "oauth_transaction_id", transactionId, {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax",
        maxAge: 60 * 10,
    });

    setCookie(c, "current_client_id", canonicalClientId, {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax",
        maxAge: 60 * 10,
    });

    // E. Determine authenticated user from session & MongoDB
    let sessionUser: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: sessionResult.user.id },
                    { _id: (sessionResult.user as any)._id },
                    { email: sessionResult.user.email },
                ],
            });
            sessionUser = { ...sessionResult.user, ...userDoc };
        }
    } catch {
        sessionUser = null;
    }

    const forwardToBetterAuth = async () => {
        const res = await authProvider.handler(c.req.raw);
        const headers = new Headers(res.headers);
        headers.append("set-cookie", `oauth_transaction_id=${transactionId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);
        headers.append("set-cookie", `current_client_id=${canonicalClientId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);
        return new Response(res.body, {
            status: res.status,
            statusText: res.statusText,
            headers,
        });
    };

    // F. Enforce Private Application Mode at OAuth Boundary
    if (!client.isPublic) {
        if (sessionUser) {
            // User is already authenticated with a valid global session
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (!isRegistered && !hasAppAccessBypass(sessionUser, canonicalClientId)) {
                // Deny authorization immediately! Do NOT issue code or continue to token issuance.
                const errorUrl = new URL(redirectUri);
                errorUrl.searchParams.set("error", "access_denied");
                errorUrl.searchParams.set("error_description", "Access restricted: Your account is not authorized for this private application");
                errorUrl.searchParams.set("state", state);
                return c.redirect(errorUrl.toString(), 302);
            }
        } else {
            // User does not have an active session yet: Better Auth will redirect to loginPage
            return forwardToBetterAuth();
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

    // Continue normal Better Auth OAuth flow
    return forwardToBetterAuth();
});

// 5. OAuth Token Endpoint with Authoritative Client Identity & Family Revocation (Fix B2)
auth.post("/oauth2/token", async (c) => {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);
    const grantType = params.get("grant_type");
    const refreshToken = params.get("refresh_token");

    // 1. Authoritative Client Identity Extraction & Conflict Resolution (RFC 6749 Section 2.3 & 5.2)
    const authHeader = c.req.header("authorization");
    let basicClientId: string | null = null;
    let basicClientSecret: string | null = null;
    let hasBasicAuth = false;

    if (authHeader) {
        if (!authHeader.toLowerCase().startsWith("basic ")) {
            return c.json({ error: "invalid_client", error_description: "Unsupported HTTP Authorization scheme; expected Basic" }, 400);
        }
        try {
            const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
            const colonIndex = decoded.indexOf(":");
            if (colonIndex === -1) {
                return c.json({ error: "invalid_client", error_description: "Malformed HTTP Basic authorization credentials" }, 400);
            }
            basicClientId = decoded.slice(0, colonIndex);
            basicClientSecret = decoded.slice(colonIndex + 1);
            hasBasicAuth = true;
        } catch {
            return c.json({ error: "invalid_client", error_description: "Malformed HTTP Basic authorization credentials" }, 400);
        }
    }

    const bodyClientId = params.get("client_id");
    const bodyClientSecret = params.get("client_secret");

    // Reject multiple authentication methods or conflicting credentials
    if (hasBasicAuth && bodyClientSecret) {
        return c.json({ error: "invalid_client", error_description: "Multiple client credentials submitted; client MUST NOT use more than one authentication method" }, 400);
    }

    if (hasBasicAuth && bodyClientId && bodyClientId !== basicClientId) {
        return c.json({ error: "invalid_client", error_description: "Conflicting client identifiers in HTTP Basic header and request body" }, 400);
    }

    // Authoritative client identifier determination
    const authClientId = hasBasicAuth ? basicClientId : bodyClientId;
    if (!authClientId) {
        return c.json({ error: "invalid_client", error_description: "Client authentication failed: missing client identifier" }, 400);
    }

    // Canonicalize client identifier against database
    const database = await getDb();
    const clientDoc = await resolveOAuthClient(database, authClientId);
    if (!clientDoc || clientDoc.disabled) {
        return c.json({ error: "invalid_client", error_description: "Client application not found or disabled" }, 400);
    }

    const canonicalClientId = clientDoc.clientId;

    // Prepare single authoritative request to forward to Better Auth
    let reqToForward = c.req.raw;
    params.delete("client_secret");
    params.delete("client_id");
    const updatedBody = params.toString();

    const forwardHeaders = new Headers(c.req.raw.headers);
    if (hasBasicAuth) {
        const canonicalBasic = Buffer.from(`${canonicalClientId}:${basicClientSecret}`).toString("base64");
        forwardHeaders.set("Authorization", `Basic ${canonicalBasic}`);
    } else if (bodyClientSecret) {
        const canonicalBasic = Buffer.from(`${canonicalClientId}:${bodyClientSecret}`).toString("base64");
        forwardHeaders.set("Authorization", `Basic ${canonicalBasic}`);
    }

    reqToForward = new Request(c.req.raw.url, {
        method: c.req.raw.method,
        headers: forwardHeaders,
        body: updatedBody,
    });

    // -- B2: Refresh Token Lifecycle & Family Revocation ---------------------------
    if (grantType === "refresh_token" && refreshToken) {
        const incomingHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

        // Fail-Closed: Check if this token family was already marked revoked
        const existingFamily = await database.collection("oauth_token_families").findOne({
            $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
        });
        if (existingFamily && existingFamily.status === "revoked") {
            return c.json(
                {
                    error: "invalid_grant",
                    error_description: "Token family has been revoked due to previous security event",
                },
                401
            );
        }

        // Atomic compare-and-swap to claim rotation rights for this token family
        // This ensures exactly 1 in-flight request attempts rotation, preventing Better Auth from purging on collision
        const claim = await database.collection("oauth_token_families").findOneAndUpdate(
            {
                activeTokenHash: incomingHash,
                status: "active",
                rotating: { $ne: true },
            },
            {
                $set: { rotating: true, rotatingAt: new Date() },
            },
            { returnDocument: "after" }
        );

        if (!claim) {
            // Check if rotation is currently in-flight by the winning concurrent request
            const currentDoc = await database.collection("oauth_token_families").findOne({
                $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
            });

            if (currentDoc && (currentDoc as any).rotating === true) {
                return c.json(
                    {
                        error: "invalid_grant",
                        error_description: "Refresh token was already consumed or is currently being rotated",
                    },
                    400
                );
            }

            // Otherwise, token was already rotated; check if within grace window or replay theft
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
            return c.json(
                {
                    error: "invalid_grant",
                    error_description: "Refresh token was already consumed or is currently being rotated",
                },
                400
            );
        }

        let preRefreshUserId: string | undefined = existingFamily?.userId;
        if (!preRefreshUserId) {
            try {
                const oldDoc = await database.collection("oauthRefreshToken").findOne({ token: refreshToken });
                if (oldDoc && oldDoc.userId) {
                    preRefreshUserId = String(oldDoc.userId);
                }
            } catch {}
        }

        // Forward to Better Auth for native rotation
        let res: Response;
        try {
            res = await authProvider.handler(reqToForward);
        } catch (handlerErr) {
            await database.collection("oauth_token_families").updateOne(
                { activeTokenHash: incomingHash, rotating: true },
                { $set: { rotating: false } }
            ).catch(() => {});
            throw handlerErr;
        }

        if (res.status === 200) {
            const tokenData = await res.clone().json().catch(() => null);
            if (tokenData && tokenData.refresh_token) {
                // Extract authenticated userId from access token JWT payload or database
                let resolvedUserId: string | undefined = preRefreshUserId;
                if (!resolvedUserId && tokenData.id_token && typeof tokenData.id_token === "string") {
                    const parts = tokenData.id_token.split(".");
                    if (parts.length === 3) {
                        try {
                            const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                            resolvedUserId = jwtPayload.sub || jwtPayload.userId;
                        } catch {}
                    }
                }
                if (!resolvedUserId && tokenData.access_token && typeof tokenData.access_token === "string") {
                    const parts = tokenData.access_token.split(".");
                    if (parts.length === 3) {
                        try {
                            const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                            resolvedUserId = jwtPayload.sub || jwtPayload.userId;
                        } catch {}
                    }
                }
                for (let attempt = 0; attempt < 5 && !resolvedUserId; attempt++) {
                    if (attempt > 0) await new Promise(r => setTimeout(r, 40 * attempt));
                    if (tokenData.refresh_token) {
                        const refDoc = await database.collection("oauthRefreshToken").findOne({
                            token: tokenData.refresh_token,
                        });
                        if (refDoc && refDoc.userId) {
                            resolvedUserId = String(refDoc.userId);
                            break;
                        }
                    }
                    if (tokenData.access_token) {
                        const accDoc = await database.collection("oauthAccessToken").findOne({
                            token: tokenData.access_token,
                        });
                        if (accDoc && accDoc.userId) {
                            resolvedUserId = String(accDoc.userId);
                            break;
                        }
                    }
                }

                // CRITICAL SECURITY INVARIANT:
                // Removed user cannot refresh old application authorization on private applications!
                if (!clientDoc.isPublic && resolvedUserId) {
                    const isRegistered = await checkUserAppRegistration(database, resolvedUserId, canonicalClientId);
                    const userDoc = await database.collection("user").findOne({
                        $or: [{ id: resolvedUserId }, { _id: resolvedUserId as any }]
                    });

                    if (!isRegistered && !hasAppAccessBypass(userDoc, canonicalClientId)) {
                        // Immediately purge issued tokens and revoke family
                        await Promise.all([
                            database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauth_token_families").updateMany(
                                { clientId: canonicalClientId, userId: resolvedUserId },
                                { $set: { status: "revoked", revokedAt: new Date() } }
                            ),
                        ]);
                        return c.json(
                            {
                                error: "invalid_grant",
                                error_description: "User is no longer authorized for this private application",
                            },
                            401
                        );
                    }
                }

                const newHash = crypto.createHash("sha256").update(tokenData.refresh_token).digest("hex");
                const rotationResult = await verifyAndRotateTokenFamily(incomingHash, newHash, resolvedUserId);

                if (rotationResult.replayed) {
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
            // Unset rotating on failure
            await database.collection("oauth_token_families").updateOne(
                { activeTokenHash: incomingHash, rotating: true },
                { $set: { rotating: false } }
            ).catch(() => {});

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
    const incomingCode = grantType === "authorization_code" ? params.get("code") : null;
    let preCodeUserId: string | undefined;
    if (incomingCode) {
        try {
            const codeDoc = await database.collection("oauthAuthorizationCode").findOne({ code: incomingCode });
            if (codeDoc && codeDoc.userId) {
                preCodeUserId = String(codeDoc.userId);
            }
        } catch {}
    }

    const res = await authProvider.handler(reqToForward);

    if (res.status === 200 && grantType === "authorization_code") {
        try {
            const tokenData = await res.clone().json().catch(() => null);
            if (tokenData && tokenData.refresh_token) {
                const initialHash = crypto.createHash("sha256").update(tokenData.refresh_token).digest("hex");
                const familyId = crypto.randomUUID();

                // Extract authenticated userId from pre-resolved code, access token JWT, or database
                let resolvedUserId: string | undefined = preCodeUserId;
                if (!resolvedUserId && tokenData.id_token && typeof tokenData.id_token === "string") {
                    const parts = tokenData.id_token.split(".");
                    if (parts.length === 3) {
                        try {
                            const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                            resolvedUserId = jwtPayload.sub || jwtPayload.userId;
                        } catch {}
                    }
                }
                if (!resolvedUserId && tokenData.access_token && typeof tokenData.access_token === "string") {
                    const parts = tokenData.access_token.split(".");
                    if (parts.length === 3) {
                        try {
                            const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                            resolvedUserId = jwtPayload.sub || jwtPayload.userId;
                        } catch {}
                    }
                }
                for (let attempt = 0; attempt < 5 && !resolvedUserId; attempt++) {
                    if (attempt > 0) await new Promise(r => setTimeout(r, 40 * attempt));
                    if (tokenData.refresh_token) {
                        const refDoc = await database.collection("oauthRefreshToken").findOne({
                            token: tokenData.refresh_token,
                        });
                        if (refDoc && refDoc.userId) {
                            resolvedUserId = String(refDoc.userId);
                            break;
                        }
                    }
                    if (tokenData.access_token) {
                        const accDoc = await database.collection("oauthAccessToken").findOne({
                            token: tokenData.access_token,
                        });
                        if (accDoc && accDoc.userId) {
                            resolvedUserId = String(accDoc.userId);
                            break;
                        }
                    }
                }

                // Strictly bind token family to canonicalClientId and resolvedUserId
                try {
                    await registerTokenFamily(familyId, canonicalClientId, resolvedUserId, initialHash);
                } catch (regErr) {
                    console.error("[TOKEN_FAMILY] Critical failure registering initial family; failing closed:", regErr);
                    // FAIL CLOSED: Purge issued tokens so no untracked refresh token exists in DB (Phase 10)
                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                    }
                    if (tokenData.access_token) {
                        await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    }
                    return c.json(
                        {
                            error: "server_error",
                            error_description: "Failed to establish secure token family state",
                        },
                        500
                    );
                }
            }
        } catch (err) {
            console.error("[TOKEN_FAMILY] Error in token issuance interceptor:", err);
            return c.json(
                {
                    error: "server_error",
                    error_description: "Internal security failure during token generation",
                },
                500
            );
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

// 7. Consent & Continue Endpoint Security Interceptors
auth.post("/oauth2/consent", async (c) => {
    let sessionUser: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            const database = await getDb();
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: sessionResult.user.id },
                    { _id: (sessionResult.user as any)._id },
                    { email: sessionResult.user.email },
                ],
            });
            sessionUser = { ...sessionResult.user, ...userDoc };
        }
    } catch {
        sessionUser = null;
    }

    if (!sessionUser) {
        return c.json({ error: "unauthorized", message: "Authentication required" }, 401);
    }

    const body = await c.req.raw.clone().json().catch(() => null);
    let clientId: string | null = null;
    let state: string | null = null;
    if (body?.oauth_query && typeof body.oauth_query === "string") {
        try {
            const queryParams = new URLSearchParams(body.oauth_query);
            clientId = queryParams.get("client_id");
            state = queryParams.get("state");
        } catch {}
    }
    if (!state) state = c.req.query("state") || null;

    const txIdCookie = getCookie(c, "oauth_transaction_id");
    const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
    if (tx) {
        if (clientId && clientId !== tx.clientId) {
            return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
        }
        clientId = tx.clientId;
    }
    if (!clientId) {
        clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
    }

    if (clientId) {
        const database = await getDb();
        const clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled) {
            return c.json({ error: "invalid_client", error_description: "Client application not found or disabled" }, 400);
        }

        if (!clientDoc.isPublic) {
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            const canonicalClientId = clientDoc.clientId;
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

            if (!isRegistered && !hasAppAccessBypass(sessionUser, canonicalClientId)) {
                return c.json({
                    error: "access_denied",
                    error_description: "Access restricted: Your account is not authorized for this private application"
                }, 403);
            }
        }
    }

    return authProvider.handler(c.req.raw);
});

auth.post("/oauth2/continue", async (c) => {
    let sessionUser: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            const database = await getDb();
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: sessionResult.user.id },
                    { _id: (sessionResult.user as any)._id },
                    { email: sessionResult.user.email },
                ],
            });
            sessionUser = { ...sessionResult.user, ...userDoc };
        }
    } catch {
        sessionUser = null;
    }

    if (sessionUser) {
        const body = await c.req.raw.clone().json().catch(() => null);
        let clientId: string | null = null;
        let state: string | null = null;
        if (body?.oauth_query && typeof body.oauth_query === "string") {
            try {
                const queryParams = new URLSearchParams(body.oauth_query);
                clientId = queryParams.get("client_id");
                state = queryParams.get("state");
            } catch {}
        }
        if (!state) state = c.req.query("state") || null;

        const txIdCookie = getCookie(c, "oauth_transaction_id");
        const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
        if (tx) {
            if (clientId && clientId !== tx.clientId) {
                return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
            }
            clientId = tx.clientId;
        }
        if (!clientId) {
            clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
        }

        if (clientId) {
            const database = await getDb();
            const clientDoc = await resolveOAuthClient(database, clientId);
            if (clientDoc && !clientDoc.isPublic) {
                const userId = String(sessionUser.id || (sessionUser as any)._id);
                const canonicalClientId = clientDoc.clientId;
                const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

                if (!isRegistered && !hasAppAccessBypass(sessionUser, canonicalClientId)) {
                    return c.json({
                        error: "access_denied",
                        error_description: "Access restricted: Your account is not authorized for this private application"
                    }, 403);
                }
            }
        }
    }

    return authProvider.handler(c.req.raw);
});

// 8. Prevent Dynamic Client Registration & Direct Client Manipulation Endpoints
auth.all("/oauth2/register", (c) =>
    c.json({ error: "access_denied", error_description: "Dynamic client registration is disabled" }, 403)
);
auth.all("/oauth2/register/*", (c) =>
    c.json({ error: "access_denied", error_description: "Dynamic client registration is disabled" }, 403)
);
auth.all("/oauth2/create-client", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client creation is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/update-client", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client update is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/delete-client", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client deletion is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/get-client", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client lookup is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/get-clients", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client lookup is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/public-client", (c) =>
    c.json({ error: "access_denied", error_description: "Direct public client lookup is forbidden." }, 403)
);
auth.all("/oauth2/public-client-prelogin", (c) =>
    c.json({ error: "access_denied", error_description: "Direct public client lookup is forbidden." }, 403)
);
auth.all("/oauth2/client/rotate-secret", (c) =>
    c.json({ error: "access_denied", error_description: "Direct secret rotation is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/client/*", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client management is forbidden. Use /api/admin/clients." }, 403)
);
auth.all("/oauth2/clients/*", (c) =>
    c.json({ error: "access_denied", error_description: "Direct client management is forbidden. Use /api/admin/clients." }, 403)
);

// 9. Super-Admin Gate for Better-Auth Internal Admin Routes
async function checkBetterAuthAdminAccess(c: any) {
    let sessionUser: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            const database = await getDb();
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: sessionResult.user.id },
                    { _id: (sessionResult.user as any)._id },
                    { email: sessionResult.user.email },
                ],
            });
            sessionUser = { ...sessionResult.user, ...userDoc };
        }
    } catch {
        sessionUser = null;
    }

    if (!sessionUser || !isSuperAdmin(sessionUser)) {
        return c.json(
            {
                error: "forbidden",
                message: "Super-Admin privileges required for internal administrative routes",
            },
            403
        );
    }

    return authProvider.handler(c.req.raw);
}

auth.all("/admin", checkBetterAuthAdminAccess);
auth.all("/admin/*", checkBetterAuthAdminAccess);

// 10. Social Login Callback App-Isolation & Registration Enforcer
async function handleSocialCallback(c: any) {
    const res = await authProvider.handler(c.req.raw);

    const state = c.req.query("state");
    const txIdCookie = getCookie(c, "oauth_transaction_id");
    let clientId: string | null = null;
    if (state || txIdCookie) {
        const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
        if (tx?.clientId) {
            clientId = tx.clientId;
        }
    }
    if (!clientId) {
        clientId = getCookie(c, "current_client_id");
    }

    if (clientId) {
        let database: any;
        try {
            database = await getDb();
        } catch (dbErr) {
            console.error("DB connection error in handleSocialCallback:", dbErr);
            return c.json({ error: "server_error", message: "Database resolution failure" }, 500);
        }

        let clientDoc: any;
        try {
            clientDoc = await resolveOAuthClient(database, clientId);
        } catch (dbErr) {
            console.error("DB query error in resolveOAuthClient:", dbErr);
            return c.json({ error: "server_error", message: "Database resolution failure" }, 500);
        }

        if (clientDoc) {
            const canonicalClientId = clientDoc.clientId;

            // Extract session token from set-cookie header on res or from incoming request cookies
            let sessionToken: string | null = null;
            const setCookieList: string[] = (res.headers as any).getSetCookie
                ? (res.headers as any).getSetCookie()
                : [res.headers.get("set-cookie") || ""];
            for (const header of setCookieList) {
                const match = header.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
                if (match) {
                    sessionToken = decodeURIComponent(match[1]);
                    break;
                }
            }
            if (!sessionToken) {
                sessionToken = getCookie(c, "better-auth.session_token") || getCookie(c, "__Secure-better-auth.session_token") || null;
            }

            const rawSessionToken = sessionToken ? sessionToken.split(".")[0] : null;

            let sessionUser: any = null;
            if (!sessionUser && (sessionToken || rawSessionToken)) {
                try {
                    const sessionDoc = await database.collection("session").findOne({
                        $or: [
                            ...(sessionToken ? [{ token: sessionToken }, { id: sessionToken }] : []),
                            ...(rawSessionToken ? [{ token: rawSessionToken }, { id: rawSessionToken }] : []),
                        ],
                    });
                    if (sessionDoc) {
                        const rawUserId = sessionDoc.userId;
                        let userObjId: any = rawUserId;
                        try {
                            if (ObjectId.isValid(rawUserId)) userObjId = new ObjectId(rawUserId);
                        } catch {}
                        sessionUser = await database.collection("user").findOne({
                            $or: [{ id: String(rawUserId) }, { _id: rawUserId }, { _id: userObjId }],
                        }).catch(() => null);
                        if (!sessionUser) {
                            sessionUser = { id: String(rawUserId), _id: rawUserId };
                        }
                    }
                } catch {
                    sessionUser = null;
                }
            }

            if (!sessionUser) {
                try {
                    const headers = getHeaders(c);
                    if (sessionToken) {
                        headers.set("cookie", `better-auth.session_token=${sessionToken}`);
                    }
                    const sessionResult = await authProvider.api.getSession({ headers });
                    sessionUser = sessionResult?.user ?? null;
                } catch {
                    sessionUser = null;
                }
            }

            if (sessionUser) {
                const userId = String(sessionUser.id || (sessionUser as any)._id);

                if (!clientDoc.isPublic) {
                    // Private application: verify authorization boundary
                    const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);

                    if (!isRegistered && !hasAppAccessBypass(sessionUser, canonicalClientId)) {
                        // CRITICAL: Fail-Closed deterministic cleanup!
                        // Identify and revoke the exact created session, without destroying the user's
                        // entire account or other devices' unrelated sessions.
                        if (sessionToken || rawSessionToken) {
                            await database.collection("session").deleteMany({
                                $or: [
                                    ...(sessionToken ? [{ token: sessionToken }, { id: sessionToken }] : []),
                                    ...(rawSessionToken ? [{ token: rawSessionToken }, { id: rawSessionToken }] : []),
                                ],
                            });
                        }

                        // Clear session cookies so the browser does not retain an authorized session
                        const headers = new Headers(res.headers);
                        headers.delete("set-cookie");
                        headers.append("set-cookie", "better-auth.session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
                        headers.append("set-cookie", "__Secure-better-auth.session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure");
                        headers.append("set-cookie", "current_client_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");

                        const errorRedirectUrl = new URL(`${config.frontendUrl}/auth`);
                        errorRedirectUrl.searchParams.set("error", "access_denied");
                        errorRedirectUrl.searchParams.set(
                            "error_description",
                            "Access restricted: Your account is not authorized for this private application"
                        );
                        headers.set("location", errorRedirectUrl.toString());

                        return new Response(null, {
                            status: 302,
                            headers,
                        });
                    }
                } else {
                    // Public application: record membership idempotently
                    await database.collection("user_app_registrations").updateOne(
                        { userId, clientId: canonicalClientId },
                        { $setOnInsert: { userId, clientId: canonicalClientId, registeredAt: new Date() } },
                        { upsert: true }
                    );
                }
            }
        }
    }

    return res;
}

auth.all("/callback/:provider", handleSocialCallback);
auth.all("/oauth2/callback/:provider", handleSocialCallback);

// 11. Standard OIDC JWKS Aliases (RFC 7517 / RFC 8414)
auth.get("/jwks.json", async (c) => {
    const forwardUrl = new URL("/api/auth/jwks", c.req.raw.url);
    const forwardReq = new Request(forwardUrl.toString(), {
        method: "GET",
        headers: c.req.raw.headers,
    });
    return authProvider.handler(forwardReq);
});

auth.get("/jwks", async (c) => {
    const forwardUrl = new URL("/api/auth/jwks", c.req.raw.url);
    const forwardReq = new Request(forwardUrl.toString(), {
        method: "GET",
        headers: c.req.raw.headers,
    });
    return authProvider.handler(forwardReq);
});

// Catch-all delegate to Better Auth
auth.all("/*", async (c) => {
    return authProvider.handler(c.req.raw);
});

export default auth;
