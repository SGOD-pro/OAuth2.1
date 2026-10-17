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
import { emergencyRateLimiter } from "../middleware/rate-limit";

import { importJWK, SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader, generateKeyPair, exportJWK } from "jose";
import { getIdpPublicKey } from "../middleware/admin-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

export const auth = new Hono();

let cachedPrivateKey: any = null;
let cachedKeyId: string = "";
let lastPrivateKeyFetch = 0;

export async function resolveUserRoleForClient(
    database: any,
    userDoc: any,
    clientId: string
): Promise<{ role: string; scopedClientId: string | null }> {
    if (!userDoc) {
        return { role: "user", scopedClientId: null };
    }

    // 1. Global Super Admin: always role: "admin", scopedClientId: null
    if (userDoc.role === "admin" && userDoc.scopedClientId === null) {
        return { role: "admin", scopedClientId: null };
    }

    if (!clientId) {
        return { role: userDoc.role || "user", scopedClientId: userDoc.scopedClientId || null };
    }

    // 2. Direct scoped match on primary user document
    if (userDoc.role === "admin" && userDoc.scopedClientId === clientId) {
        return { role: "admin", scopedClientId: clientId };
    }

    // 3. Check app_admins collection by userId and email
    const userIdStr = (userDoc.id || userDoc._id)?.toString();
    const adminOrConditions: any[] = [];
    if (userIdStr) adminOrConditions.push({ userId: userIdStr });
    if (userDoc._id) adminOrConditions.push({ userId: userDoc._id });
    if (userDoc.email) {
        adminOrConditions.push({ email: userDoc.email.toLowerCase().trim() });
    }
    if (adminOrConditions.length > 0) {
        const appAdmin = await database.collection("app_admins").findOne({
            clientId,
            $or: adminOrConditions,
            isActive: { $ne: false },
        });
        if (appAdmin) {
            return { role: "admin", scopedClientId: clientId };
        }
    }

    // 4. Check user_app_registrations collection for appRole: "admin"
    const orConditions: any[] = [];
    if (userIdStr) orConditions.push({ userId: userIdStr });
    if (userDoc._id) orConditions.push({ userId: userDoc._id });
    if (orConditions.length > 0) {
        const reg = await database.collection("user_app_registrations").findOne({
            clientId,
            $or: orConditions,
            appRole: "admin",
        });
        if (reg) {
            return { role: "admin", scopedClientId: clientId };
        }
    }

    // 5. Default to role: "user" with scopedClientId null for this client
    return { role: "user", scopedClientId: null };
}

async function generateAndStoreFreshKeypair(database: any): Promise<{ privateKey: any; kid: string } | null> {
    try {
        const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
        const publicJwk: any = await exportJWK(publicKey);
        const privateJwk: any = await exportJWK(privateKey);
        const kid = `idp-key-${crypto.randomUUID()}`;
        publicJwk.kid = kid;
        publicJwk.alg = "RS256";
        publicJwk.use = "sig";
        privateJwk.kid = kid;
        privateJwk.alg = "RS256";
        privateJwk.use = "sig";

        let storedPrivateKey: any = typeof privateJwk === "string" ? privateJwk : JSON.stringify(privateJwk);
        if (config.auth.secret) {
            try {
                const enc = await symmetricEncrypt({
                    key: config.auth.secret,
                    data: JSON.stringify(privateJwk),
                });
                storedPrivateKey = JSON.stringify(enc);
            } catch (encryptErr) {
                console.error("[getIdpSigningKey] Critical: Failed to symmetrically encrypt fresh private key at rest:", encryptErr);
                return null;
            }
        }

        const newDoc = {
            _id: kid as any,
            id: kid,
            kid,
            publicKey: JSON.stringify(publicJwk),
            privateKey: storedPrivateKey,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await database.collection("jwks").insertOne(newDoc);
        console.log(`[getIdpSigningKey] Self-healed: generated and stored fresh RS256 keypair (kid: ${kid})`);

        cachedPrivateKey = privateKey;
        cachedKeyId = kid;
        lastPrivateKeyFetch = Date.now();
        return { privateKey: cachedPrivateKey, kid: cachedKeyId };
    } catch (healErr) {
        console.error("[getIdpSigningKey] Catastrophic failure self-healing RS256 keypair:", healErr);
        return null;
    }
}

let signingKeyOverrideForTesting: (() => Promise<{ privateKey: any; kid: string } | null>) | null = null;
export function setSigningKeyOverrideForTesting(override: (() => Promise<{ privateKey: any; kid: string } | null>) | null): void {
    signingKeyOverrideForTesting = override;
}

export function clearSigningKeyCacheForTesting(): void {
    cachedPrivateKey = null;
    cachedKeyId = "";
    lastPrivateKeyFetch = 0;
    signingKeyOverrideForTesting = null;
}

export async function getIdpSigningKey(): Promise<{ privateKey: any; kid: string } | null> {
    if (signingKeyOverrideForTesting) {
        return signingKeyOverrideForTesting();
    }
    const now = Date.now();
    if (cachedPrivateKey && cachedKeyId && now - lastPrivateKeyFetch < 60_000) {
        return { privateKey: cachedPrivateKey, kid: cachedKeyId };
    }
    const database = await getDb();
    const jwksRecord = await database.collection("jwks").findOne(
        { privateKey: { $exists: true } },
        { sort: { createdAt: -1 } }
    );
    if (!jwksRecord || !jwksRecord.privateKey) {
        console.warn("[getIdpSigningKey] No valid signing key found in database. Self-healing with fresh keypair...");
        return generateAndStoreFreshKeypair(database);
    }
    try {
        let rawData: any;
        if (typeof jwksRecord.privateKey === "string") {
            try {
                rawData = JSON.parse(jwksRecord.privateKey);
            } catch {
                rawData = jwksRecord.privateKey;
            }
        } else {
            rawData = jwksRecord.privateKey;
        }

        let jwk: any;
        if (rawData && typeof rawData === "object" && rawData.kty) {
            jwk = rawData;
        } else if (config.auth.secret) {
            try {
                const decrypted = await symmetricDecrypt({ key: config.auth.secret, data: rawData });
                jwk = typeof decrypted === "string" ? JSON.parse(decrypted) : decrypted;
            } catch (decErr) {
                console.warn("[getIdpSigningKey] symmetricDecrypt failed, attempting rawData:", decErr);
                jwk = rawData;
            }
        } else {
            jwk = rawData;
        }

        if (typeof jwk === "string") {
            try {
                jwk = JSON.parse(jwk);
            } catch {}
        }

        if (!jwk || typeof jwk !== "object" || !jwk.kty) {
            throw new Error("Invalid or unreadable JWK private key format");
        }

        cachedPrivateKey = await importJWK(jwk, "RS256");
        cachedKeyId = jwksRecord.kid || (jwksRecord._id ? jwksRecord._id.toString() : "idp-key");
        lastPrivateKeyFetch = now;
        return { privateKey: cachedPrivateKey, kid: cachedKeyId };
    } catch (err) {
        console.warn("[getIdpSigningKey] Existing signing key is unreadable or corrupted. Self-healing with fresh keypair...", err);
        if (jwksRecord && jwksRecord._id) {
            await database.collection("jwks").deleteOne({ _id: jwksRecord._id }).catch(() => {});
        }
        return generateAndStoreFreshKeypair(database);
    }
}

export async function mintJwtAccessToken(params: {
    userId: string;
    clientId: string;
    expiresInSeconds?: number;
    scope?: string;
}): Promise<string | null> {
    try {
        const signingKey = await getIdpSigningKey();
        if (!signingKey) return null;

        const database = await getDb();
        const orConditions: any[] = [{ id: params.userId }];
        if (ObjectId.isValid(params.userId)) {
            orConditions.push({ _id: new ObjectId(params.userId) });
        }
        const userDoc = await database.collection("user").findOne({
            $or: orConditions
        });

        const { role, scopedClientId } = await resolveUserRoleForClient(database, userDoc, params.clientId);
        const email = userDoc?.email || undefined;
        const name = userDoc?.name || undefined;
        const ttl = params.expiresInSeconds || 900;

        const jwt = await new SignJWT({
            sub: params.userId,
            role,
            scoped_client_id: scopedClientId,
            email,
            name,
            client_id: params.clientId,
            azp: params.clientId,
            scope: params.scope || "openid profile email",
        })
            .setProtectedHeader({ alg: "RS256", kid: signingKey.kid })
            .setIssuedAt()
            .setIssuer(config.auth.baseURL)
            .setAudience(params.clientId)
            .setExpirationTime(`${ttl}s`)
            .setJti(crypto.randomUUID())
            .sign(signingKey.privateKey);

        return jwt;
    } catch (err) {
        console.error("[MINT_JWT_ACCESS_TOKEN] Error minting JWT access token:", err);
        return null;
    }
}

async function resignIdTokenWithNewAtHash(idToken: string, newAccessToken: string): Promise<string> {
    if (!idToken || typeof idToken !== "string") return idToken;
    const parts = idToken.split(".");
    if (parts.length !== 3) return idToken;
    try {
        const idPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        if (!idPayload.at_hash) return idToken;
        const newAtHash = crypto
            .createHash("sha256")
            .update(newAccessToken)
            .digest()
            .subarray(0, 16)
            .toString("base64url");
        idPayload.at_hash = newAtHash;
        const signingKey = await getIdpSigningKey();
        if (!signingKey) return idToken;
        return await new SignJWT(idPayload)
            .setProtectedHeader({ alg: "RS256", kid: signingKey.kid })
            .sign(signingKey.privateKey);
    } catch (e) {
        console.error("[ID_TOKEN_RE_SIGN] Error updating at_hash:", e);
        return idToken;
    }
}

export function isSuperAdmin(user: any): boolean {
    return Boolean(
        user &&
        user.role === "admin" &&
        user.scopedClientId === null
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
                // Secondary: MongoDB Sliding-Window TTL Collection
                const entry = await incrementRateLimit(targetKey, Date.now(), targetWindowMs);
                if (entry.count > targetLimit) {
                    targetAllowed = false;
                }
            } catch (mongoErr) {
                console.warn("[AUTH] Target rate limit store error, engaging emergency limiter:", mongoErr);
                // Tertiary: Bounded in-process emergency limiter
                const emergResult = emergencyRateLimiter.increment(targetKey, Date.now(), targetWindowMs, targetLimit);
                if (!emergResult.allowed) {
                    targetAllowed = false;
                }
            }
        }

        if (!targetAllowed) {
            return c.json(
                {
                    error: "too_many_requests",
                    message: "Too many sign-in attempts for this account. Please try again later.",
                },
                429
            );
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
    const isPromptLogin = c.req.query("prompt") === "login";
    if (!isPromptLogin) {
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
    }

    const forwardToBetterAuth = async () => {
        let rawReq = c.req.raw;
        if (isPromptLogin) {
            const h = new Headers(rawReq.headers);
            const cookieHeader = h.get("cookie") || "";
            const filteredCookies = cookieHeader
                .split(";")
                .map((part) => part.trim())
                .filter((part) => !part.startsWith("better-auth.session_token=") && !part.startsWith("__Secure-better-auth.session_token="))
                .join("; ");
            if (filteredCookies) {
                h.set("cookie", filteredCookies);
            } else {
                h.delete("cookie");
            }
            rawReq = new Request(rawReq.url, {
                method: rawReq.method,
                headers: h,
                body: rawReq.body,
                redirect: "manual",
            });
        }
        const res = await authProvider.handler(rawReq);
        const headers = new Headers(res.headers);
        headers.append("set-cookie", `oauth_transaction_id=${transactionId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);
        headers.append("set-cookie", `current_client_id=${canonicalClientId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);

        const location = headers.get("location");
        if (location) {
            try {
                const locUrl = new URL(location, config.auth.baseURL);
                if (locUrl.pathname.includes("/auth")) {
                    locUrl.searchParams.set("client_id", canonicalClientId);
                    if (!client.isPublic) {
                        locUrl.searchParams.set("is_public", "false");
                    }
                    headers.set("location", locUrl.toString());
                }
            } catch {}
        }

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
            // Unauthenticated user attempting OAuth on a private application:
            // Forward to centralized IdP login with registration disabled.
            // DO NOT block unauthenticated users from reaching the IdP login page.
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

        // Fail-Closed: Check if this token family exists and belongs to the authenticated client
        const existingFamily = await database.collection("oauth_token_families").findOne({
            $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
        });

        // Cross-client defense: Verify the token family belongs to the authenticated client
        // Do NOT leak whether the token exists, is consumed, or is revoked to an unauthorized client
        // FAIL-CLOSED: A token family without a matching clientId is strictly rejected
        if (existingFamily && (!existingFamily.clientId || existingFamily.clientId !== canonicalClientId)) {
            return c.json(
                {
                    error: "invalid_grant",
                    error_description: "Refresh token was not issued to the authenticated client",
                },
                400
            );
        }

        if (existingFamily && existingFamily.status === "revoked") {
            return c.json(
                {
                    error: "invalid_grant",
                    error_description: "Token family has been revoked due to previous security event",
                },
                401
            );
        }

        const staleLockThreshold = new Date(Date.now() - 15000);

        // Atomic compare-and-swap to claim rotation rights for this token family
        // Scoped strictly by canonicalClientId to prevent cross-client CAS contention
        // Allows reclaiming a stale lock if a previous rotation timed out or crashed (> 15s)
        const claim = await database.collection("oauth_token_families").findOneAndUpdate(
            {
                activeTokenHash: incomingHash,
                clientId: canonicalClientId,
                status: "active",
                $or: [
                    { rotating: { $ne: true } },
                    { rotatingAt: { $lt: staleLockThreshold } },
                ],
            },
            {
                $set: { rotating: true, rotatingAt: new Date() },
            },
            { returnDocument: "after" }
        );

        if (!claim) {
            // Check if rotation is currently in-flight by the winning concurrent request for this client
            const currentDoc = await database.collection("oauth_token_families").findOne({
                clientId: canonicalClientId,
                $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
            });

            const isActivelyRotating =
                currentDoc &&
                (currentDoc as any).rotating === true &&
                (currentDoc as any).rotatingAt &&
                new Date((currentDoc as any).rotatingAt).getTime() > Date.now() - 15000;

            if (isActivelyRotating) {
                return c.json(
                    {
                        error: "invalid_grant",
                        error_description: "Refresh token was already consumed or is currently being rotated",
                    },
                    400
                );
            }

            // Otherwise, token was already rotated; check if within grace window or replay theft
            const check = await verifyAndRotateTokenFamily(incomingHash, "dummy", undefined, Date.now(), canonicalClientId);
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
                { activeTokenHash: incomingHash, clientId: canonicalClientId, rotating: true },
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
                const rotationResult = await verifyAndRotateTokenFamily(incomingHash, newHash, resolvedUserId, Date.now(), canonicalClientId);

                if (rotationResult.replayed) {
                    return c.json(
                        {
                            error: "invalid_grant",
                            error_description: "Refresh token has been revoked due to replay detection",
                        },
                        401
                    );
                }

                if (!rotationResult.valid) {
                    return c.json(
                        {
                            error: "invalid_grant",
                            error_description: "Refresh token was already consumed or is invalid",
                        },
                        400
                    );
                }

                if (tokenData && tokenData.access_token) {
                    if (!resolvedUserId) {
                        console.error("[TOKEN_MINTING] Missing resolvedUserId in refresh_token flow; failing closed without opaque fallback");
                        const newRefreshHash = tokenData.refresh_token
                            ? crypto.createHash("sha256").update(tokenData.refresh_token).digest("base64url")
                            : null;
                        const newAccessHash = tokenData.access_token
                            ? crypto.createHash("sha256").update(tokenData.access_token).digest("base64url")
                            : null;

                        // FAIL CLOSED: Purge unminted new tokens; never resurrect consumed old credentials
                        if (tokenData.refresh_token) {
                            await database.collection("oauthRefreshToken").deleteMany({
                                $or: [
                                    { token: tokenData.refresh_token },
                                    ...(newRefreshHash ? [{ token: newRefreshHash }] : [])
                                ]
                            }).catch(() => {});
                        }
                        if (tokenData.access_token) {
                            await database.collection("oauthAccessToken").deleteMany({
                                $or: [
                                    { token: tokenData.access_token },
                                    ...(newAccessHash ? [{ token: newAccessHash }] : [])
                                ]
                            }).catch(() => {});
                        }
                        if (rotationResult.familyId) {
                            await database.collection("oauth_token_families").updateOne(
                                { familyId: rotationResult.familyId, activeTokenHash: newHash },
                                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                            ).catch(() => {});
                        }
                        return c.json(
                            {
                                error: "server_error",
                                error_description: "Failed to resolve authenticated user identity for token minting",
                            },
                            500
                        );
                    }

                    const jwtAt = await mintJwtAccessToken({
                        userId: resolvedUserId,
                        clientId: canonicalClientId,
                        expiresInSeconds: tokenData.expires_in || 900,
                        scope: tokenData.scope,
                    });

                    if (!jwtAt) {
                        console.error("[TOKEN_MINTING] Failed to mint RS256 access token in refresh_token flow; failing closed without opaque fallback");
                        const newRefreshStoredHash = tokenData.refresh_token
                            ? crypto.createHash("sha256").update(tokenData.refresh_token).digest("base64url")
                            : null;
                        const newAccessStoredHash = tokenData.access_token
                            ? crypto.createHash("sha256").update(tokenData.access_token).digest("base64url")
                            : null;

                        // FAIL CLOSED: Purge newly minted refresh and access tokens
                        if (tokenData.refresh_token) {
                            await database.collection("oauthRefreshToken").deleteMany({
                                $or: [
                                    { token: tokenData.refresh_token },
                                    ...(newRefreshStoredHash ? [{ token: newRefreshStoredHash }] : [])
                                ]
                            }).catch(() => {});
                        }
                        if (tokenData.access_token) {
                            await database.collection("oauthAccessToken").deleteMany({
                                $or: [
                                    { token: tokenData.access_token },
                                    ...(newAccessStoredHash ? [{ token: newAccessStoredHash }] : [])
                                ]
                            }).catch(() => {});
                        }

                        // Revoke the token family forward-only so neither consumed incoming token nor unminted token is usable.
                        // NEVER resurrect consumed/deleted credentials or reverse concurrent administrator revocations.
                        if (rotationResult.familyId) {
                            await database.collection("oauth_token_families").updateOne(
                                { familyId: rotationResult.familyId, activeTokenHash: newHash },
                                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                            ).catch(() => {});
                        }

                        return c.json(
                            {
                                error: "server_error",
                                error_description: "Failed to mint RS256 access token",
                            },
                            500
                        );
                    }

                    await database.collection("oauthAccessToken").insertOne({
                        token: jwtAt,
                        clientId: canonicalClientId,
                        userId: resolvedUserId,
                        expiresAt: new Date(Date.now() + (tokenData.expires_in || 900) * 1000),
                        createdAt: new Date(),
                        scopes: tokenData.scope ? tokenData.scope.split(" ") : ["openid", "profile", "email"],
                    }).catch(() => {});
                    tokenData.access_token = jwtAt;
                    if (tokenData.id_token) {
                        tokenData.id_token = await resignIdTokenWithNewAtHash(tokenData.id_token, jwtAt);
                    }
                    return c.json(tokenData, 200);
                }
            }
        } else {
            // Unset rotating on failure
            await database.collection("oauth_token_families").updateOne(
                { activeTokenHash: incomingHash, clientId: canonicalClientId, rotating: true },
                { $set: { rotating: false } }
            ).catch(() => {});

            // Check if failure was due to replaying an already consumed token
            const check = await verifyAndRotateTokenFamily(incomingHash, "dummy", undefined, Date.now(), canonicalClientId);
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

            // Extract authenticated userId — resolve at outer scope so JWT minting below can access it
            let resolvedUserId: string | undefined = preCodeUserId;
            if (tokenData) {
                if (!resolvedUserId && tokenData.id_token && typeof tokenData.id_token === "string") {
                    const parts = tokenData.id_token.split(".");
                    if (parts.length === 3) {
                        try {
                            const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                            resolvedUserId = jwtPayload.sub || jwtPayload.userId;
                        } catch {}
                    }
                }
                // DB polling fallback (access token is opaque at this point; only use refresh_token lookup)
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
            }

            let initialHash: string | null = null;
            let familyId: string | null = null;
            if (tokenData && tokenData.refresh_token) {
                initialHash = crypto.createHash("sha256").update(tokenData.refresh_token).digest("hex");
                familyId = crypto.randomUUID();

                // Strictly bind token family to canonicalClientId and resolvedUserId
                try {
                    await registerTokenFamily(familyId, canonicalClientId, resolvedUserId, initialHash);
                } catch (regErr) {
                    console.error("[TOKEN_FAMILY] Critical failure registering initial family; failing closed:", regErr);
                    // FAIL CLOSED: Purge issued tokens so no untracked refresh token exists in DB (Phase 10)
                    await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
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

            if (tokenData && tokenData.access_token) {
                if (!resolvedUserId) {
                    console.error("[TOKEN_MINTING] Missing resolvedUserId in authorization_code flow; failing closed without opaque fallback");
                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                        if (familyId) {
                            await database.collection("oauth_token_families").deleteMany({ familyId }).catch(() => {});
                        }
                    }
                    await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    return c.json(
                        {
                            error: "server_error",
                            error_description: "Failed to resolve authenticated user identity for token minting",
                        },
                        500
                    );
                }

                const jwtAt = await mintJwtAccessToken({
                    userId: resolvedUserId,
                    clientId: canonicalClientId,
                    expiresInSeconds: tokenData.expires_in || 900,
                    scope: tokenData.scope,
                });

                if (!jwtAt) {
                    console.error("[TOKEN_MINTING] Failed to mint RS256 access token in authorization_code flow; failing closed without opaque fallback");
                    const newRefreshStoredHash = tokenData.refresh_token
                        ? crypto.createHash("sha256").update(tokenData.refresh_token).digest("base64url")
                        : null;
                    const newAccessStoredHash = tokenData.access_token
                        ? crypto.createHash("sha256").update(tokenData.access_token).digest("base64url")
                        : null;

                    // FAIL CLOSED: Purge any created tokens and token family state so no partial/unusable credentials survive
                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({
                            $or: [
                                { token: tokenData.refresh_token },
                                ...(newRefreshStoredHash ? [{ token: newRefreshStoredHash }] : [])
                            ]
                        }).catch(() => {});
                        if (familyId) {
                            await database.collection("oauth_token_families").deleteMany({ familyId }).catch(() => {});
                        }
                    }
                    if (tokenData.access_token) {
                        await database.collection("oauthAccessToken").deleteMany({
                            $or: [
                                { token: tokenData.access_token },
                                ...(newAccessStoredHash ? [{ token: newAccessStoredHash }] : [])
                            ]
                        }).catch(() => {});
                    }

                    return c.json(
                        {
                            error: "server_error",
                            error_description: "Failed to mint RS256 access token",
                        },
                        500
                    );
                }

                await database.collection("oauthAccessToken").insertOne({
                    token: jwtAt,
                    clientId: canonicalClientId,
                    userId: resolvedUserId,
                    expiresAt: new Date(Date.now() + (tokenData.expires_in || 900) * 1000),
                    createdAt: new Date(),
                    scopes: tokenData.scope ? tokenData.scope.split(" ") : ["openid", "profile", "email"],
                }).catch(() => {});
                tokenData.access_token = jwtAt;
                if (tokenData.id_token) {
                    tokenData.id_token = await resignIdTokenWithNewAtHash(tokenData.id_token, jwtAt);
                }
                return c.json(tokenData, 200);
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
        const authHeader = c.req.header("authorization") || c.req.header("Authorization");
        const bearerToken = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

        let res = await authProvider.handler(c.req.raw);

        // Fallback for RS256 JWT access tokens if Better Auth expects opaque tokens
        if (res.status !== 200 && bearerToken && bearerToken.includes(".")) {
            try {
                let kid: string | undefined;
                try {
                    const header = decodeProtectedHeader(bearerToken);
                    kid = header.kid;
                } catch {}
                const publicKey = await getIdpPublicKey(kid);
                if (publicKey) {
                    const { payload } = await jwtVerify(bearerToken, publicKey, {
                        algorithms: ["RS256"],
                        issuer: config.auth.baseURL,
                    });
                    if (payload && payload.sub) {
                        const database = await getDb();
                        const userId = String(payload.sub);
                        const userDoc = await database.collection("user").findOne({
                            $or: [
                                { id: userId },
                                ...(ObjectId.isValid(userId) ? [{ _id: new ObjectId(userId) }] : [])
                            ]
                        });
                        const targetClientId = (payload.client_id || payload.azp || (typeof payload.aud === "string" ? payload.aud : payload.aud?.[0]) || "") as string;
                        const resolved = await resolveUserRoleForClient(database, userDoc, targetClientId);
                        return c.json({
                            sub: userId,
                            email: userDoc?.email || payload.email,
                            name: userDoc?.name || payload.name || (userDoc?.email ? userDoc.email.split("@")[0] : userId),
                            role: resolved.role,
                            scoped_client_id: resolved.scopedClientId,
                        }, 200);
                    }
                }
            } catch {
                // fall through to error handling
            }
        }
        if (res.status >= 500) {
            return c.json(
                { error: "invalid_token", error_description: "Invalid or unsupported access token" },
                401,
                { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid or unsupported access token"' }
            );
        }
        if (res.status === 200) {
            try {
                const text = await res.text();
                let data: any = null;
                try {
                    data = JSON.parse(text);
                } catch {
                    return new Response(text, { status: res.status, headers: res.headers });
                }

                if (data && (data.sub || data.id)) {
                    const database = await getDb();
                    const userId = String(data.sub || data.id);
                    const orConditions: any[] = [{ id: userId }];
                    if (data.email) orConditions.push({ email: data.email });
                    if (ObjectId.isValid(userId)) {
                        orConditions.push({ _id: new ObjectId(userId) });
                    }
                    const userDoc = await database.collection("user").findOne({
                        $or: orConditions
                    });

                    let targetClientId = c.req.query("client_id") || "";
                    if (!targetClientId && bearerToken) {
                        try {
                            const decoded: any = decodeJwt(bearerToken);
                            targetClientId = (decoded?.client_id || decoded?.azp || (typeof decoded?.aud === "string" ? decoded.aud : decoded?.aud?.[0]) || "") as string;
                        } catch {}
                    }
                    const resolved = await resolveUserRoleForClient(database, userDoc, targetClientId);
                    data.role = resolved.role;
                    data.scoped_client_id = resolved.scopedClientId;
                    return c.json(data, 200);
                }
                return c.json(data, 200);
            } catch (err) {
                console.error("[USERINFO_ERR]", err);
                return res;
            }
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

// 6.5. Token Introspection Interceptor (RFC 7662)
auth.post("/oauth2/introspect", async (c) => {
    try {
        const rawBodyText = await c.req.raw.clone().text().catch(() => "");
        const params = new URLSearchParams(rawBodyText);
        const token = params.get("token") || c.req.query("token") || "";

        // First forward to Better Auth for client authentication and default handling
        const res = await authProvider.handler(c.req.raw);

        // If Better Auth rejected client credentials (e.g. 401), preserve the security gate
        if (res.status !== 200) {
            return res;
        }

        const data = await res.clone().json().catch(() => null);

        // If Better Auth already identified it as active, return immediately
        if (data && data.active === true) {
            return res;
        }

        // Better Auth returned active: false (e.g. JWT audience did not match a registered resource server).
        // Check if the token is an RS256 JWT access token issued by SWYRA Auth.
        if (token && typeof token === "string" && token.includes(".")) {
            try {
                // Extract authenticated client ID from Basic Auth or request body
                let authClientId: string | undefined;
                const authHeader = c.req.header("authorization") || c.req.header("Authorization");
                if (authHeader && authHeader.toLowerCase().startsWith("basic ")) {
                    try {
                        const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
                        const idx = decoded.indexOf(":");
                        if (idx !== -1) authClientId = decoded.slice(0, idx);
                    } catch {}
                }
                if (!authClientId) {
                    authClientId = params.get("client_id") || undefined;
                }

                let kid: string | undefined;
                try {
                    const header = decodeProtectedHeader(token);
                    kid = header.kid;
                } catch {}
                const publicKey = await getIdpPublicKey(kid);
                if (publicKey) {
                    const { payload } = await jwtVerify(token, publicKey, {
                        algorithms: ["RS256"],
                        issuer: config.auth.baseURL,
                    });

                    const nowSec = Math.floor(Date.now() / 1000);
                    if (payload.exp && payload.exp <= nowSec) {
                        return c.json({ active: false }, 200);
                    }

                    // RFC 7662 §4: Anti-scanning & Cross-client token isolation
                    const tokenClientId = (payload.client_id as string) || (payload.azp as string) || (payload.aud as string);
                    if (authClientId && tokenClientId && tokenClientId !== authClientId) {
                        return c.json({ active: false }, 200);
                    }

                    // Check active state in database (revocation check)
                    const database = await getDb();
                    const tokenDoc = await database.collection("oauthAccessToken").findOne({
                        token,
                        clientId: tokenClientId,
                    });
                    if (!tokenDoc) {
                        return c.json({ active: false }, 200);
                    }

                    // Dynamically resolve user role to ensure freshly revoked or granted admin privileges reflect immediately
                    const userId = String(payload.sub || tokenDoc.userId || "");
                    const orConditions: any[] = [{ id: userId }];
                    if (payload.email) orConditions.push({ email: payload.email });
                    if (ObjectId.isValid(userId)) {
                        orConditions.push({ _id: new ObjectId(userId) });
                    }
                    const userDoc = await database.collection("user").findOne({
                        $or: orConditions,
                    });

                    const resolved = await resolveUserRoleForClient(database, userDoc, tokenClientId);

                    return c.json({
                        active: true,
                        sub: payload.sub,
                        client_id: tokenClientId,
                        scope: payload.scope || (Array.isArray(tokenDoc.scopes) ? tokenDoc.scopes.join(" ") : "openid profile email"),
                        exp: payload.exp,
                        iat: payload.iat,
                        iss: payload.iss,
                        token_type: "Bearer",
                        role: resolved.role,
                        scoped_client_id: resolved.scopedClientId,
                    }, 200);
                }
            } catch {
                return c.json({ active: false }, 200);
            }
        }

        return res;
    } catch (err) {
        console.error("[INTROSPECT_ERR]", err);
        return c.json({ active: false }, 200);
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
        clientId = getCookie(c, "current_client_id") || null;
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
