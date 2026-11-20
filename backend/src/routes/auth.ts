import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import crypto from "crypto";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { ObjectId } from "mongodb";
import {
    registerTokenFamily,
    verifyAndRotateTokenFamily,
    incrementRateLimit,
    createOAuthTransaction,
    getOAuthTransaction,
    consumeOAuthTransaction,
    recordAuthEvent,
} from "../db/state";
import { rateLimiters, checkRateLimit } from "../cache/redis";
import { getTrustedClientIp, getHeaders, resolveOAuthClient, isRegisteredRedirectUri, checkUserAppRegistration, checkUserHasAppAccess, hashToken, hasDangerousMongoKeys, validateSafePrimitiveString, toApprovedDisplayLabel, isEmailShaped } from "../utils/security";
import { config } from "../config";
import { emergencyRateLimiter } from "../middleware/rate-limit";
import { checkAccountEligibility } from "../utils/account-eligibility";

import { importJWK, SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader, generateKeyPair, exportJWK } from "jose";
import { getIdpPublicKey, checkUserIsClientAdmin, requireAdmin, requireSuperAdmin, requireRecentMfa } from "../middleware/admin-auth";
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

    // 1. Global Super Admin: MAuth platform dashboard only.
    // USER-REQUIRED POLICY: Super admins must NEVER receive consumer app-admin privileges or enter consumer admin portals using their platform identity.
    if (isSuperAdmin(userDoc)) {
        return { role: "user", scopedClientId: null };
    }

    if (!clientId) {
        return { role: "user", scopedClientId: null };
    }

    // 2. Application Administrator: verify explicit assignment for this target clientId
    const userIdStr = (userDoc.id || userDoc._id)?.toString();
    if (userIdStr && database) {
        const isClientAdmin = await checkUserIsClientAdmin(database, userDoc, userIdStr, clientId);
        if (isClientAdmin) {
            return { role: "admin", scopedClientId: clientId };
        }
    }

    // 3. Default to role: "user" with scopedClientId null
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

export type TokenBarrierStage =
    | "before_issuance_commit"
    | "after_issuance_commit"
    | "before_fence_code"
    | "before_fence_refresh";

let tokenBarrierHookForTesting: ((stage: TokenBarrierStage, userId?: string) => Promise<void>) | null = null;
export function setTokenBarrierHookForTesting(hook: ((stage: TokenBarrierStage, userId?: string) => Promise<void>) | null): void {
    tokenBarrierHookForTesting = hook;
}

export async function revokeUserTokensDurable(database: any, userId: string, revocationTime?: Date): Promise<number> {
    const now = revocationTime || new Date();
    const filter = {
        $or: [
            { id: userId },
            ...(ObjectId.isValid(userId) && userId.length === 24 ? [{ _id: new ObjectId(userId) }] : []),
        ],
    };

    const updateResult = await database.collection("user").findOneAndUpdate(
        filter,
        [
            {
                $set: {
                    tokenVersion: {
                        $add: [{ $ifNull: ["$tokenVersion", 1] }, 1],
                    },
                    tokensRevokedBefore: {
                        $cond: {
                            if: { $gt: ["$tokensRevokedBefore", now] },
                            then: "$tokensRevokedBefore",
                            else: now,
                        },
                    },
                },
            },
        ],
        { returnDocument: "after" }
    );

    const updatedDoc = updateResult?.value || updateResult;
    const finalVersion = typeof updatedDoc?.tokenVersion === "number" ? updatedDoc.tokenVersion : 2;

    await database.collection("oauth_token_families").updateMany(
        { userId },
        { $set: { status: "revoked", revokedAt: now, rotating: false } }
    );

    await Promise.all([
        database.collection("oauthAccessToken").deleteMany({ userId }),
        database.collection("oauthRefreshToken").deleteMany({ userId }),
    ]);

    return finalVersion;
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
    tokenIssuedAtSec?: number;
    tokenIssuedAtMs?: number;
    tokenVersion?: number;
    familyId?: string;
}): Promise<string | null> {
    try {
        const signingKey = await getIdpSigningKey();
        if (!signingKey) return null;

        const database = await getDb();
        const orConditions: any[] = [{ id: params.userId }];
        if (ObjectId.isValid(params.userId) && String(params.userId).length === 24) {
            orConditions.push({ _id: new ObjectId(params.userId) });
        }
        const userDoc = await database.collection("user").findOne({
            $or: orConditions
        });

        // Enforce Authoritative Account Eligibility
        const nowMs = Date.now();
        const tokenIssuedAtMs = params.tokenIssuedAtMs ?? (params.tokenIssuedAtSec ? params.tokenIssuedAtSec * 1000 : nowMs);
        const tokenIssuedAtSec = params.tokenIssuedAtSec ?? Math.floor(tokenIssuedAtMs / 1000);
        const tokenVersion = params.tokenVersion ?? (typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1);

        const eligibility = checkAccountEligibility(userDoc, {
            tokenIssuedAtMs,
            tokenIssuedAtSec,
            tokenVersion,
        });
        if (!eligibility.eligible) {
            console.warn(`[MINT_JWT_ACCESS_TOKEN] Denied token minting for ineligible account ${params.userId}: ${eligibility.reason}`);
            return null;
        }

        const { role, scopedClientId } = await resolveUserRoleForClient(database, userDoc, params.clientId);

        // Scope and Privacy Enforcement (Slice 2): Release claims only under granted scopes
        const scopes = (params.scope || "openid profile email")
            .split(" ")
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean);
        const scopeSet = new Set(scopes);

        const email = scopeSet.has("email") ? (userDoc?.email || undefined) : undefined;
        const emailVerified = scopeSet.has("email") ? (userDoc?.emailVerified ?? undefined) : undefined;
        const rawName = userDoc?.name || (userDoc?.email ? userDoc.email.split("@")[0] : undefined);
        const safeName = isEmailShaped(rawName) ? toApprovedDisplayLabel(rawName) : rawName;
        const name = scopeSet.has("profile") ? safeName : undefined;
        const ttl = params.expiresInSeconds || 900;

        const claims: Record<string, any> = {
            sub: params.userId,
            role,
            scoped_client_id: scopedClientId,
            client_id: params.clientId,
            azp: params.clientId,
            scope: params.scope || "openid profile email",
            iat_ms: tokenIssuedAtMs,
            token_version: tokenVersion,
        };

        if (params.familyId) {
            claims.family_id = params.familyId;
        }

        if (email !== undefined) claims.email = email;
        if (emailVerified !== undefined) claims.email_verified = emailVerified;
        if (name !== undefined) claims.name = name;

        const jwt = await new SignJWT(claims)
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
    if (!user) return false;
    if (user.role === "super-admin") {
        return user.scopedClientId === null;
    }
    if (user.role === "admin" && user.scopedClientId === null) {
        return true;
    }
    return false;
}

export function isAppAdmin(user: any): boolean {
    if (!user) return false;
    if (user.role === "app-admin") return true;
    if (user.role === "admin" && typeof user.scopedClientId === "string" && user.scopedClientId.trim().length > 0) {
        return true;
    }
    return false;
}

interface ClientContext {
    clientId: string | null;
    isBoundOAuthFlow: boolean;
}

// Helper to extract clientId from various locations with authoritative transaction state resolution
async function extractClientContext(c: any, body?: any): Promise<ClientContext> {
    const query = c.req.query("client_id") || c.req.query("clientId");
    if (query) return { clientId: query, isBoundOAuthFlow: true };

    if (body?.clientId) return { clientId: body.clientId, isBoundOAuthFlow: true };
    if (body?.client_id) return { clientId: body.client_id, isBoundOAuthFlow: true };

    let state: string | null = c.req.query("state") || null;

    if (body?.callbackURL && typeof body.callbackURL === "string") {
        try {
            const url = new URL(body.callbackURL, "http://localhost");
            const cid = url.searchParams.get("client_id") || url.searchParams.get("clientId");
            if (cid) return { clientId: cid, isBoundOAuthFlow: true };
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    const callbackQuery = c.req.query("callbackURL");
    if (callbackQuery) {
        try {
            const url = new URL(callbackQuery, "http://localhost");
            const cid = url.searchParams.get("client_id") || url.searchParams.get("clientId");
            if (cid) return { clientId: cid, isBoundOAuthFlow: true };
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    // Authoritative server-side transaction lookup by state parameter
    if (state) {
        const tx = await getOAuthTransaction({ state });
        if (tx?.clientId) return { clientId: tx.clientId, isBoundOAuthFlow: true };
    }

    // Detect platform (MAuth) sign-in context.
    // Platform sign-in has callbackURL explicitly pointing to /admin or /api/admin.
    // Stale oauth_transaction_id / current_client_id cookies from a prior
    // private-app OAuth flow must NEVER contaminate platform sign-in.
    const rawCallback = body?.callbackURL ?? c.req.query("callbackURL") ?? "";
    let callbackPath = "";
    if (typeof rawCallback === "string" && rawCallback.length > 0) {
        try {
            callbackPath = new URL(rawCallback, "http://localhost").pathname;
        } catch {
            callbackPath = rawCallback;
        }
    }
    const isPlatformSignIn =
        callbackPath.startsWith("/admin") ||
        callbackPath.startsWith("/api/admin");

    if (!isPlatformSignIn) {
        // Only inherit cookie-based client context for ongoing OAuth flows,
        // never for platform sign-in. Cookie fallback requires no explicit
        // client_id or state to be present in the request.
        const txIdCookie = getCookie(c, "oauth_transaction_id");
        if (txIdCookie) {
            const tx = await getOAuthTransaction({ transactionId: txIdCookie });
            if (tx?.clientId) return { clientId: tx.clientId, isBoundOAuthFlow: true };
        }

        const cookieVal = getCookie(c, "current_client_id");
        if (cookieVal) {
            // A bare current_client_id cookie without an active validated transaction
            // is validated for client existence (preventing cookie poisoning), but is not
            // treated as a bound OAuth flow for private app membership blocking.
            return { clientId: cookieVal, isBoundOAuthFlow: false };
        }
    }

    return { clientId: null, isBoundOAuthFlow: false };
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
        if (!clientDoc || clientDoc.disabled) {
            await recordAuthEvent({
                eventType: "sign_in",
                outcome: "denied",
                clientId,
                targetIdentifier,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: clientDoc?.disabled ? "client_disabled" : "invalid_client",
            });
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

    const boundClientId = (clientCtx.isBoundOAuthFlow && canonicalClientId) ? canonicalClientId : null;
    const boundClientName = (clientCtx.isBoundOAuthFlow && clientDoc) ? (clientDoc.client_name || clientDoc.name || null) : null;

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
            await recordAuthEvent({
                eventType: "account_lockout",
                outcome: "denied",
                targetIdentifier,
                clientId: boundClientId,
                clientName: boundClientName,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: "rate_limit_exceeded",
                details: { threshold: 15, windowSeconds: 300 },
            });
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
        } else if (clientDoc && !clientDoc.isPublic && canonicalClientId && clientCtx.isBoundOAuthFlow) {
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

    // CRITICAL SECURITY INVARIANT:
    // Application membership MUST NEVER mutate before successful authentication!
    // Only if credentials were valid (res.status 2xx) and application is public, record registration.
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
            // CRITICAL AUTHENTICATION BOUNDARY:
            // First factor (password) verified, but authentication is NOT completed until MFA finishes!
            // Do NOT record sign_in success or mutate application registration here.
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
            const setCookie = res.headers.get("set-cookie") || "";
            const match = setCookie.match(/better-auth\.session_token=([^;]+)/);
            if (match) {
                const rawToken = decodeURIComponent(match[1]);
                const token = rawToken.split(".")[0];
                const sessionDoc = await database.collection("session").findOne({ token });
                if (sessionDoc) {
                    sessionId = String(sessionDoc._id || sessionDoc.id);
                }
            }
        } catch {}

        if (authUserId && clientDoc && clientDoc.isPublic && canonicalClientId) {
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
});

// 3. Sign-Up App-Isolation Registration
auth.post("/sign-up/email", async (c) => {
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
        if (!clientDoc || clientDoc.disabled) {
            await recordAuthEvent({
                eventType: "sign_up",
                outcome: "denied",
                clientId,
                targetIdentifier,
                ipAddress: safeIp,
                userAgent: safeUserAgent,
                reason: clientDoc?.disabled ? "client_disabled" : "invalid_client",
            });
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
    const isSuccess = res.status >= 200 && res.status < 300;
    let createdUserId: string | null = null;

    // Only upon successful user creation (res.status 2xx), ensure no privilege fields and record public app registration
    if (isSuccess && body?.email) {
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

            const createdUser = await database.collection("user").findOne({ email });
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
                const sessionUserId = String(sessionResult.user.id || (sessionResult.user as any)._id);
                const userDoc = await database.collection("user").findOne({
                    $or: [
                        { id: sessionUserId },
                        ...(ObjectId.isValid(sessionUserId) && sessionUserId.length === 24 ? [{ _id: new ObjectId(sessionUserId) }] : []),
                    ],
                });

                // Authoritative Account Eligibility Check on Authorize
                // Bound to active session creation timestamp; older session must not survive revocation
                const sessionCreatedAtMs = sessionResult?.session?.createdAt
                    ? new Date(sessionResult.session.createdAt).getTime()
                    : Date.now();
                const sessionCreatedAtSec = Math.floor(sessionCreatedAtMs / 1000);
                const eligibility = checkAccountEligibility(userDoc, {
                    tokenIssuedAtMs: sessionCreatedAtMs,
                    tokenIssuedAtSec: sessionCreatedAtSec,
                    tokenVersion: userDoc?.tokenVersion,
                });
                if (!eligibility.eligible) {
                    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                    await recordAuthEvent({
                        eventType: "oauth_authorize",
                        outcome: "denied",
                        userId: sessionUserId,
                        targetIdentifier: userDoc?.email || sessionResult.user.email || null,
                        clientId: canonicalClientId,
                        clientName: client.client_name || client.name || null,
                        ipAddress: safeIp,
                        reason: `account_ineligible_${eligibility.reason}`,
                    });
                    const errorUrl = new URL(redirectUri);
                    errorUrl.searchParams.set("error", "access_denied");
                    errorUrl.searchParams.set("error_description", `Account is not eligible for authorization: ${eligibility.reason}`);
                    errorUrl.searchParams.set("state", state);
                    return c.redirect(errorUrl.toString(), 302);
                }

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

        let location = headers.get("location");

        // If Better Auth returned a JSON object with { redirect: true, url }, convert it into a standard
        // OAuth 302 Found redirect so browser user-agents seamlessly follow authorization to the callback URL
        if (!location && res.status === 200) {
            try {
                const resClone = res.clone();
                const json = await resClone.json();
                if (json && json.redirect === true && typeof json.url === "string") {
                    location = json.url;
                    headers.set("location", location);
                }
            } catch {}
        }

        if (location) {
            try {
                const locUrl = new URL(location, config.auth.baseURL);
                const code = locUrl.searchParams.get("code");
                if (code && sessionUser) {
                    const sessionUserId = String(sessionUser.id || sessionUser._id);
                    const currentVersion = typeof sessionUser.tokenVersion === "number" ? sessionUser.tokenVersion : 1;
                    await database.collection("oauthAuthorizationCode").updateOne(
                        { code },
                        {
                            $set: {
                                tokenVersion: currentVersion,
                                userId: sessionUserId,
                            },
                        }
                    ).catch(() => {});
                }
                if (locUrl.pathname.includes("/auth")) {
                    locUrl.searchParams.set("client_id", canonicalClientId);
                    if (!client.isPublic) {
                        locUrl.searchParams.set("is_public", "false");
                    }
                    location = locUrl.toString();
                    headers.set("location", location);
                }
            } catch {}
            return new Response(null, {
                status: 302,
                statusText: "Found",
                headers,
            });
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
            const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

            if (!hasAccess) {
                const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                await recordAuthEvent({
                    eventType: "oauth_authorize",
                    outcome: "denied",
                    userId: String(sessionUser.id || (sessionUser as any)._id),
                    targetIdentifier: sessionUser.email || null,
                    clientId: canonicalClientId,
                    clientName: client.client_name || client.name || null,
                    ipAddress: safeIp,
                    reason: "private_app_unauthorized",
                });
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
    if (hasBasicAuth || bodyClientSecret) {
        params.delete("client_id");
    } else {
        // Preserve canonical client_id in body for public clients
        params.set("client_id", canonicalClientId);
    }
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
        const incomingHash = hashToken(refreshToken, "hex");

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
                const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                await recordAuthEvent({
                    eventType: "oauth_token",
                    outcome: "denied",
                    clientId: canonicalClientId,
                    clientName: clientDoc?.client_name || clientDoc?.name || null,
                    ipAddress: safeIp,
                    reason: "refresh_token_reuse",
                });
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

        let preRefreshIssuedAtSec: number | undefined;
        let preRefreshIssuedAtMs: number | undefined;
        let preRefreshTokenVersion: number | undefined;
        let preRefreshUserId: string | undefined = existingFamily?.userId;
        if (existingFamily?.createdAt) {
            preRefreshIssuedAtMs = new Date(existingFamily.createdAt).getTime();
            preRefreshIssuedAtSec = Math.floor(preRefreshIssuedAtMs / 1000);
        }
        if (existingFamily?.tokenVersion !== undefined) {
            preRefreshTokenVersion = existingFamily.tokenVersion;
        }
        if (!preRefreshUserId || !preRefreshIssuedAtMs) {
            try {
                const oldDoc = await database.collection("oauthRefreshToken").findOne({
                    $or: [
                        { token: refreshToken },
                        { token: hashToken(refreshToken, "base64url") },
                        { token: hashToken(refreshToken, "hex") }
                    ]
                });
                if (oldDoc) {
                    if (oldDoc.userId && !preRefreshUserId) {
                        preRefreshUserId = String(oldDoc.userId);
                    }
                    if (oldDoc.createdAt) {
                        preRefreshIssuedAtMs = new Date(oldDoc.createdAt).getTime();
                        preRefreshIssuedAtSec = Math.floor(preRefreshIssuedAtMs / 1000);
                    }
                    if (oldDoc.tokenVersion !== undefined) {
                        preRefreshTokenVersion = oldDoc.tokenVersion;
                    }
                }
            } catch {}
        }

        // CRITICAL SECURITY INVARIANT:
        // Authoritative Account Eligibility across all client types (public and private)
        if (preRefreshUserId) {
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: preRefreshUserId },
                    ...(ObjectId.isValid(preRefreshUserId) && preRefreshUserId.length === 24 ? [{ _id: new ObjectId(preRefreshUserId) }] : []),
                ]
            });
            const eligibility = checkAccountEligibility(userDoc, {
                tokenIssuedAtMs: preRefreshIssuedAtMs,
                tokenIssuedAtSec: preRefreshIssuedAtSec ?? Math.floor(Date.now() / 1000),
                tokenVersion: preRefreshTokenVersion,
            });
            if (!eligibility.eligible) {
                // Immediately purge issued tokens and revoke family
                await Promise.all([
                    database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
                    database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
                    database.collection("oauth_token_families").updateMany(
                        { clientId: canonicalClientId, userId: preRefreshUserId },
                        { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                    ),
                ]);
                return c.json(
                    {
                        error: "invalid_grant",
                        error_description: `User account is not eligible for token refresh: ${eligibility.reason}`,
                    },
                    401
                );
            }

            if (!clientDoc.isPublic) {
                const hasAccess = await checkUserHasAppAccess(database, userDoc || preRefreshUserId, canonicalClientId);
                if (!hasAccess) {
                    await Promise.all([
                        database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
                        database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
                        database.collection("oauth_token_families").updateMany(
                            { clientId: canonicalClientId, userId: preRefreshUserId },
                            { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
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
                // Authoritative Account Eligibility across all client types (public and private)
                if (resolvedUserId) {
                    const userDoc = await database.collection("user").findOne({
                        $or: [
                            { id: resolvedUserId },
                            ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
                        ]
                    });
                    const eligibility = checkAccountEligibility(userDoc, {
                        tokenIssuedAtMs: preRefreshIssuedAtMs,
                        tokenIssuedAtSec: preRefreshIssuedAtSec ?? Math.floor(Date.now() / 1000),
                        tokenVersion: preRefreshTokenVersion,
                    });
                    if (!eligibility.eligible) {
                        // Immediately purge issued tokens and revoke family
                        await Promise.all([
                            database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauth_token_families").updateMany(
                                { clientId: canonicalClientId, userId: resolvedUserId },
                                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                            ),
                        ]);
                        return c.json(
                            {
                                error: "invalid_grant",
                                error_description: `User account is not eligible for token refresh: ${eligibility.reason}`,
                            },
                            401
                        );
                    }

                    if (!clientDoc.isPublic) {
                        const hasAccess = await checkUserHasAppAccess(database, userDoc || resolvedUserId, canonicalClientId);
                        if (!hasAccess) {
                            await Promise.all([
                                database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                                database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                                database.collection("oauth_token_families").updateMany(
                                    { clientId: canonicalClientId, userId: resolvedUserId },
                                    { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
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
                }

                const newHash = hashToken(tokenData.refresh_token, "hex");
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
                            ? hashToken(tokenData.refresh_token, "base64url")
                            : null;
                        const newAccessHash = tokenData.access_token
                            ? hashToken(tokenData.access_token, "base64url")
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

                    const expectedRefreshTokenVersion = typeof preRefreshTokenVersion === "number"
                        ? preRefreshTokenVersion
                        : (typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1);

                    const currentFamilyId = rotationResult.familyId || existingFamily?.familyId;

                    const jwtAt = await mintJwtAccessToken({
                        userId: resolvedUserId,
                        clientId: canonicalClientId,
                        expiresInSeconds: tokenData.expires_in || 900,
                        scope: tokenData.scope,
                        tokenIssuedAtMs: preRefreshIssuedAtMs,
                        tokenIssuedAtSec: preRefreshIssuedAtSec,
                        tokenVersion: expectedRefreshTokenVersion,
                        familyId: currentFamilyId || undefined,
                    });

                    if (!jwtAt) {
                        console.error("[TOKEN_MINTING] Failed to mint RS256 access token in refresh_token flow; failing closed without opaque fallback");
                        const newRefreshStoredHash = tokenData.refresh_token
                            ? hashToken(tokenData.refresh_token, "base64url")
                            : null;
                        const newAccessStoredHash = tokenData.access_token
                            ? hashToken(tokenData.access_token, "base64url")
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
                        familyId: currentFamilyId || undefined,
                        expiresAt: new Date(Date.now() + (tokenData.expires_in || 900) * 1000),
                        createdAt: new Date(),
                        scopes: tokenData.scope ? tokenData.scope.split(" ") : ["openid", "profile", "email"],
                        tokenVersion: expectedRefreshTokenVersion,
                    }).catch(() => {});

                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").updateOne(
                            { token: tokenData.refresh_token },
                            { $set: { familyId: currentFamilyId || undefined, tokenVersion: expectedRefreshTokenVersion } }
                        ).catch(() => {});
                    }

                    if (tokenBarrierHookForTesting && resolvedUserId) {
                        await tokenBarrierHookForTesting("before_issuance_commit", resolvedUserId);
                        await tokenBarrierHookForTesting("before_fence_refresh", resolvedUserId);
                    }

                    // Exact Issuance/Revocation Linearization Point:
                    // Durable Conditional State Transition coordinated with revocation.
                    let refreshCommitSuccess = false;
                    if (resolvedUserId) {
                        const refreshCommitCondition: Record<string, any> = {
                            $or: [
                                { id: resolvedUserId },
                                ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
                            ],
                            $and: [
                                {
                                    $or: [
                                        { tokenVersion: expectedRefreshTokenVersion },
                                        ...(expectedRefreshTokenVersion === 1 ? [{ tokenVersion: { $exists: false } }, { tokenVersion: null }] : []),
                                    ],
                                },
                                { banned: { $ne: true } },
                                { disabled: { $ne: true } },
                                { isActive: { $ne: false } },
                                { status: { $nin: ["inactive", "deleting", "deleted"] } },
                                { deletedAt: { $exists: false } },
                                ...(preRefreshIssuedAtMs ? [{
                                    $or: [
                                        { tokensRevokedBefore: { $exists: false } },
                                        { tokensRevokedBefore: null },
                                        { tokensRevokedBefore: { $lte: new Date(preRefreshIssuedAtMs) } },
                                    ],
                                }] : [{
                                    $or: [
                                        { tokensRevokedBefore: { $exists: false } },
                                        { tokensRevokedBefore: null },
                                        { tokensRevokedBefore: { $lte: new Date() } },
                                    ],
                                }]),
                                ...(preRefreshIssuedAtMs ? [{
                                    $or: [
                                        { passwordChangedAt: { $exists: false } },
                                        { passwordChangedAt: null },
                                        { passwordChangedAt: { $lte: new Date(preRefreshIssuedAtMs) } },
                                    ],
                                }] : []),
                            ],
                        };

                        const commitResult = await database.collection("user").findOneAndUpdate(
                            refreshCommitCondition,
                            {
                                $set: {
                                    tokenVersion: expectedRefreshTokenVersion,
                                    lastTokenIssuedAt: new Date(),
                                },
                            },
                            { returnDocument: "after" }
                        );

                        if (commitResult) {
                            refreshCommitSuccess = true;
                        }
                    }

                    if (!refreshCommitSuccess) {
                        await Promise.all([
                            database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                            database.collection("oauth_token_families").updateMany(
                                { clientId: canonicalClientId, userId: resolvedUserId },
                                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                            ),
                        ]);
                        return c.json(
                            {
                                error: "invalid_grant",
                                error_description: "User account was revoked or version transitioned during token refresh",
                            },
                            401
                        );
                    }

                    if (rotationResult.familyId) {
                        await database.collection("oauth_token_families").updateOne(
                            { familyId: rotationResult.familyId },
                            { $set: { rotating: false, tokenVersion: expectedRefreshTokenVersion } }
                        ).catch(() => {});
                    }

                    if (tokenBarrierHookForTesting && resolvedUserId) {
                        await tokenBarrierHookForTesting("after_issuance_commit", resolvedUserId);
                    }

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
                const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                await recordAuthEvent({
                    eventType: "oauth_token",
                    outcome: "denied",
                    clientId: canonicalClientId,
                    clientName: clientDoc?.client_name || clientDoc?.name || null,
                    ipAddress: safeIp,
                    reason: "refresh_token_reuse",
                });
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
    let codeIssuedAtSec: number | undefined;
    let codeIssuedAtMs: number | undefined;
    let codeTokenVersion: number | undefined;
    if (incomingCode) {
        try {
            const codeDoc = await database.collection("oauthAuthorizationCode").findOne({ code: incomingCode });
            if (codeDoc) {
                if (codeDoc.userId) {
                    preCodeUserId = String(codeDoc.userId);
                }
                if (codeDoc.createdAt) {
                    codeIssuedAtMs = new Date(codeDoc.createdAt).getTime();
                    codeIssuedAtSec = Math.floor(codeIssuedAtMs / 1000);
                }
                if (codeDoc.tokenVersion !== undefined) {
                    codeTokenVersion = codeDoc.tokenVersion;
                }
                if (preCodeUserId) {
                    const userDoc = await database.collection("user").findOne({
                        $or: [
                            { id: preCodeUserId },
                            ...(ObjectId.isValid(preCodeUserId) && preCodeUserId.length === 24 ? [{ _id: new ObjectId(preCodeUserId) }] : []),
                        ],
                    });
                    const eligibility = checkAccountEligibility(userDoc, {
                        tokenIssuedAtMs: codeIssuedAtMs,
                        tokenIssuedAtSec: codeIssuedAtSec ?? Math.floor(Date.now() / 1000),
                        tokenVersion: codeTokenVersion,
                    });
                    if (!eligibility.eligible) {
                        return c.json({
                            error: "invalid_grant",
                            error_description: `User account is not eligible for token exchange: ${eligibility.reason}`,
                        }, 400);
                    }
                }
            }
        } catch {}
    }

    const res = await authProvider.handler(reqToForward);

    if (res.status === 200 && grantType === "authorization_code") {
        try {
            const tokenData = await res.clone().json().catch(() => null);

            // Extract authenticated userId — resolve at outer scope so JWT minting below can access it
            let resolvedUserId: string | undefined = preCodeUserId;
            let userDoc: any = null;
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

            if (resolvedUserId) {
                userDoc = await database.collection("user").findOne({
                    $or: [
                        { id: resolvedUserId },
                        ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
                    ],
                });
                const eligibility = checkAccountEligibility(userDoc, {
                    tokenIssuedAtMs: codeIssuedAtMs,
                    tokenIssuedAtSec: codeIssuedAtSec ?? Math.floor(Date.now() / 1000),
                    tokenVersion: codeTokenVersion,
                });
                if (!eligibility.eligible) {
                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                    }
                    if (tokenData.access_token) {
                        await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    }
                    return c.json({
                        error: "invalid_grant",
                        error_description: `User account is not eligible for token exchange: ${eligibility.reason}`,
                    }, 400);
                }
            }

            const expectedTokenVersion = typeof codeTokenVersion === "number"
                ? codeTokenVersion
                : (typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1);

            let initialHash: string | null = null;
            let familyId: string | null = null;
            if (tokenData && tokenData.refresh_token) {
                initialHash = hashToken(tokenData.refresh_token, "hex");
                familyId = crypto.randomUUID();

                // Strictly bind token family to canonicalClientId and resolvedUserId
                try {
                    await registerTokenFamily(familyId, canonicalClientId, resolvedUserId, initialHash, expectedTokenVersion);
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
                    tokenIssuedAtMs: codeIssuedAtMs,
                    tokenIssuedAtSec: codeIssuedAtSec,
                    tokenVersion: expectedTokenVersion,
                    familyId: familyId || undefined,
                });

                if (!jwtAt) {
                    console.error("[TOKEN_MINTING] Failed to mint RS256 access token in authorization_code flow; failing closed without opaque fallback");
                    const newRefreshStoredHash = tokenData.refresh_token
                        ? hashToken(tokenData.refresh_token, "base64url")
                        : null;
                    const newAccessStoredHash = tokenData.access_token
                        ? hashToken(tokenData.access_token, "base64url")
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
                    familyId: familyId || undefined,
                    expiresAt: new Date(Date.now() + (tokenData.expires_in || 900) * 1000),
                    createdAt: new Date(),
                    scopes: tokenData.scope ? tokenData.scope.split(" ") : ["openid", "profile", "email"],
                    tokenVersion: expectedTokenVersion,
                }).catch(() => {});

                if (tokenData.refresh_token) {
                    await database.collection("oauthRefreshToken").updateOne(
                        { token: tokenData.refresh_token },
                        { $set: { familyId: familyId || undefined, tokenVersion: expectedTokenVersion } }
                    ).catch(() => {});
                }

                if (tokenBarrierHookForTesting && resolvedUserId) {
                    await tokenBarrierHookForTesting("before_issuance_commit", resolvedUserId);
                    await tokenBarrierHookForTesting("before_fence_code", resolvedUserId);
                }

                // Exact Issuance/Revocation Linearization Point:
                // Durable Conditional State Transition coordinated with revocation.
                let commitSuccess = false;
                if (resolvedUserId) {
                    const commitCondition: Record<string, any> = {
                        $or: [
                            { id: resolvedUserId },
                            ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
                        ],
                        $and: [
                            {
                                $or: [
                                    { tokenVersion: expectedTokenVersion },
                                    ...(expectedTokenVersion === 1 ? [{ tokenVersion: { $exists: false } }, { tokenVersion: null }] : []),
                                ],
                            },
                            { banned: { $ne: true } },
                            { disabled: { $ne: true } },
                            { isActive: { $ne: false } },
                            { status: { $nin: ["inactive", "deleting", "deleted"] } },
                            { deletedAt: { $exists: false } },
                            ...(codeIssuedAtMs ? [{
                                $or: [
                                    { tokensRevokedBefore: { $exists: false } },
                                    { tokensRevokedBefore: null },
                                    { tokensRevokedBefore: { $lte: new Date(codeIssuedAtMs) } },
                                ],
                            }] : [{
                                $or: [
                                    { tokensRevokedBefore: { $exists: false } },
                                    { tokensRevokedBefore: null },
                                    { tokensRevokedBefore: { $lte: new Date() } },
                                ],
                            }]),
                            ...(codeIssuedAtMs ? [{
                                $or: [
                                    { passwordChangedAt: { $exists: false } },
                                    { passwordChangedAt: null },
                                    { passwordChangedAt: { $lte: new Date(codeIssuedAtMs) } },
                                ],
                            }] : []),
                        ],
                    };

                    const commitResult = await database.collection("user").findOneAndUpdate(
                        commitCondition,
                        {
                            $set: {
                                tokenVersion: expectedTokenVersion,
                                lastTokenIssuedAt: new Date(),
                            },
                        },
                        { returnDocument: "after" }
                    );

                    if (commitResult) {
                        commitSuccess = true;
                    }
                }

                if (!commitSuccess) {
                    await Promise.all([
                        database.collection("oauthAccessToken").deleteMany({
                            $or: [
                                { clientId: canonicalClientId, userId: resolvedUserId },
                                { token: jwtAt },
                                ...(tokenData.access_token ? [{ token: tokenData.access_token }] : []),
                            ],
                        }),
                        database.collection("oauthRefreshToken").deleteMany({
                            $or: [
                                { clientId: canonicalClientId, userId: resolvedUserId },
                                ...(tokenData.refresh_token ? [{ token: tokenData.refresh_token }] : []),
                            ],
                        }),
                        familyId
                            ? database.collection("oauth_token_families").deleteMany({ familyId })
                            : database.collection("oauth_token_families").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
                    ]);
                    return c.json({
                        error: "invalid_grant",
                        error_description: "User account was revoked or version transitioned during token exchange",
                    }, 400);
                }

                if (tokenBarrierHookForTesting && resolvedUserId) {
                    await tokenBarrierHookForTesting("after_issuance_commit", resolvedUserId);
                }

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
                                ...(ObjectId.isValid(userId) && userId.length === 24 ? [{ _id: new ObjectId(userId) }] : [])
                            ]
                        });

                        // Authoritative Account Eligibility Check
                        const tokenIssuedAtMs = typeof payload.iat_ms === "number"
                            ? payload.iat_ms
                            : (typeof payload.iat === "number" ? payload.iat * 1000 : undefined);
                        const tokenVersion = typeof payload.token_version === "number" ? payload.token_version : undefined;
                        const eligibility = checkAccountEligibility(userDoc, {
                            tokenIssuedAtMs,
                            tokenIssuedAtSec: payload.iat,
                            tokenVersion,
                        });
                        if (!eligibility.eligible) {
                            return c.json(
                                { error: "invalid_token", error_description: `User account is ineligible or revoked: ${eligibility.reason}` },
                                401,
                                { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="User account is ineligible or revoked"' }
                            );
                        }

                        const targetClientId = (payload.client_id || payload.azp || (typeof payload.aud === "string" ? payload.aud : payload.aud?.[0]) || "") as string;

                        if (payload && (payload as any).family_id) {
                            const familyDoc = await database.collection("oauth_token_families").findOne({
                                familyId: String((payload as any).family_id),
                                ...(targetClientId ? { clientId: targetClientId } : {}),
                            });
                            if (!familyDoc || familyDoc.status === "revoked") {
                                return c.json(
                                    { error: "invalid_token", error_description: "Token family has been revoked" },
                                    401,
                                    { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token family has been revoked"' }
                                );
                            }
                        }

                        const resolved = await resolveUserRoleForClient(database, userDoc, targetClientId);

                        // Scope and Privacy Enforcement (Slice 2)
                        const scopes = ((payload.scope as string) || "openid").split(" ").map(s => s.trim().toLowerCase());
                        const scopeSet = new Set(scopes);
                        const responsePayload: Record<string, any> = {
                            sub: userId,
                            role: resolved.role,
                            scoped_client_id: resolved.scopedClientId,
                        };

                        if (scopeSet.has("email") && (userDoc?.email || payload.email)) {
                            responsePayload.email = userDoc?.email || payload.email;
                            responsePayload.email_verified = userDoc?.emailVerified ?? false;
                        }

                        if (scopeSet.has("profile")) {
                            responsePayload.name = userDoc?.name || payload.name || (userDoc?.email ? userDoc.email.split("@")[0] : userId);
                        }

                        return c.json(responsePayload, 200);
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
                    if (ObjectId.isValid(userId) && userId.length === 24) {
                        orConditions.push({ _id: new ObjectId(userId) });
                    }
                    const userDoc = await database.collection("user").findOne({
                        $or: orConditions
                    });

                    let tokenIssuedAtSec: number | undefined;
                    let tokenIssuedAtMs: number | undefined;
                    let tokenVersion: number | undefined;
                    try {
                        const accDoc = await database.collection("oauthAccessToken").findOne({
                            $or: [
                                { token: bearerToken },
                                { token: hashToken(bearerToken, "base64url") },
                                { token: hashToken(bearerToken, "hex") },
                            ],
                        });
                        if (accDoc?.createdAt) {
                            tokenIssuedAtMs = new Date(accDoc.createdAt).getTime();
                            tokenIssuedAtSec = Math.floor(tokenIssuedAtMs / 1000);
                        }
                        if (accDoc?.tokenVersion !== undefined) {
                            tokenVersion = accDoc.tokenVersion;
                        }
                    } catch {}

                    // Authoritative Account Eligibility Check
                    const eligibility = checkAccountEligibility(userDoc, {
                        tokenIssuedAtMs,
                        tokenIssuedAtSec: tokenIssuedAtSec ?? Math.floor(Date.now() / 1000),
                        tokenVersion,
                    });
                    if (!eligibility.eligible) {
                        return c.json(
                            { error: "invalid_token", error_description: `User account is ineligible or revoked: ${eligibility.reason}` },
                            401,
                            { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="User account is ineligible or revoked"' }
                        );
                    }

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

        // If Better Auth identified it as active, verify account and client status before returning active=true
        if (data && data.active === true) {
            const database = await getDb();
            const tokenSub = String(data.sub || data.userId || data.user_id || "");
            if (tokenSub) {
                const userDoc = await database.collection("user").findOne({
                    $or: [
                        { id: tokenSub },
                        ...(ObjectId.isValid(tokenSub) && tokenSub.length === 24 ? [{ _id: new ObjectId(tokenSub) }] : [])
                    ]
                });
                const eligibility = checkAccountEligibility(userDoc, {
                    tokenIssuedAtMs: data.iat_ms || (data.iat ? data.iat * 1000 : undefined),
                    tokenIssuedAtSec: data.iat || (data.exp ? data.exp - 900 : undefined),
                    tokenVersion: data.token_version,
                });
                if (!eligibility.eligible) {
                    return c.json({ active: false }, 200);
                }
            }

            const tokenClientId = data.client_id || data.clientId;
            if (tokenClientId) {
                const clientDoc = await resolveOAuthClient(database, tokenClientId);
                if (!clientDoc || clientDoc.disabled) {
                    return c.json({ active: false }, 200);
                }
            }

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

                    const database = await getDb();
                    // Check client validity
                    if (tokenClientId) {
                        const clientDoc = await resolveOAuthClient(database, tokenClientId);
                        if (!clientDoc || clientDoc.disabled) {
                            return c.json({ active: false }, 200);
                        }
                    }

                    // Check active state in database (revocation check)
                    const tokenDoc = await database.collection("oauthAccessToken").findOne({
                        token,
                        clientId: tokenClientId,
                    });
                    if (!tokenDoc) {
                        return c.json({ active: false }, 200);
                    }

                    const activeFamilyId = (tokenDoc as any)?.familyId || (payload as any)?.family_id;
                    if (activeFamilyId) {
                        const fam = await database.collection("oauth_token_families").findOne({
                            familyId: String(activeFamilyId),
                            ...(tokenClientId ? { clientId: tokenClientId } : {}),
                        });
                        if (!fam || fam.status === "revoked") {
                            return c.json({ active: false }, 200);
                        }
                    }

                    // Immutable subject ownership: query ONLY by immutable subject ID
                    const userId = String(payload.sub || tokenDoc.userId || "");
                    const orConditions: any[] = [{ id: userId }];
                    if (ObjectId.isValid(userId) && userId.length === 24) {
                        orConditions.push({ _id: new ObjectId(userId) });
                    }
                    const userDoc = await database.collection("user").findOne({
                        $or: orConditions,
                    });

                    const tokenIssuedAtMs = typeof payload.iat_ms === "number"
                        ? payload.iat_ms
                        : (typeof payload.iat === "number" ? payload.iat * 1000 : undefined);
                    const tokenVersion = typeof payload.token_version === "number" ? payload.token_version : undefined;
                    const eligibility = checkAccountEligibility(userDoc, {
                        tokenIssuedAtMs,
                        tokenIssuedAtSec: payload.iat,
                        tokenVersion,
                    });
                    if (!eligibility.eligible) {
                        return c.json({ active: false }, 200);
                    }

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
            const canonicalClientId = clientDoc.clientId;
            const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

            if (!hasAccess) {
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
                const canonicalClientId = clientDoc.clientId;
                const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

                if (!hasAccess) {
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
[
    { path: "/oauth2/register", description: "Dynamic client registration is disabled" },
    { path: "/oauth2/register/*", description: "Dynamic client registration is disabled" },
    { path: "/oauth2/create-client", description: "Direct client creation is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/update-client", description: "Direct client update is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/delete-client", description: "Direct client deletion is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/get-client", description: "Direct client lookup is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/get-clients", description: "Direct client lookup is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/public-client", description: "Direct public client lookup is forbidden." },
    { path: "/oauth2/public-client-prelogin", description: "Direct public client lookup is forbidden." },
    { path: "/oauth2/client/rotate-secret", description: "Direct secret rotation is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/client/*", description: "Direct client management is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/clients/*", description: "Direct client management is forbidden. Use /api/admin/clients." },
].forEach(({ path, description }) => {
    auth.all(path, (c) =>
        c.json({ error: "access_denied", error_description: description }, 403)
    );
});

// 9. Authoritative Super-Admin Gate for Better-Auth Internal Admin Routes (Slice 3)
auth.use("/admin", requireSuperAdmin);
auth.use("/admin/*", requireSuperAdmin);
auth.use("/admin/*", async (c, next) => {
    const method = c.req.method.toUpperCase();
    if (method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE") {
        return requireRecentMfa(c, next);
    }
    return next();
});

// Privacy projection for Better Auth admin list-users (Slice 2)
auth.all("/admin/list-users", async (c) => {
    const res = await authProvider.handler(c.req.raw);
    if (res.status === 200) {
        try {
            const data = await res.clone().json();
            if (data && Array.isArray(data.users)) {
                data.users = data.users.map((u: any) => ({
                    ...u,
                    displayLabel: toApprovedDisplayLabel(u.email, u.name),
                    email: toApprovedDisplayLabel(u.email),
                    name: isEmailShaped(u.name) ? toApprovedDisplayLabel(u.name) : (u.name || "User"),
                }));
                return c.json(data, 200);
            }
        } catch {}
    }
    return res;
});

// OAuth 2.1 Token Revocation (RFC 7009) with authenticated client and family scoping
auth.post("/oauth2/revoke", async (c) => {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);
    const token = params.get("token");

    // 1. Forward request to Better Auth for client authentication and provider handling
    const res = await authProvider.handler(c.req.raw);

    // CRITICAL: Provider authentication failure MUST cause zero revocation mutations
    if (res.status === 401) {
        return res;
    }

    if (!token) {
        return res;
    }

    if (token) {
        try {
            const authHeader = c.req.header("authorization");
            let basicClientId: string | null = null;
            if (authHeader && authHeader.toLowerCase().startsWith("basic ")) {
                try {
                    const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
                    const colonIndex = decoded.indexOf(":");
                    if (colonIndex !== -1) {
                        basicClientId = decoded.slice(0, colonIndex);
                    }
                } catch {}
            }
            const bodyClientId = params.get("client_id");
            const rawClientId = basicClientId || bodyClientId;

            if (!rawClientId) {
                return res;
            }

            const database = await getDb();
            const clientDoc = await resolveOAuthClient(database, rawClientId);
            if (!clientDoc || clientDoc.disabled) {
                return res;
            }

            const canonicalClientId = clientDoc.clientId;
            const { hashToken } = await import("../utils/security");
            const tokenHex = hashToken(token, "hex");
            const tokenBase64 = hashToken(token, "base64url");
            const now = new Date();

            // 1. Look up if token was a refresh token in families scoped strictly to authenticated client
            const familyDoc = await database.collection("oauth_token_families").findOne({
                clientId: canonicalClientId,
                $or: [
                    { activeTokenHash: tokenHex },
                    { activeTokenHash: tokenBase64 },
                    { consumedTokenHashes: tokenHex },
                    { consumedTokenHashes: tokenBase64 },
                ],
            });

            if (familyDoc) {
                // Targeted client-scoped family revocation: revokes only this family for this client
                await database.collection("oauth_token_families").updateOne(
                    { familyId: familyDoc.familyId, clientId: canonicalClientId },
                    { $set: { status: "revoked", revokedAt: now, rotating: false } }
                );

                const familyHashes = [
                    familyDoc.activeTokenHash,
                    ...(Array.isArray(familyDoc.consumedTokenHashes) ? familyDoc.consumedTokenHashes : []),
                ].filter(Boolean);

                await Promise.all([
                    database.collection("oauthAccessToken").deleteMany({
                        clientId: canonicalClientId,
                        familyId: familyDoc.familyId,
                    }),
                    database.collection("oauthRefreshToken").deleteMany({
                        clientId: canonicalClientId,
                        $or: [
                            { familyId: familyDoc.familyId },
                            { token: token },
                            { token: tokenBase64 },
                            { token: tokenHex },
                            ...(familyHashes.length > 0 ? [{ token: { $in: familyHashes } }] : []),
                        ],
                    }),
                ]);
            } else {
                // 2. Look up in oauthAccessToken scoped strictly to authenticated client
                const accDoc = await database.collection("oauthAccessToken").findOne({
                    clientId: canonicalClientId,
                    $or: [{ token }, { token: tokenBase64 }, { token: tokenHex }],
                });
                if (accDoc) {
                    if (accDoc.familyId) {
                        await database.collection("oauth_token_families").updateOne(
                            { familyId: accDoc.familyId, clientId: canonicalClientId },
                            { $set: { status: "revoked", revokedAt: now, rotating: false } }
                        );
                        await Promise.all([
                            database.collection("oauthAccessToken").deleteMany({
                                clientId: canonicalClientId,
                                familyId: accDoc.familyId,
                            }),
                            database.collection("oauthRefreshToken").deleteMany({
                                clientId: canonicalClientId,
                                familyId: accDoc.familyId,
                            }),
                        ]);
                    } else {
                        await database.collection("oauthAccessToken").deleteOne({ _id: accDoc._id });
                    }
                } else {
                    // 3. Look up in oauthRefreshToken scoped strictly to authenticated client
                    const refDoc = await database.collection("oauthRefreshToken").findOne({
                        clientId: canonicalClientId,
                        $or: [{ token }, { token: tokenBase64 }, { token: tokenHex }],
                    });
                    if (refDoc) {
                        if (refDoc.familyId) {
                            await database.collection("oauth_token_families").updateOne(
                                { familyId: refDoc.familyId, clientId: canonicalClientId },
                                { $set: { status: "revoked", revokedAt: now, rotating: false } }
                            );
                            await Promise.all([
                                database.collection("oauthAccessToken").deleteMany({
                                    clientId: canonicalClientId,
                                    familyId: refDoc.familyId,
                                }),
                                database.collection("oauthRefreshToken").deleteMany({
                                    clientId: canonicalClientId,
                                    $or: [
                                        { familyId: refDoc.familyId },
                                        { token: refDoc.token },
                                    ],
                                }),
                            ]);
                        } else {
                            await database.collection("oauthRefreshToken").deleteOne({ _id: refDoc._id });
                        }
                    }
                }
            }
        } catch (err) {
            console.error("[REVOCATION] Error during client scoped token revocation hook:", err);
        }
    }

    return c.json({}, 200);
});

// Wire tokenVersion through Better Auth admin revocation mutations
const adminRevocationRoutes = [
    "/admin/ban-user",
    "/admin/revoke-user-sessions",
    "/admin/set-password",
    "/admin/remove-user",
];

adminRevocationRoutes.forEach((routePath) => {
    auth.post(routePath, async (c) => {
        const body = await c.req.raw.clone().json().catch(() => ({}));
        const targetUserId = body.userId || body.id;
        const res = await authProvider.handler(c.req.raw);
        if (res.status < 400 && targetUserId) {
            try {
                const database = await getDb();
                await revokeUserTokensDurable(database, String(targetUserId));
            } catch (err) {
                console.error(`[ADMIN_REVOCATION] Error syncing durable revocation for ${routePath}:`, err);
            }
        }
        return res;
    });
});

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
                    const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

                    if (!hasAccess) {
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


// 12. Validated Two Factor OAuth Continuation Helpers & Telemetry Handlers
interface ValidatedMfaOauthContext {
    transactionId: string;
    clientId: string;
    clientName: string | null;
    boundUserId?: string | null;
}

async function resolveValidatedMfaOauthContext(c: any): Promise<ValidatedMfaOauthContext | null> {
    const txIdCookie = getCookie(c, "oauth_transaction_id");
    const txIdQuery = c.req.query("transaction_id");
    const stateQuery = c.req.query("state");
    const queryClientId = c.req.query("client_id");

    const candidateTxId = txIdCookie || txIdQuery;
    if (!candidateTxId && !stateQuery) {
        // No server side OAuth continuation context present (e.g. standalone MFA flow)
        return null;
    }

    try {
        const tx = await getOAuthTransaction({
            transactionId: candidateTxId || undefined,
            state: stateQuery || undefined,
        });

        if (!tx || tx.status !== "pending") {
            return null;
        }

        // Context integrity: if client_id was supplied as a query hint, it must strictly match the server transaction!
        // Tampered or conflicting hints must fail closed.
        if (queryClientId && queryClientId !== tx.clientId) {
            console.warn(`[MFA_OAUTH] Conflicting client_id in query hint: expected ${tx.clientId}, got ${queryClientId}`);
            return null;
        }

        // Revalidate target client existence and active status
        const database = await getDb();
        const clientDoc = await database.collection("oauthClient").findOne({ clientId: tx.clientId });
        if (!clientDoc || clientDoc.disabled === true) {
            return null;
        }

        const clientName = clientDoc.clientName || clientDoc.client_name || clientDoc.name || null;

        return {
            transactionId: tx.transactionId,
            clientId: tx.clientId,
            clientName,
            boundUserId: tx.userId || null,
        };
    } catch {
        return null;
    }
}

async function resolveCandidateMfaUser(c: any): Promise<{ id: string | null; email: string | null } | null> {
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            return {
                id: (sessionResult.user.id || (sessionResult.user as any)._id)?.toString() || null,
                email: sessionResult.user.email || null,
            };
        }
    } catch {
        // no active session
    }

    try {
        const twoFactorCookie = getCookie(c, "better-auth.two_factor");
        if (twoFactorCookie) {
            const database = await getDb();
            const parts = twoFactorCookie.split(".");
            const tokenVal = parts[0];
            const record = await database.collection("verification").findOne({
                $or: [
                    { identifier: twoFactorCookie },
                    { identifier: tokenVal },
                    { value: twoFactorCookie },
                    { value: tokenVal },
                ],
            });
            if (record?.value) {
                const candidateUserId = record.value;
                const userConditions: any[] = [{ id: candidateUserId }, { _id: candidateUserId }];
                if (ObjectId.isValid(candidateUserId)) {
                    userConditions.push({ _id: new ObjectId(candidateUserId) });
                }
                const u = await database.collection("user").findOne({
                    $or: userConditions,
                });
                if (u) {
                    return {
                        id: (u.id || u._id)?.toString() || null,
                        email: u.email || null,
                    };
                }
            }
        }
    } catch {
        // ignore
    }

    return null;
}

async function recordMfaPublicAppMembership(
    database: any,
    completedUserId: string,
    validatedContext: ValidatedMfaOauthContext | null
): Promise<void> {
    if (!completedUserId || !validatedContext) {
        // Standalone MFA or unvalidated context: never create application membership
        return;
    }

    // Identity binding: completed identity must match the validated OAuth continuation binding.
    // Missing or mismatched identity binding cannot create membership.
    if (!validatedContext.boundUserId || validatedContext.boundUserId !== completedUserId) {
        console.warn(`[MFA_OAUTH] Identity binding mismatch or missing: bound ${validatedContext.boundUserId} vs completed ${completedUserId}`);
        return;
    }

    // Retrieve user document to verify existence and check super admin isolation
    const userConditions: any[] = [{ id: completedUserId }, { _id: completedUserId }];
    if (ObjectId.isValid(completedUserId)) {
        userConditions.push({ _id: new ObjectId(completedUserId) });
    }
    const userDoc = await database.collection("user").findOne({
        $or: userConditions,
    });
    if (!userDoc) {
        return;
    }

    // Super Admin Isolation: super admins are not regular consumer app members
    if (isSuperAdmin(userDoc)) {
        return;
    }

    // Client verification: must exist, be active (not disabled), and be a public client
    const clientDoc = await database.collection("oauthClient").findOne({ clientId: validatedContext.clientId });
    if (!clientDoc || clientDoc.disabled === true || !clientDoc.isPublic) {
        // Private clients require explicit provisioning; disabled clients receive no new registrations
        return;
    }

    const canonicalClientId = clientDoc.clientId;
    await database.collection("user_app_registrations").updateOne(
        { userId: completedUserId, clientId: canonicalClientId },
        { $setOnInsert: { userId: completedUserId, clientId: canonicalClientId, registeredAt: new Date() } },
        { upsert: true }
    );

    // Bind completed user identity to pending OAuth transaction for downstream authorization continuity
    await database.collection("oauth_transactions").updateOne(
        { transactionId: validatedContext.transactionId, status: "pending" },
        { $set: { userId: completedUserId } }
    );
}

interface VerifiedMfaSession {
    sessionId: string | null;
    completedUserId: string | null;
    actor: string | null;
}

async function resolveVerifiedMfaSession(res: Response): Promise<VerifiedMfaSession> {
    if (res.status >= 400) {
        return { sessionId: null, completedUserId: null, actor: null };
    }

    try {
        const setCookie = res.headers.get("set-cookie") || "";
        const match = setCookie.match(/better-auth\.session_token=([^;]+)/);
        if (match) {
            const rawToken = decodeURIComponent(match[1]);
            const token = rawToken.split(".")[0];
            const database = await getDb();
            const sessionDoc = await database.collection("session").findOne({ token });
            if (sessionDoc && sessionDoc.userId) {
                const sessionId = String(sessionDoc._id || sessionDoc.id);
                const completedUserId = sessionDoc.userId.toString();
                // Authoritative MFA session marking for administrative & OAuth continuation
                await database.collection("session").updateOne(
                    { _id: sessionDoc._id },
                    { $set: { twoFactorVerified: true, mfaVerifiedAt: new Date() } }
                ).catch(() => {});
                let actor: string | null = null;
                const u = await database.collection("user").findOne({
                    $or: [{ id: completedUserId }, { _id: completedUserId }],
                });
                if (u?.email) {
                    actor = u.email;
                }
                return { sessionId, completedUserId, actor };
            }
        }
    } catch {
        // ignore
    }

    return { sessionId: null, completedUserId: null, actor: null };
}

auth.post("/two-factor/verify-totp", async (c) => {
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
});

auth.post("/two-factor/verify-backup-code", async (c) => {
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
});

// Catch-all delegate to Better Auth
auth.all("/*", async (c) => {
    return authProvider.handler(c.req.raw);
});

export default auth;
