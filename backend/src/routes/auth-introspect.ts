import { ObjectId } from "mongodb";
import { decodeProtectedHeader, jwtVerify } from "jose";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { getIdpPublicKey } from "../middleware/admin-auth";
import { checkAccountEligibility } from "../utils/account-eligibility";
import { resolveOAuthClient, checkPrivateAppTokenAccess } from "../utils/security";
import { resolveUserRoleForClient } from "./auth-keys";

export async function handleOAuthIntrospect(c: any): Promise<Response> {
    try {
        const rawBodyText = await c.req.raw.clone().text().catch(() => "");
        const params = new URLSearchParams(rawBodyText);
        const token = params.get("token") || c.req.query("token") || "";

        // Verify calling client is not ambiguous
        const authHeader = c.req.header("authorization") || c.req.header("Authorization");
        let basicClientId: string | null = null;
        let basicClientSecret: string | null = null;
        let hasBasicAuth = false;
        if (authHeader && authHeader.toLowerCase().startsWith("basic ")) {
            try {
                const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
                const colonIndex = decoded.indexOf(":");
                if (colonIndex !== -1) {
                    basicClientId = decoded.slice(0, colonIndex);
                    basicClientSecret = decoded.slice(colonIndex + 1);
                    hasBasicAuth = true;
                }
            } catch {}
        }
        const bodyClientId = params.get("client_id");
        const bodyClientSecret = params.get("client_secret");

        // Reject multiple or conflicting credentials
        if (hasBasicAuth && bodyClientSecret) {
            return c.json({ error: "invalid_client", error_description: "Multiple client credentials submitted" }, 400);
        }
        if (hasBasicAuth && bodyClientId && bodyClientId !== basicClientId) {
            return c.json({ error: "invalid_client", error_description: "Conflicting client identifiers" }, 400);
        }

        const callerClientId = basicClientId || bodyClientId;
        const callerSecret = hasBasicAuth ? basicClientSecret : bodyClientSecret;

        if (callerClientId) {
            const database = await getDb();
            const callerDoc = await resolveOAuthClient(database, callerClientId);
            if (callerDoc?.isAmbiguous) {
                const headers = hasBasicAuth ? { "WWW-Authenticate": 'Basic realm="OAuth"' } : undefined;
                return c.json({ error: "invalid_client", error_description: "Calling client configuration is ambiguous" }, 401, headers);
            }
            if (callerDoc?.disabled) {
                return c.json({ error: "invalid_client", error_description: "Calling client is disabled" }, 401);
            }
        }

        // Determine if token is a custom RS256 JWT issued by SWYRA Auth
        const isCustomJwt = typeof token === "string" && token.includes(".");

        let res: Response;
        if (isCustomJwt) {
            // Establish caller authentication through supported engine mechanism using sentinel token probe
            const probeParams = new URLSearchParams(params);
            probeParams.set("token", "swyra_credential_probe_sentinel");
            const probeReq = new Request(c.req.raw.url, {
                method: "POST",
                headers: c.req.raw.headers,
                body: probeParams.toString(),
            });
            res = await authProvider.handler(probeReq);
        } else {
            // Forward raw request to engine for opaque / engine-managed tokens
            res = await authProvider.handler(c.req.raw);
        }

        // Preserve engine authentication failures (including body secret HTTP 400 and Basic 401)
        if (res.status === 401 || res.status === 400) {
            return res;
        }

        // Engine errors and outages must never become active:true responses
        if (res.status >= 500) {
            return c.json({ error: "server_error", error_description: "Authentication engine failure" }, res.status);
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
                if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                    return c.json({ active: false }, 200);
                }
                const hasAccess = await checkPrivateAppTokenAccess(database, tokenSub, clientDoc);
                if (!hasAccess) {
                    return c.json({ active: false }, 200);
                }
            }

            return res;
        }

        // JWT fallback for SWYRA Auth RS256 access tokens
        // Caller authentication was already proven by the engine returning HTTP 200 on the probe
        if (isCustomJwt) {
            if (!callerClientId) {
                return c.json({ error: "invalid_client", error_description: "Missing required client credentials" }, 401);
            }
            const database = await getDb();
            const callerDoc = await resolveOAuthClient(database, callerClientId);
            if (!callerDoc || callerDoc.disabled || callerDoc.isAmbiguous) {
                return c.json({ error: "invalid_client", error_description: "Calling client not found, disabled, or ambiguous" }, 401);
            }

            let kid: string | undefined;
            try {
                const header = decodeProtectedHeader(token);
                kid = header.kid;
            } catch {}
            const publicKey = await getIdpPublicKey(kid);
            if (!publicKey) {
                return c.json({ active: false }, 200);
            }

            try {
                const { payload } = await jwtVerify(token, publicKey, {
                    algorithms: ["RS256"],
                    issuer: config.auth.baseURL,
                });

                const nowSec = Math.floor(Date.now() / 1000);
                if (payload.exp && payload.exp <= nowSec) {
                    return c.json({ active: false }, 200);
                }

                // RFC 7662 Section 4: Anti-scanning & Cross-client token isolation
                const authClientId = callerDoc.clientId;
                const tokenClientId = (payload.client_id as string) || (payload.azp as string) || (payload.aud as string);
                if (authClientId && tokenClientId && tokenClientId !== authClientId) {
                    return c.json({ active: false }, 200);
                }

                // Check client validity
                const clientDoc = tokenClientId ? await resolveOAuthClient(database, tokenClientId) : null;
                if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                    return c.json({ active: false }, 200);
                }
                const hasAccess = await checkPrivateAppTokenAccess(database, payload.sub, clientDoc);
                if (!hasAccess) {
                    return c.json({ active: false }, 200);
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
            } catch {
                return c.json({ active: false }, 200);
            }
        }

        return res;
    } catch (err) {
        console.error("[INTROSPECT_ERR]", err);
        return c.json({ active: false }, 200);
    }
}
