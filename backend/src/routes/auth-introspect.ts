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
        let hasBasicAuth = false;
        if (authHeader && authHeader.toLowerCase().startsWith("basic ")) {
            try {
                const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
                const colonIndex = decoded.indexOf(":");
                if (colonIndex !== -1) {
                    basicClientId = decoded.slice(0, colonIndex);
                    hasBasicAuth = true;
                }
            } catch {}
        }
        const callerClientId = basicClientId || params.get("client_id");
        if (callerClientId) {
            const database = await getDb();
            const callerDoc = await resolveOAuthClient(database, callerClientId);
            if (callerDoc?.isAmbiguous) {
                const headers = hasBasicAuth ? { "WWW-Authenticate": 'Basic realm="OAuth"' } : undefined;
                return c.json({ error: "invalid_client", error_description: "Calling client configuration is ambiguous" }, 401, headers);
            }
        }

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

                    // RFC 7662 Section 4: Anti-scanning & Cross-client token isolation
                    const tokenClientId = (payload.client_id as string) || (payload.azp as string) || (payload.aud as string);
                    if (authClientId && tokenClientId && tokenClientId !== authClientId) {
                        return c.json({ active: false }, 200);
                    }

                    const database = await getDb();
                    // Check client validity
                    if (tokenClientId) {
                        const clientDoc = await resolveOAuthClient(database, tokenClientId);
                        if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                            return c.json({ active: false }, 200);
                        }
                        const hasAccess = await checkPrivateAppTokenAccess(database, payload.sub, clientDoc);
                        if (!hasAccess) {
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
}
