import { ObjectId } from "mongodb";
import { decodeProtectedHeader, jwtVerify, decodeJwt } from "jose";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { getIdpPublicKey } from "../middleware/admin-auth";
import { checkAccountEligibility } from "../utils/account-eligibility";
import { hashToken } from "../utils/security";
import { resolveUserRoleForClient } from "./auth-keys";

export async function handleOAuthUserInfo(c: any): Promise<Response> {
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
                        const accDoc = bearerToken
                            ? await database.collection("oauthAccessToken").findOne({
                                $or: [
                                    { token: bearerToken },
                                    { token: hashToken(bearerToken, "base64url") },
                                    { token: hashToken(bearerToken, "hex") },
                                ],
                            })
                            : null;
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
}
