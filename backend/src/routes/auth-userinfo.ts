import { ObjectId } from "mongodb";
import { decodeProtectedHeader, jwtVerify, decodeJwt } from "jose";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { getIdpPublicKey } from "../middleware/admin-auth";
import { checkAccountEligibilityWithLedger } from "../utils/account-eligibility";
import { hashToken, resolveOAuthClient, checkPrivateAppTokenAccess } from "../utils/security";
import { resolveUserRoleForClient } from "./auth-keys";
import { filterConsumerClaims } from "../identity/claim-policy";
import { AccountKeyAccessError, type AccountKeyProvider } from "../identity/account-key-provider";
import { ProtectedFieldError } from "../identity/protected-envelope";
import {
    resolveAuthorizedProtectedUserInfoClaims,
    type ProtectedProfileCollection,
} from "../identity/protected-profile-store";

export interface UserInfoRouteDeps {
    getDb?: () => Promise<any>;
    authHandler?: (req: Request) => Promise<Response>;
    resolveClient?: (database: any, clientId: string) => Promise<any>;
    checkPrivateAccess?: (database: any, userDoc: any, clientDoc: any) => Promise<boolean>;
    resolveRole?: (database: any, userDoc: any, clientId: string) => Promise<{ role: string; scopedClientId: string | null }>;
    protectedProfileStore?: ProtectedProfileCollection;
    accountKeyProvider?: AccountKeyProvider;
    migrationMode?: "compat" | "strict";
}

function mapProtectedUserInfoError(c: any, err: unknown): Response | null {
    if (err instanceof AccountKeyAccessError) {
        const status = err.code === "provider_outage" ? 503 : 403;
        return c.json({ error: err.code, error_description: err.message }, status);
    }
    if (err instanceof ProtectedFieldError) {
        return c.json({ error: err.code, error_description: err.message }, err.code === "profile_not_found" ? 404 : 500);
    }
    return null;
}

export function createOAuthUserInfoHandler(deps: UserInfoRouteDeps = {}) {
    return (c: any) => runOAuthUserInfo(c, deps);
}

export async function handleOAuthUserInfo(c: any): Promise<Response> {
    return runOAuthUserInfo(c, {});
}

async function runOAuthUserInfo(c: any, deps: UserInfoRouteDeps): Promise<Response> {
    try {
        const authHeader = c.req.header("authorization") || c.req.header("Authorization");
        const bearerToken = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

        let res = await (deps.authHandler ?? ((req: Request) => authProvider.handler(req)))(c.req.raw);

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
                        const database = await (deps.getDb ?? getDb)();
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
                        const eligibility = await checkAccountEligibilityWithLedger(database, userDoc, {
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

                        const queryClientId = c.req.query("client_id");
                        if (queryClientId && queryClientId !== targetClientId) {
                            return c.json(
                                { error: "invalid_request", error_description: "Query client_id does not match authenticated token client" },
                                400
                            );
                        }

                        if (!targetClientId) {
                            return c.json(
                                { error: "invalid_token", error_description: "Token is missing required client audience" },
                                401,
                                { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token is missing required client audience"' }
                            );
                        }

                        const clientDoc = await (deps.resolveClient ?? resolveOAuthClient)(database, targetClientId);
                        if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                            return c.json(
                                { error: "invalid_client", error_description: "Target client is disabled, ambiguous, or not found" },
                                401
                            );
                        }

                        const hasAccess = await (deps.checkPrivateAccess ?? checkPrivateAppTokenAccess)(database, userDoc, clientDoc);
                        if (!hasAccess) {
                            return c.json(
                                { error: "forbidden", error_description: "User is not an authorized member of this private application" },
                                403
                            );
                        }

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

                        const resolved = await (deps.resolveRole ?? resolveUserRoleForClient)(database, userDoc, targetClientId);

                        // Scope and Privacy Enforcement (Slice 2)
                        const scopes = ((payload.scope as string) || "openid").split(" ").map(s => s.trim().toLowerCase());
                        const scopeSet = new Set(scopes);
                        let responsePayload: Record<string, any> = {
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

                        if (deps.protectedProfileStore && deps.accountKeyProvider) {
                            try {
                                responsePayload = await resolveAuthorizedProtectedUserInfoClaims({
                                    store: deps.protectedProfileStore,
                                    provider: deps.accountKeyProvider,
                                    accountId: userId,
                                    migrationMode: deps.migrationMode ?? "compat",
                                    userDoc,
                                    scopes,
                                    claims: responsePayload,
                                });
                            } catch (err) {
                                const mapped = mapProtectedUserInfoError(c, err);
                                if (mapped) return mapped;
                                throw err;
                            }
                        }

                        return c.json(filterConsumerClaims(responsePayload, scopes, userDoc), 200);
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
                let data: any = null;
                try {
                    const text = await res.text();
                    data = JSON.parse(text);
                } catch {
                    return c.json(
                        { error: "invalid_token", error_description: "Invalid response from authorization server" },
                        401,
                        { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid response from authorization server"' }
                    );
                }

                if (!data || (!data.sub && !data.id)) {
                    return c.json(
                        { error: "invalid_token", error_description: "Invalid or unsupported access token" },
                        401,
                        { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid or unsupported access token"' }
                    );
                }

                const database = await (deps.getDb ?? getDb)();
                const userId = String(data.sub || data.id);
                const orConditions: any[] = [{ id: userId }];
                if (ObjectId.isValid(userId) && userId.length === 24) {
                    orConditions.push({ _id: new ObjectId(userId) });
                }
                const userDoc = await database.collection("user").findOne({
                    $or: orConditions
                });

                let accDoc: any = null;
                let tokenIssuedAtSec: number | undefined;
                let tokenIssuedAtMs: number | undefined;
                let tokenVersion: number | undefined;
                if (bearerToken) {
                    try {
                        accDoc = await database.collection("oauthAccessToken").findOne({
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
                }

                // Authoritative Account Eligibility Check
                const eligibility = await checkAccountEligibilityWithLedger(database, userDoc, {
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

                let targetClientId = (accDoc?.clientId || data.client_id || data.clientId || "") as string;
                if (!targetClientId && bearerToken) {
                    try {
                        const decoded: any = decodeJwt(bearerToken);
                        targetClientId = (decoded?.client_id || decoded?.azp || (typeof decoded?.aud === "string" ? decoded.aud : decoded?.aud?.[0]) || "") as string;
                    } catch {}
                }

                if (!targetClientId) {
                    return c.json(
                        { error: "invalid_token", error_description: "Token is missing required client audience" },
                        401,
                        { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token is missing required client audience"' }
                    );
                }

                const queryClientId = c.req.query("client_id");
                if (queryClientId && queryClientId !== targetClientId) {
                    return c.json(
                        { error: "invalid_request", error_description: "Query client_id does not match authenticated token client" },
                        400
                    );
                }

                const clientDoc = await (deps.resolveClient ?? resolveOAuthClient)(database, targetClientId);
                if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                    return c.json(
                        { error: "invalid_client", error_description: "Target client is disabled, ambiguous, or not found" },
                        401
                    );
                }

                const hasAccess = await (deps.checkPrivateAccess ?? checkPrivateAppTokenAccess)(database, userDoc, clientDoc);
                if (!hasAccess) {
                    return c.json(
                        { error: "forbidden", error_description: "User is not an authorized member of this private application" },
                        403
                    );
                }

                if (accDoc?.familyId) {
                    const familyDoc = await database.collection("oauth_token_families").findOne({
                        familyId: String(accDoc.familyId),
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

                const resolved = await (deps.resolveRole ?? resolveUserRoleForClient)(database, userDoc, targetClientId);
                data.role = resolved.role;
                data.scoped_client_id = resolved.scopedClientId;
                const opaqueScopes = accDoc?.scopes || accDoc?.scope || "openid";
                if (deps.protectedProfileStore && deps.accountKeyProvider) {
                    try {
                        data = await resolveAuthorizedProtectedUserInfoClaims({
                            store: deps.protectedProfileStore,
                            provider: deps.accountKeyProvider,
                            accountId: userId,
                            migrationMode: deps.migrationMode ?? "compat",
                            userDoc,
                            scopes: opaqueScopes,
                            claims: data,
                        });
                    } catch (err) {
                        const mapped = mapProtectedUserInfoError(c, err);
                        if (mapped) return mapped;
                        throw err;
                    }
                }
                return c.json(filterConsumerClaims(data, opaqueScopes, userDoc), 200);
            } catch (err) {
                console.error("[USERINFO_ERR]", err);
                return c.json(
                    { error: "invalid_token", error_description: "Failed to process userinfo request" },
                    401,
                    { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Failed to process userinfo request"' }
                );
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
