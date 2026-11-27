import crypto from "crypto";
import { ObjectId } from "mongodb";
import { SignJWT } from "jose";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { toApprovedDisplayLabel, isEmailShaped } from "../utils/security";
import { checkAccountEligibilityWithLedger } from "../utils/account-eligibility";
import { getIdpSigningKey, resolveUserRoleForClient } from "./auth-keys";
import { AccountKeyAccessError, type AccountKeyProvider } from "../identity/account-key-provider";
import { filterConsumerClaims } from "../identity/claim-policy";
import { ProtectedFieldError } from "../identity/protected-envelope";
import {
    resolveAuthorizedProtectedUserInfoClaims,
    type ProtectedProfileCollection,
} from "../identity/protected-profile-store";

export interface ProtectedTokenClaimDeps {
    protectedProfileStore?: ProtectedProfileCollection;
    accountKeyProvider?: AccountKeyProvider;
    migrationMode?: "compat" | "strict";
    preResolvedProtectedClaims?: Record<string, any>;
}

export interface MintJwtDeps extends ProtectedTokenClaimDeps {
    getDb?: () => Promise<any>;
    getSigningKey?: typeof getIdpSigningKey;
    resolveRole?: (database: any, userDoc: any, clientId: string) => Promise<{ role: string; scopedClientId: string | null }>;
}

export interface TokenGrantDeps extends MintJwtDeps {
    authHandler?: (req: Request) => Promise<Response>;
}

export function mapProtectedTokenError(c: any, err: unknown): Response | null {
    if (err instanceof AccountKeyAccessError) {
        const status = err.code === "provider_outage" ? 503 : 403;
        return c.json({ error: err.code, error_description: err.message }, status);
    }
    if (err instanceof ProtectedFieldError) {
        return c.json({ error: err.code, error_description: err.message }, err.code === "profile_not_found" ? 404 : 500);
    }
    return null;
}

export function buildProtectedIdTokenClaimFilter(
    scopes: string | string[],
    userDoc: any,
    deps: ProtectedTokenClaimDeps = {}
): (payload: Record<string, any>) => Promise<Record<string, any>> {
    return async (payload: Record<string, any>) => {
        let next = { ...payload };
        if (deps.preResolvedProtectedClaims) {
            next = { ...next, ...deps.preResolvedProtectedClaims };
        } else if (deps.protectedProfileStore && deps.accountKeyProvider) {
            const accountId = String(userDoc?._id || userDoc?.id || payload.sub || "");
            next = await resolveAuthorizedProtectedUserInfoClaims({
                store: deps.protectedProfileStore,
                provider: deps.accountKeyProvider,
                accountId,
                migrationMode: deps.migrationMode ?? "compat",
                userDoc,
                scopes,
                claims: next,
            });
        }
        return filterConsumerClaims(next, scopes, userDoc);
    };
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
}, deps: MintJwtDeps = {}): Promise<string | null> {
    try {
        const signingKey = await (deps.getSigningKey ?? getIdpSigningKey)();
        if (!signingKey) return null;

        const database = await (deps.getDb ?? getDb)();
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

        const eligibility = await checkAccountEligibilityWithLedger(database, userDoc, {
            tokenIssuedAtMs,
            tokenIssuedAtSec,
            tokenVersion,
        });
        if (!eligibility.eligible) {
            console.warn(`[MINT_JWT_ACCESS_TOKEN] Denied token minting for ineligible account ${params.userId}: ${eligibility.reason}`);
            return null;
        }

        const { role, scopedClientId } = await (deps.resolveRole ?? resolveUserRoleForClient)(database, userDoc, params.clientId);

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

        let finalClaims = claims;
        if (deps.preResolvedProtectedClaims) {
            finalClaims = filterConsumerClaims({ ...finalClaims, ...deps.preResolvedProtectedClaims }, scopes, userDoc);
        } else if (deps.protectedProfileStore && deps.accountKeyProvider) {
            finalClaims = await resolveAuthorizedProtectedUserInfoClaims({
                store: deps.protectedProfileStore,
                provider: deps.accountKeyProvider,
                accountId: params.userId,
                migrationMode: deps.migrationMode ?? "compat",
                userDoc,
                scopes,
                claims: finalClaims,
            });
            finalClaims = filterConsumerClaims(finalClaims, scopes, userDoc);
        }

        const jwt = await new SignJWT(finalClaims)
            .setProtectedHeader({ alg: "RS256", kid: signingKey.kid })
            .setIssuedAt()
            .setIssuer(config.auth.baseURL)
            .setAudience(params.clientId)
            .setExpirationTime(`${ttl}s`)
            .setJti(crypto.randomUUID())
            .sign(signingKey.privateKey);

        return jwt;
    } catch (err) {
        if (err instanceof AccountKeyAccessError || err instanceof ProtectedFieldError) {
            throw err;
        }
        console.error("[MINT_JWT_ACCESS_TOKEN] Error minting JWT access token:", err);
        return null;
    }
}

export async function resignIdTokenWithNewAtHash(
    idToken: string,
    newAccessToken: string,
    claimFilter?: (payload: Record<string, any>) => Record<string, any> | Promise<Record<string, any>>,
    getSigningKeyFn: typeof getIdpSigningKey = getIdpSigningKey
): Promise<string> {
    if (!idToken || typeof idToken !== "string") return idToken;
    const parts = idToken.split(".");
    if (parts.length !== 3) return idToken;
    try {
        let idPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        if (claimFilter) {
            idPayload = await claimFilter(idPayload);
        }
        if (idPayload.at_hash) {
            const newAtHash = crypto
                .createHash("sha256")
                .update(newAccessToken)
                .digest()
                .subarray(0, 16)
                .toString("base64url");
            idPayload.at_hash = newAtHash;
        }
        const signingKey = await getSigningKeyFn();
        if (!signingKey) return idToken;
        return await new SignJWT(idPayload)
            .setProtectedHeader({ alg: "RS256", kid: signingKey.kid })
            .sign(signingKey.privateKey);
    } catch (e) {
        if (e instanceof AccountKeyAccessError || e instanceof ProtectedFieldError) {
            throw e;
        }
        console.error("[ID_TOKEN_RE_SIGN] Error updating at_hash:", e);
        return idToken;
    }
}
