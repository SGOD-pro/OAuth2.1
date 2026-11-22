import crypto from "crypto";
import { ObjectId } from "mongodb";
import { SignJWT } from "jose";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { toApprovedDisplayLabel, isEmailShaped } from "../utils/security";
import { checkAccountEligibility } from "../utils/account-eligibility";
import { getIdpSigningKey, resolveUserRoleForClient } from "./auth-keys";

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

export async function resignIdTokenWithNewAtHash(idToken: string, newAccessToken: string): Promise<string> {
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
