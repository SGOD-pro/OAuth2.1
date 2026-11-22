import crypto from "crypto";
import { ObjectId } from "mongodb";
import { generateKeyPair, exportJWK, importJWK } from "jose";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { isSuperAdmin } from "../middleware/admin-auth";
import { checkUserIsClientAdmin } from "../middleware/admin-auth";

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
    | "before_fence_refresh"
    | "after_lease_claim";

let tokenBarrierHookForTesting: ((stage: TokenBarrierStage, userId?: string) => Promise<void>) | null = null;
export function setTokenBarrierHookForTesting(hook: ((stage: TokenBarrierStage, userId?: string) => Promise<void>) | null): void {
    tokenBarrierHookForTesting = hook;
}

export function getTokenBarrierHookForTesting(): ((stage: TokenBarrierStage, userId?: string) => Promise<void>) | null {
    return tokenBarrierHookForTesting;
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
