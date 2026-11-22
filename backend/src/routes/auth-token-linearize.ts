import { ObjectId } from "mongodb";
import { hashToken } from "../utils/security";

/**
 * Resolves authenticated subject userId from ID token, access token JWT payload, or database tokens.
 */
export async function resolveTokenSubjectUserId(
    database: any,
    tokenData: any,
    fallbackUserId?: string
): Promise<string | undefined> {
    if (fallbackUserId) return fallbackUserId;

    if (tokenData?.id_token && typeof tokenData.id_token === "string") {
        const parts = tokenData.id_token.split(".");
        if (parts.length === 3) {
            try {
                const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                const sub = jwtPayload.sub || jwtPayload.userId;
                if (sub) return String(sub);
            } catch {}
        }
    }

    if (tokenData?.access_token && typeof tokenData.access_token === "string") {
        const parts = tokenData.access_token.split(".");
        if (parts.length === 3) {
            try {
                const jwtPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
                const sub = jwtPayload.sub || jwtPayload.userId;
                if (sub) return String(sub);
            } catch {}
        }
    }

    for (let attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 40 * attempt));
        if (tokenData?.refresh_token) {
            const refDoc = await database.collection("oauthRefreshToken").findOne({
                token: tokenData.refresh_token,
            });
            if (refDoc?.userId) return String(refDoc.userId);
        }
        if (tokenData?.access_token) {
            const accDoc = await database.collection("oauthAccessToken").findOne({
                token: tokenData.access_token,
            });
            if (accDoc?.userId) return String(accDoc.userId);
        }
    }

    return undefined;
}

/**
 * Exact Issuance/Revocation Linearization Point:
 * Durable Conditional State Transition coordinated with revocation.
 */
export async function commitTokenIssuanceLinearization(
    database: any,
    resolvedUserId: string,
    expectedTokenVersion: number,
    issuedAtMs?: number
): Promise<boolean> {
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
            ...(issuedAtMs ? [{
                $or: [
                    { tokensRevokedBefore: { $exists: false } },
                    { tokensRevokedBefore: null },
                    { tokensRevokedBefore: { $lte: new Date(issuedAtMs) } },
                ],
            }] : [{
                $or: [
                    { tokensRevokedBefore: { $exists: false } },
                    { tokensRevokedBefore: null },
                    { tokensRevokedBefore: { $lte: new Date() } },
                ],
            }]),
            ...(issuedAtMs ? [{
                $or: [
                    { passwordChangedAt: { $exists: false } },
                    { passwordChangedAt: null },
                    { passwordChangedAt: { $lte: new Date(issuedAtMs) } },
                ],
            }] : []),
        ],
    };

    const commitResult: any = await database.collection("user").findOneAndUpdate(
        commitCondition,
        {
            $set: {
                tokenVersion: expectedTokenVersion,
                lastTokenIssuedAt: new Date(),
            },
        },
        { returnDocument: "after" }
    );

    const updatedDoc = commitResult && (commitResult.value !== undefined ? commitResult.value : commitResult);
    return Boolean(updatedDoc);
}

/**
 * Purge newly minted tokens and token family state when access token signing fails.
 */
export async function purgeTokensOnMintFailure(
    database: any,
    tokenData: any,
    familyId?: string | null
): Promise<void> {
    const newRefreshStoredHash = tokenData.refresh_token ? hashToken(tokenData.refresh_token, "base64url") : null;
    const newAccessStoredHash = tokenData.access_token ? hashToken(tokenData.access_token, "base64url") : null;

    if (tokenData.refresh_token) {
        await database.collection("oauthRefreshToken").deleteMany({
            $or: [
                { token: tokenData.refresh_token },
                ...(newRefreshStoredHash ? [{ token: newRefreshStoredHash }] : []),
            ],
        }).catch(() => {});
        if (familyId) {
            await database.collection("oauth_token_families").deleteMany({ familyId }).catch(() => {});
        }
    }
    if (tokenData.access_token) {
        await database.collection("oauthAccessToken").deleteMany({
            $or: [
                { token: tokenData.access_token },
                ...(newAccessStoredHash ? [{ token: newAccessStoredHash }] : []),
            ],
        }).catch(() => {});
    }
}

/**
 * Purge tokens and revoke token family state when conditional linearization commit fails.
 */
export async function purgeTokensOnCommitFailure(
    database: any,
    canonicalClientId: string,
    resolvedUserId: string,
    jwtAt: string,
    tokenData: any,
    familyId?: string | null
): Promise<void> {
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
}
