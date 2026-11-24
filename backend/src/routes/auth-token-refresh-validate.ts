import { ObjectId } from "mongodb";
import { checkUserHasAppAccess } from "../utils/security";
import { checkAccountEligibility } from "../utils/account-eligibility";

export interface RefreshValidationResult {
    valid: boolean;
    errorResponse?: { error: string; error_description: string; status: number };
    userDoc?: any;
}

/**
 * Validates pre-refresh eligibility and private app access for the incoming refresh token.
 */
export async function validatePreRefreshEligibility(
    database: any,
    canonicalClientId: string,
    clientDoc: any,
    preRefreshUserId: string,
    preRefreshIssuedAtMs?: number,
    preRefreshIssuedAtSec?: number,
    preRefreshTokenVersion?: number
): Promise<RefreshValidationResult> {
    const userDoc = await database.collection("user").findOne({
        $or: [
            { id: preRefreshUserId },
            ...(ObjectId.isValid(preRefreshUserId) && preRefreshUserId.length === 24 ? [{ _id: new ObjectId(preRefreshUserId) }] : []),
        ],
    });

    const eligibility = checkAccountEligibility(userDoc, {
        tokenIssuedAtMs: preRefreshIssuedAtMs,
        tokenIssuedAtSec: preRefreshIssuedAtSec ?? Math.floor(Date.now() / 1000),
        tokenVersion: preRefreshTokenVersion,
    });

    if (!eligibility.eligible) {
        await Promise.all([
            database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
            database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: preRefreshUserId }),
            database.collection("oauth_token_families").updateMany(
                { clientId: canonicalClientId, userId: preRefreshUserId },
                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
            ),
        ]);
        return {
            valid: false,
            errorResponse: {
                error: "invalid_grant",
                error_description: `User account is not eligible for token refresh: ${eligibility.reason}`,
                status: 401,
            },
        };
    }

    const isPrivatePre = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
    if (isPrivatePre) {
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
            return {
                valid: false,
                errorResponse: {
                    error: "invalid_grant",
                    error_description: "User is no longer authorized for this private application",
                    status: 401,
                },
            };
        }
    }

    return { valid: true, userDoc };
}

/**
 * Validates post-refresh eligibility and private app access for the resolved user.
 */
export async function validatePostRefreshEligibility(
    database: any,
    canonicalClientId: string,
    clientDoc: any,
    resolvedUserId: string,
    preRefreshIssuedAtMs?: number,
    preRefreshIssuedAtSec?: number,
    preRefreshTokenVersion?: number
): Promise<RefreshValidationResult> {
    const userDoc = await database.collection("user").findOne({
        $or: [
            { id: resolvedUserId },
            ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
        ],
    });

    const eligibility = checkAccountEligibility(userDoc, {
        tokenIssuedAtMs: preRefreshIssuedAtMs,
        tokenIssuedAtSec: preRefreshIssuedAtSec ?? Math.floor(Date.now() / 1000),
        tokenVersion: preRefreshTokenVersion,
    });

    if (!eligibility.eligible) {
        await Promise.all([
            database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
            database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId, userId: resolvedUserId }),
            database.collection("oauth_token_families").updateMany(
                { clientId: canonicalClientId, userId: resolvedUserId },
                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
            ),
        ]);
        return {
            valid: false,
            errorResponse: {
                error: "invalid_grant",
                error_description: `User account is not eligible for token refresh: ${eligibility.reason}`,
                status: 401,
            },
        };
    }

    const isPrivatePost = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
    if (isPrivatePost) {
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
            return {
                valid: false,
                errorResponse: {
                    error: "invalid_grant",
                    error_description: "User is no longer authorized for this private application",
                    status: 401,
                },
            };
        }
    }

    return { valid: true, userDoc };
}
