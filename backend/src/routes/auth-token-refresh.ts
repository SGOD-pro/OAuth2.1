import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { hashToken } from "../utils/security";
import { verifyAndRotateTokenFamily } from "../db/state";
import { mintJwtAccessToken, resignIdTokenWithNewAtHash } from "./auth-jwt";
import { filterConsumerClaims } from "../identity/claim-policy";
import { getTokenBarrierHookForTesting } from "./auth-keys";
import { claimRotationRights } from "./auth-token-claim";
import { AuthenticatedClientContext } from "./auth-token-auth";
import {
    resolveTokenSubjectUserId, commitTokenIssuanceLinearization,
    purgeTokensOnMintFailure, purgeTokensOnCommitFailure, buildClientIssuanceFence,
} from "./auth-token-linearize";
import {
    validatePreRefreshEligibility,
    validatePostRefreshEligibility,
} from "./auth-token-refresh-validate";

async function releaseRotationLock(
    database: any,
    activeTokenHash: string,
    clientId: string,
    leaseOwner?: string
): Promise<void> {
    const filter: Record<string, any> = { activeTokenHash, clientId, rotating: true };
    if (leaseOwner) filter.rotationOwner = leaseOwner;
    await database.collection("oauth_token_families").updateOne(
        filter,
        { $set: { rotating: false }, $unset: { rotationOwner: "" } }
    ).catch(() => {});
}

/**
 * Handle refresh_token grant exchange.
 * Enforces atomic rotation locks, replay detection, eligibility gates,
 * RS256 token minting, and conditional issuance linearization.
 */
export async function handleRefreshTokenGrant(
    c: any,
    clientContext: AuthenticatedClientContext,
    refreshToken: string
): Promise<Response> {
    const { canonicalClientId, clientDoc, reqToForward } = clientContext;
    const clientFence = buildClientIssuanceFence(canonicalClientId, clientDoc);
    const database = await getDb();
    const incomingHash = hashToken(refreshToken, "hex");

    const claimResult = await claimRotationRights(c, database, canonicalClientId, clientDoc, incomingHash);
    if (!claimResult.claimed) {
        return claimResult.response;
    }
    const { existingFamily, leaseOwner } = claimResult;

    try {
        const tokenBarrierHook = getTokenBarrierHookForTesting();
        if (tokenBarrierHook) {
            await tokenBarrierHook("after_lease_claim", leaseOwner);
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
                        { token: hashToken(refreshToken, "hex") },
                    ],
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

        if (preRefreshUserId) {
            const preCheck = await validatePreRefreshEligibility(
                database,
                canonicalClientId,
                clientDoc,
                preRefreshUserId,
                preRefreshIssuedAtMs,
                preRefreshIssuedAtSec,
                preRefreshTokenVersion
            );
            if (!preCheck.valid && preCheck.errorResponse) {
                await releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner);
                return c.json(
                    {
                        error: preCheck.errorResponse.error,
                        error_description: preCheck.errorResponse.error_description,
                    },
                    preCheck.errorResponse.status
                );
            }
        }

        let res: Response;
        try {
            res = await authProvider.handler(reqToForward);
        } catch (handlerErr) {
            await releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner);
            throw handlerErr;
        }

        if (res.status === 200) {
            const tokenData = await res.clone().json().catch(() => null);
            if (tokenData && tokenData.refresh_token) {
                let resolvedUserId: string | undefined = await resolveTokenSubjectUserId(database, tokenData, preRefreshUserId);
                let userDoc: any = null;

                if (resolvedUserId) {
                    const postCheck = await validatePostRefreshEligibility(
                        database,
                        canonicalClientId,
                        clientDoc,
                        resolvedUserId,
                        preRefreshIssuedAtMs,
                        preRefreshIssuedAtSec,
                        preRefreshTokenVersion
                    );
                    if (!postCheck.valid && postCheck.errorResponse) {
                        await releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner);
                        return c.json(
                            {
                                error: postCheck.errorResponse.error,
                                error_description: postCheck.errorResponse.error_description,
                            },
                            postCheck.errorResponse.status
                        );
                    }
                    userDoc = postCheck.userDoc;
                }

                const newHash = hashToken(tokenData.refresh_token, "hex");
                const rotationResult = await verifyAndRotateTokenFamily(
                    incomingHash,
                    newHash,
                    resolvedUserId,
                    Date.now(),
                    canonicalClientId,
                    preRefreshTokenVersion,
                    leaseOwner
                );

                if (rotationResult.replayed) {
                    return c.json({
                        error: "invalid_grant",
                        error_description: "Refresh token has been revoked due to replay detection",
                    }, 401);
                }

                if (!rotationResult.valid) {
                    await purgeTokensOnMintFailure(database, tokenData, null);
                    return c.json({
                        error: "invalid_grant",
                        error_description: "Refresh token was already consumed or is invalid",
                    }, 400);
                }

                if (tokenData && tokenData.access_token) {
                    if (!resolvedUserId) {
                        console.error("[TOKEN_MINTING] Missing resolvedUserId in refresh_token flow; failing closed without opaque fallback");
                        await purgeTokensOnMintFailure(database, tokenData, null);
                        if (rotationResult.familyId) {
                            await database.collection("oauth_token_families").updateOne(
                                { familyId: rotationResult.familyId, activeTokenHash: newHash },
                                { $set: { status: "revoked", revokedAt: new Date(), rotating: false } }
                            ).catch(() => {});
                        }
                        return c.json({
                            error: "server_error",
                            error_description: "Failed to resolve authenticated user identity for token minting",
                        }, 500);
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
                        await purgeTokensOnMintFailure(database, tokenData, null);
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

                    const tokenBarrierHook = getTokenBarrierHookForTesting();
                    if (tokenBarrierHook && resolvedUserId) {
                        await tokenBarrierHook("before_issuance_commit", resolvedUserId);
                        await tokenBarrierHook("before_fence_refresh", resolvedUserId);
                    }

                    const commitSuccess = await commitTokenIssuanceLinearization(
                        database,
                        resolvedUserId,
                        expectedRefreshTokenVersion,
                        preRefreshIssuedAtMs,
                        clientFence
                    );

                    if (!commitSuccess) {
                        await purgeTokensOnCommitFailure(
                            database,
                            canonicalClientId,
                            resolvedUserId,
                            jwtAt,
                            tokenData,
                            currentFamilyId,
                            true
                        );
                        return c.json({
                            error: "invalid_grant",
                            error_description: "User account was revoked or version transitioned during token refresh",
                        }, 401);
                    }

                    if (tokenBarrierHook && resolvedUserId) {
                        await tokenBarrierHook("after_issuance_commit", resolvedUserId);
                    }

                    tokenData.access_token = jwtAt;
                    if (tokenData.id_token) {
                        tokenData.id_token = await resignIdTokenWithNewAtHash(
                            tokenData.id_token,
                            jwtAt,
                            (payload) => filterConsumerClaims(payload, tokenData.scope || "openid profile email", userDoc)
                        );
                    }
                    return c.json(tokenData, 200);
                }
            }
        }

        await releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner);
        return res;
    } catch (err) {
        await releaseRotationLock(database, incomingHash, canonicalClientId, leaseOwner);
        throw err;
    }
}
