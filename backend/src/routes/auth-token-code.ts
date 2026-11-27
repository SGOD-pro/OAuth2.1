import crypto from "crypto";
import { ObjectId } from "mongodb";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { hashToken, checkUserHasAppAccess } from "../utils/security";
import { checkAccountEligibilityWithLedger } from "../utils/account-eligibility";
import { registerTokenFamily } from "../db/state";
import { verifyAndConsumeAuthorizationCode } from "../utils/pkce";
import {
    buildProtectedIdTokenClaimFilter,
    mapProtectedTokenError,
    mintJwtAccessToken,
    resignIdTokenWithNewAtHash,
    type ProtectedTokenClaimDeps,
    type TokenGrantDeps,
} from "./auth-jwt";

export function buildCodeIdTokenClaimFilter(
    scope: string | string[],
    userDoc: any,
    deps: ProtectedTokenClaimDeps = {}
) {
    return buildProtectedIdTokenClaimFilter(scope, userDoc, deps);
}
import { getTokenBarrierHookForTesting } from "./auth-keys";
import { AuthenticatedClientContext, verifyConfidentialClientCredentials } from "./auth-token-auth";
import {
    resolveTokenSubjectUserId,
    commitTokenIssuanceLinearization,
    purgeTokensOnMintFailure,
    purgeTokensOnCommitFailure,
    isArtifactInvalidatedByClientTransition,
    buildClientIssuanceFence,
} from "./auth-token-linearize";

/**
 * Handle authorization_code grant exchange.
 * Enforces pre-code user eligibility, registers token family, mints RS256 JWT,
 * and performs atomic conditional issuance linearization.
 */
export async function handleAuthorizationCodeGrant(
    c: any,
    clientContext: AuthenticatedClientContext,
    deps: TokenGrantDeps = {}
): Promise<Response> {
    const { canonicalClientId, reqToForward, params } = clientContext;
    const database = await (deps.getDb ?? getDb)();
    const incomingCode = params.get("code");
    if (!incomingCode) {
        return c.json({ error: "invalid_request", error_description: "code is required" }, 400);
    }

    // Authenticate confidential clients through the installed engine before code mutation
    const clientDoc = clientContext.clientDoc;
    const clientFence = buildClientIssuanceFence(canonicalClientId, clientDoc);
    const isPublicClient = clientDoc?.clientType === "public" ||
        (clientDoc?.isPublic === true && !clientDoc?.clientSecret && !clientDoc?.client_secret);

    if (!isPublicClient) {
        const authProbe = await verifyConfidentialClientCredentials(c, clientContext);
        if (!authProbe.success) {
            return authProbe.response;
        }
    }

    const codeVerifier = params.get("code_verifier");
    const consumption = await verifyAndConsumeAuthorizationCode(database, {
        code: incomingCode,
        clientId: canonicalClientId,
        redirectUri: params.get("redirect_uri"),
        codeVerifier,
    });

    if (!consumption.success) {
        return c.json(
            { error: consumption.error, error_description: consumption.description },
            consumption.status
        );
    }

    let preCodeUserId: string | undefined;
    let codeIssuedAtSec: number | undefined;
    let codeIssuedAtMs: number | undefined;
    let codeTokenVersion: number | undefined;

    const codeDoc = consumption.codeDoc;
    if (codeDoc) {
        if (isArtifactInvalidatedByClientTransition(clientDoc, codeDoc)) {
            return c.json({ error: "invalid_grant", error_description: "Client credentials transitioned since authorization code was issued" }, 400);
        }
        if (codeDoc.userId) {
            preCodeUserId = String(codeDoc.userId);
        }
        if (codeDoc.createdAt) {
            codeIssuedAtMs = new Date(codeDoc.createdAt).getTime();
            codeIssuedAtSec = Math.floor(codeIssuedAtMs / 1000);
        }
        if (codeDoc.tokenVersion !== undefined) {
            codeTokenVersion = codeDoc.tokenVersion;
        }
        if (preCodeUserId) {
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: preCodeUserId },
                    ...(ObjectId.isValid(preCodeUserId) && preCodeUserId.length === 24 ? [{ _id: new ObjectId(preCodeUserId) }] : []),
                ],
            });
            const eligibility = await checkAccountEligibilityWithLedger(database, userDoc, {
                tokenIssuedAtMs: codeIssuedAtMs,
                tokenIssuedAtSec: codeIssuedAtSec ?? Math.floor(Date.now() / 1000),
                tokenVersion: codeTokenVersion,
            });
            if (!eligibility.eligible) {
                return c.json({
                    error: "invalid_grant",
                    error_description: `User account is not eligible for token exchange: ${eligibility.reason}`,
                }, 400);
            }

            const isPrivate = clientContext.clientDoc?.accessPolicy === "private" ||
                (clientContext.clientDoc?.accessPolicy !== "open" && clientContext.clientDoc?.isPublic === false);
            if (isPrivate) {
                const hasAccess = await checkUserHasAppAccess(database, userDoc, canonicalClientId);
                if (!hasAccess) {
                    return c.json({
                        error: "invalid_grant",
                        error_description: "User is not an authorized member of this private application",
                    }, 400);
                }
            }
        }
    }

    const res = await (deps.authHandler ?? ((req: Request) => authProvider.handler(req)))(reqToForward);

    if (res.status === 200) {
        try {
            const tokenData = await res.clone().json().catch(() => null);

            let resolvedUserId: string | undefined = await resolveTokenSubjectUserId(database, tokenData, preCodeUserId);
            let userDoc: any = null;

            if (resolvedUserId) {
                userDoc = await database.collection("user").findOne({
                    $or: [
                        { id: resolvedUserId },
                        ...(ObjectId.isValid(resolvedUserId) && resolvedUserId.length === 24 ? [{ _id: new ObjectId(resolvedUserId) }] : []),
                    ],
                });
                const eligibility = await checkAccountEligibilityWithLedger(database, userDoc, {
                    tokenIssuedAtMs: codeIssuedAtMs,
                    tokenIssuedAtSec: codeIssuedAtSec ?? Math.floor(Date.now() / 1000),
                    tokenVersion: codeTokenVersion,
                });
                if (!eligibility.eligible) {
                    if (tokenData?.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                    }
                    if (tokenData?.access_token) {
                        await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    }
                    return c.json({
                        error: "invalid_grant",
                        error_description: `User account is not eligible for token exchange: ${eligibility.reason}`,
                    }, 400);
                }
            }

            const expectedTokenVersion = typeof codeTokenVersion === "number"
                ? codeTokenVersion
                : (typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1);

            let familyId: string | null = null;
            if (tokenData && tokenData.refresh_token) {
                const initialHash = hashToken(tokenData.refresh_token, "hex");
                familyId = crypto.randomUUID();

                try {
                    await registerTokenFamily(familyId, canonicalClientId, resolvedUserId, initialHash, expectedTokenVersion);
                } catch (regErr) {
                    console.error("[TOKEN_FAMILY] Critical failure registering initial family; failing closed:", regErr);
                    await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                    if (tokenData.access_token) {
                        await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    }
                    return c.json(
                        {
                            error: "server_error",
                            error_description: "Failed to establish secure token family state",
                        },
                        500
                    );
                }
            }

            if (tokenData && tokenData.access_token) {
                if (!resolvedUserId) {
                    console.error("[TOKEN_MINTING] Missing resolvedUserId in authorization_code flow; failing closed without opaque fallback");
                    if (tokenData.refresh_token) {
                        await database.collection("oauthRefreshToken").deleteMany({ token: tokenData.refresh_token }).catch(() => {});
                        if (familyId) {
                            await database.collection("oauth_token_families").deleteMany({ familyId }).catch(() => {});
                        }
                    }
                    await database.collection("oauthAccessToken").deleteMany({ token: tokenData.access_token }).catch(() => {});
                    return c.json(
                        {
                            error: "server_error",
                            error_description: "Failed to resolve authenticated user identity for token minting",
                        },
                        500
                    );
                }

                let jwtAt: string | null = null;
                let resignedIdToken = tokenData.id_token;
                try {
                    jwtAt = await mintJwtAccessToken({
                        userId: resolvedUserId,
                        clientId: canonicalClientId,
                        expiresInSeconds: tokenData.expires_in || 900,
                        scope: tokenData.scope,
                        tokenIssuedAtMs: codeIssuedAtMs,
                        tokenIssuedAtSec: codeIssuedAtSec,
                        tokenVersion: expectedTokenVersion,
                        familyId: familyId || undefined,
                    }, deps);
                    if (jwtAt && tokenData.id_token) {
                        resignedIdToken = await resignIdTokenWithNewAtHash(
                            tokenData.id_token,
                            jwtAt,
                            buildCodeIdTokenClaimFilter(tokenData.scope || "openid", userDoc, deps),
                            deps.getSigningKey
                        );
                    }
                } catch (mintErr) {
                    await purgeTokensOnMintFailure(database, tokenData, familyId);
                    const mapped = mapProtectedTokenError(c, mintErr);
                    if (mapped) return mapped;
                    throw mintErr;
                }

                if (!jwtAt) {
                    console.error("[TOKEN_MINTING] Failed to mint RS256 access token in authorization_code flow; failing closed without opaque fallback");
                    await purgeTokensOnMintFailure(database, tokenData, familyId);
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
                    familyId: familyId || undefined,
                    expiresAt: new Date(Date.now() + (tokenData.expires_in || 900) * 1000),
                    createdAt: new Date(),
                    scopes: tokenData.scope ? tokenData.scope.split(/\s+/).filter(Boolean) : ["openid"],
                    tokenVersion: expectedTokenVersion,
                }).catch(() => {});

                if (tokenData.refresh_token) {
                    await database.collection("oauthRefreshToken").updateOne(
                        { token: tokenData.refresh_token },
                        { $set: { familyId: familyId || undefined, tokenVersion: expectedTokenVersion } }
                    ).catch(() => {});
                }

                const tokenBarrierHook = getTokenBarrierHookForTesting();
                if (tokenBarrierHook && resolvedUserId) {
                    await tokenBarrierHook("before_issuance_commit", resolvedUserId);
                    await tokenBarrierHook("before_fence_code", resolvedUserId);
                }

                const commitSuccess = await commitTokenIssuanceLinearization(
                    database,
                    resolvedUserId,
                    expectedTokenVersion,
                    codeIssuedAtMs,
                    clientFence
                );

                if (!commitSuccess) {
                    await purgeTokensOnCommitFailure(
                        database,
                        canonicalClientId,
                        resolvedUserId,
                        jwtAt,
                        tokenData,
                        familyId
                    );
                    return c.json({
                        error: "invalid_grant",
                        error_description: "User account was revoked or version transitioned during token exchange",
                    }, 400);
                }

                if (tokenBarrierHook && resolvedUserId) {
                    await tokenBarrierHook("after_issuance_commit", resolvedUserId);
                }

                if (familyId) {
                    await database.collection("oauthAuthorizationCode").updateOne(
                        { code: incomingCode },
                        { $set: { familyId } }
                    ).catch(() => {});
                }

                tokenData.access_token = jwtAt;
                if (tokenData.id_token) {
                    tokenData.id_token = resignedIdToken;
                }
                return c.json(tokenData, 200);
            }
        } catch (err) {
            console.error("[TOKEN_FAMILY] Error in token issuance interceptor:", err);
            return c.json(
                {
                    error: "server_error",
                    error_description: "Internal security failure during token generation",
                },
                500
            );
        }
    }

    return res;
}
