import type { Context } from "hono";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { resolveOAuthClient, hashToken } from "../utils/security";

/**
 * Handle OAuth 2.1 Token Revocation (RFC 7009) with authenticated client and family scoping.
 * Enforces client boundary matching and atomic family revocation fences.
 */
export async function handleOAuthRevoke(c: Context) {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);
    const token = params.get("token");

    const authHeader = c.req.header("authorization");
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
    const bodyClientId = params.get("client_id");
    const rawClientId = basicClientId || bodyClientId;

    if (rawClientId) {
        const database = await getDb();
        const clientDoc = await resolveOAuthClient(database, rawClientId);
        if (clientDoc?.isAmbiguous) {
            const headers = hasBasicAuth ? { "WWW-Authenticate": 'Basic realm="OAuth"' } : undefined;
            return c.json(
                { error: "invalid_client", error_description: "Client configuration is ambiguous and requires administrative review" },
                401,
                headers
            );
        }
    }

    // 1. Forward request to Better Auth for client authentication and provider handling
    const res = await authProvider.handler(c.req.raw);

    // CRITICAL: Provider authentication failure MUST cause zero revocation mutations
    if (res.status === 401) {
        return res;
    }

    if (!token) {
        return res;
    }

    if (token) {
        try {
            if (!rawClientId) {
                return res;
            }

            const database = await getDb();
            const clientDoc = await resolveOAuthClient(database, rawClientId);
            if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                return res;
            }

            const canonicalClientId = clientDoc.clientId;
            const tokenHex = hashToken(token, "hex");
            const tokenBase64 = hashToken(token, "base64url");
            const now = new Date();

            // 1. Look up if token was a refresh token in families scoped strictly to authenticated client
            const familyDoc = await database.collection("oauth_token_families").findOne({
                clientId: canonicalClientId,
                $or: [
                    { activeTokenHash: tokenHex },
                    { activeTokenHash: tokenBase64 },
                    { consumedTokenHashes: tokenHex },
                    { consumedTokenHashes: tokenBase64 },
                ],
            });

            if (familyDoc) {
                // Targeted client-scoped family revocation: revokes only this family for this client
                await database.collection("oauth_token_families").updateOne(
                    { familyId: familyDoc.familyId, clientId: canonicalClientId },
                    { $set: { status: "revoked", revokedAt: now, rotating: false } }
                );

                const familyHashes = [
                    familyDoc.activeTokenHash,
                    ...(Array.isArray(familyDoc.consumedTokenHashes) ? familyDoc.consumedTokenHashes : []),
                ].filter(Boolean);

                await Promise.all([
                    database.collection("oauthAccessToken").deleteMany({
                        clientId: canonicalClientId,
                        familyId: familyDoc.familyId,
                    }),
                    database.collection("oauthRefreshToken").deleteMany({
                        clientId: canonicalClientId,
                        $or: [
                            { familyId: familyDoc.familyId },
                            { token: token },
                            { token: tokenBase64 },
                            { token: tokenHex },
                            ...(familyHashes.length > 0 ? [{ token: { $in: familyHashes } }] : []),
                        ],
                    }),
                ]);
            } else {
                // 2. Look up in oauthAccessToken scoped strictly to authenticated client
                const accDoc = await database.collection("oauthAccessToken").findOne({
                    clientId: canonicalClientId,
                    $or: [{ token }, { token: tokenBase64 }, { token: tokenHex }],
                });
                if (accDoc) {
                    if (accDoc.familyId) {
                        await database.collection("oauth_token_families").updateOne(
                            { familyId: accDoc.familyId, clientId: canonicalClientId },
                            { $set: { status: "revoked", revokedAt: now, rotating: false } }
                        );
                        await Promise.all([
                            database.collection("oauthAccessToken").deleteMany({
                                clientId: canonicalClientId,
                                familyId: accDoc.familyId,
                            }),
                            database.collection("oauthRefreshToken").deleteMany({
                                clientId: canonicalClientId,
                                familyId: accDoc.familyId,
                            }),
                        ]);
                    } else {
                        await database.collection("oauthAccessToken").deleteOne({ _id: accDoc._id });
                    }
                } else {
                    // 3. Look up in oauthRefreshToken scoped strictly to authenticated client
                    const refDoc = await database.collection("oauthRefreshToken").findOne({
                        clientId: canonicalClientId,
                        $or: [{ token }, { token: tokenBase64 }, { token: tokenHex }],
                    });
                    if (refDoc) {
                        if (refDoc.familyId) {
                            await database.collection("oauth_token_families").updateOne(
                                { familyId: refDoc.familyId, clientId: canonicalClientId },
                                { $set: { status: "revoked", revokedAt: now, rotating: false } }
                            );
                            await Promise.all([
                                database.collection("oauthAccessToken").deleteMany({
                                    clientId: canonicalClientId,
                                    familyId: refDoc.familyId,
                                }),
                                database.collection("oauthRefreshToken").deleteMany({
                                    clientId: canonicalClientId,
                                    $or: [
                                        { familyId: refDoc.familyId },
                                        { token: refDoc.token },
                                    ],
                                }),
                            ]);
                        } else {
                            await database.collection("oauthRefreshToken").deleteOne({ _id: refDoc._id });
                        }
                    }
                }
            }
        } catch (err) {
            console.error("[REVOCATION] Error during client scoped token revocation hook:", err);
        }
    }

    return c.json({}, 200);
}
