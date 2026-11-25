import { ObjectId } from "mongodb";
import { hashToken } from "../utils/security";
import { bindAuthorizationCode, type BindAuthorizationCodeParams } from "../utils/pkce";
import { getTokenBarrierHookForTesting } from "./auth-keys";
import {
    type SelectedSessionIssuanceFence,
    commitSelectedSessionLinearization,
    resolveSessionFenceFromTransaction,
} from "../identity/session-issuance-fence";

export {
    type SelectedSessionIssuanceFence,
    commitSelectedSessionLinearization,
    resolveSessionFenceFromTransaction,
};

export interface ClientIssuanceFence {
    clientId: string;
    expectedClientType?: string;
    expectedCredentialVersion?: number;
}

/**
 * Builds an issuance fence for a DB-backed OAuth client, returning undefined only for
 * unbacked unit-test stub contexts lacking client document identifiers.
 */
export function buildClientIssuanceFence(canonicalClientId: string, clientDoc: any): ClientIssuanceFence | undefined {
    if (!clientDoc?._id && !clientDoc?.clientId && !clientDoc?.client_id && !clientDoc?.id) {
        return undefined;
    }
    return {
        clientId: canonicalClientId,
        expectedClientType: clientDoc.clientType,
        expectedCredentialVersion: typeof clientDoc.credentialVersion === "number" ? clientDoc.credentialVersion : 1,
    };
}

function buildExpectedClientTypeFilter(expectedClientType?: string): Record<string, any> | null {
    if (expectedClientType === "public") {
        return {
            $or: [
                { clientType: "public" },
                {
                    $and: [
                        { $or: [{ clientType: { $exists: false } }, { clientType: null }] },
                        { $or: [{ clientSecret: { $exists: false } }, { clientSecret: null }] },
                        { $or: [{ client_secret: { $exists: false } }, { client_secret: null }] },
                    ],
                },
            ],
        };
    }
    if (expectedClientType === "confidential") {
        return {
            $or: [
                { clientType: "confidential" },
                {
                    $and: [
                        { $or: [{ clientType: { $exists: false } }, { clientType: null }] },
                        { $or: [{ clientSecret: { $exists: true, $ne: null } }, { client_secret: { $exists: true, $ne: null } }] },
                    ],
                },
            ],
        };
    }
    return null;
}

/**
 * Verifies and stamps an in-flight OAuth client authorization or token issuance against
 * concurrent Confidential -> Public transitions, disabled state, or ambiguity flags.
 */
export async function commitClientIssuanceLinearization(
    database: any,
    fence: ClientIssuanceFence
): Promise<boolean> {
    const version = typeof fence.expectedCredentialVersion === "number" ? fence.expectedCredentialVersion : 1;
    const andClauses: Record<string, any>[] = [
        { $or: [{ clientId: fence.clientId }, { client_id: fence.clientId }, { id: fence.clientId }] },
        {
            $or: [
                { credentialVersion: version },
                ...(version === 1 ? [{ credentialVersion: { $exists: false } }, { credentialVersion: null }] : []),
            ],
        },
    ];
    const typeFilter = buildExpectedClientTypeFilter(fence.expectedClientType);
    if (typeFilter) andClauses.push(typeFilter);

    const condition: Record<string, any> = {
        disabled: { $ne: true },
        isAmbiguous: { $ne: true },
        $and: andClauses,
    };

    const result: any = await database.collection("oauthClient").findOneAndUpdate(
        condition,
        { $set: { lastTokenIssuedAt: new Date() } },
        { returnDocument: "after" }
    );
    const updated = result && (result.value !== undefined ? result.value : result);
    return Boolean(updated);
}

/**
 * Purges a newly minted authorization code from local and engine stores if a concurrent client
 * transition occurred before code issuance committed.
 */
export async function purgeAuthorizationCodeOnCommitFailure(database: any, code: string): Promise<void> {
    const codeB64 = hashToken(code, "base64url");
    await Promise.all([
        database.collection("oauthAuthorizationCode").deleteMany({ code }).catch(() => {}),
        database.collection("verification").deleteMany({ identifier: { $in: [code, codeB64] } }).catch(() => {}),
    ]);
}

/**
 * Verifies in-flight client policy state before committing and binding an issued authorization code.
 */
export async function commitUserIssuanceLinearization(
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

export async function finalizeAuthorizeCodeWithFence(
    database: any,
    fence: ClientIssuanceFence,
    bindParams: Omit<BindAuthorizationCodeParams, "clientType" | "clientCredentialVersion">,
    sessionFence?: SelectedSessionIssuanceFence
): Promise<boolean> {
    const barrierHook = getTokenBarrierHookForTesting();
    if (barrierHook) {
        await barrierHook("before_authorize_commit", fence.clientId);
        const targetId = sessionFence?.transactionId || bindParams.transactionId || undefined;
        if (targetId) {
            await barrierHook("before_selected_session_commit", targetId);
        }
    }
    const clientCommitted = await commitClientIssuanceLinearization(database, fence);
    if (!clientCommitted) {
        await purgeAuthorizationCodeOnCommitFailure(database, bindParams.code);
        return false;
    }
    if (bindParams.userId) {
        const userCommitted = await commitUserIssuanceLinearization(
            database,
            bindParams.userId,
            typeof bindParams.tokenVersion === "number" ? bindParams.tokenVersion : 1
        );
        if (!userCommitted) {
            await purgeAuthorizationCodeOnCommitFailure(database, bindParams.code);
            return false;
        }
    }
    const effectiveSessionFence = sessionFence || (bindParams.transactionId ? await resolveSessionFenceFromTransaction(database, bindParams.transactionId) : undefined);
    if (effectiveSessionFence) {
        const sessionCommitted = await commitSelectedSessionLinearization(database, effectiveSessionFence, bindParams.code);
        if (!sessionCommitted) {
            await purgeAuthorizationCodeOnCommitFailure(database, bindParams.code);
            return false;
        }
    }
    await bindAuthorizationCode(database, {
        ...bindParams,
        clientType: fence.expectedClientType,
        clientCredentialVersion: fence.expectedCredentialVersion,
    });
    return true;
}

/**
 * Checks whether an authorization code or refresh artifact predates a Confidential -> Public
 * credential transition on the target client.
 */
export function isArtifactInvalidatedByClientTransition(
    clientDoc: any,
    artifact?: { clientType?: string; clientCredentialVersion?: number; createdAt?: any; issuedAtMs?: number }
): boolean {
    if (!clientDoc || !artifact) return false;
    const currentVersion = typeof clientDoc.credentialVersion === "number" ? clientDoc.credentialVersion : 1;
    if (typeof artifact.clientCredentialVersion === "number" && artifact.clientCredentialVersion !== currentVersion) {
        return true;
    }
    if (artifact.clientType && clientDoc.clientType && artifact.clientType !== clientDoc.clientType) {
        return true;
    }
    const createdMs = artifact.issuedAtMs ?? (artifact.createdAt ? new Date(artifact.createdAt).getTime() : undefined);
    if (clientDoc.clientSecretRevokedAt && createdMs && createdMs <= new Date(clientDoc.clientSecretRevokedAt).getTime()) {
        return true;
    }
    return false;
}
