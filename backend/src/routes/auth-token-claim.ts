import { verifyAndRotateTokenFamily, recordAuthEvent } from "../db/state";
import { getTrustedClientIp } from "../utils/security";
import { config } from "../config";
import crypto from "node:crypto";

export type ClaimRotationResult =
    | { claimed: true; claim: any; existingFamily: any; leaseOwner: string }
    | { claimed: false; response: Response };

export async function claimRotationRights(
    c: any,
    database: any,
    canonicalClientId: string,
    clientDoc: any,
    incomingHash: string
): Promise<ClaimRotationResult> {
    const existingFamily = await database.collection("oauth_token_families").findOne({
        $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
    });

    // Cross-client defense: Verify the token family belongs to the authenticated client
    // Do NOT leak whether the token exists, is consumed, or is revoked to an unauthorized client
    // FAIL-CLOSED: A token family without a matching clientId is strictly rejected
    if (existingFamily && (!existingFamily.clientId || existingFamily.clientId !== canonicalClientId)) {
        return {
            claimed: false,
            response: c.json(
                {
                    error: "invalid_grant",
                    error_description: "Refresh token was not issued to the authenticated client",
                },
                400
            ),
        };
    }

    if (existingFamily && existingFamily.status === "revoked") {
        return {
            claimed: false,
            response: c.json(
                {
                    error: "invalid_grant",
                    error_description: "Token family has been revoked due to previous security event",
                },
                401
            ),
        };
    }

    const staleLockThreshold = new Date(Date.now() - 15000);
    const leaseOwner = crypto.randomUUID();

    // Atomic compare-and-swap to claim rotation rights for this token family
    // Scoped strictly by canonicalClientId to prevent cross-client CAS contention
    // Allows reclaiming a stale lock if a previous rotation timed out or crashed (> 15s)
    const claim = await database.collection("oauth_token_families").findOneAndUpdate(
        {
            activeTokenHash: incomingHash,
            clientId: canonicalClientId,
            status: "active",
            $or: [
                { rotating: { $ne: true } },
                { rotatingAt: { $lt: staleLockThreshold } },
            ],
        },
        {
            $set: { rotating: true, rotatingAt: new Date(), rotationOwner: leaseOwner },
        },
        { returnDocument: "after" }
    );

    if (!claim) {
        // Check if rotation is currently in-flight by the winning concurrent request for this client
        const currentDoc = await database.collection("oauth_token_families").findOne({
            clientId: canonicalClientId,
            $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
        });

        const isActivelyRotating =
            currentDoc &&
            (currentDoc as any).rotating === true &&
            (currentDoc as any).rotatingAt &&
            new Date((currentDoc as any).rotatingAt).getTime() > Date.now() - 15000;

        if (isActivelyRotating) {
            return {
                claimed: false,
                response: c.json(
                    {
                        error: "invalid_grant",
                        error_description: "Refresh token was already consumed or is currently being rotated",
                    },
                    400
                ),
            };
        }

        // Otherwise, token was already rotated; check if within grace window or replay theft
        const check = await verifyAndRotateTokenFamily(incomingHash, "dummy", undefined, Date.now(), canonicalClientId);
        if (check.replayed) {
            const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
            const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
            await recordAuthEvent({
                eventType: "oauth_token",
                outcome: "denied",
                clientId: canonicalClientId,
                clientName: clientDoc?.client_name || clientDoc?.name || null,
                ipAddress: safeIp,
                reason: "refresh_token_reuse",
            });
            return {
                claimed: false,
                response: c.json(
                    {
                        error: "invalid_grant",
                        error_description: "Refresh token has been revoked due to replay detection",
                    },
                    401
                ),
            };
        }
        return {
            claimed: false,
            response: c.json(
                {
                    error: "invalid_grant",
                    error_description: "Refresh token was already consumed or is currently being rotated",
                },
                400
            ),
        };
    }

    return {
        claimed: true,
        claim,
        existingFamily,
        leaseOwner,
    };
}
