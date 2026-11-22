import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOAuthTransaction } from "../db/state";
import { getHeaders } from "../utils/security";
import { isSuperAdmin } from "../middleware/admin-auth";

export interface ValidatedMfaOauthContext {
    transactionId: string;
    clientId: string;
    clientName: string | null;
    boundUserId?: string | null;
}

export async function resolveValidatedMfaOauthContext(c: Context): Promise<ValidatedMfaOauthContext | null> {
    const txIdCookie = getCookie(c, "oauth_transaction_id");
    const txIdQuery = c.req.query("transaction_id");
    const stateQuery = c.req.query("state");
    const queryClientId = c.req.query("client_id");

    const candidateTxId = txIdCookie || txIdQuery;
    if (!candidateTxId && !stateQuery) {
        return null;
    }

    try {
        const tx = await getOAuthTransaction({
            transactionId: candidateTxId || undefined,
            state: stateQuery || undefined,
        });

        if (!tx || tx.status !== "pending") {
            return null;
        }

        if (queryClientId && queryClientId !== tx.clientId) {
            console.warn(`[MFA_OAUTH] Conflicting client_id in query hint: expected ${tx.clientId}, got ${queryClientId}`);
            return null;
        }

        const database = await getDb();
        const clientDoc = await database.collection("oauthClient").findOne({ clientId: tx.clientId });
        if (!clientDoc || clientDoc.disabled === true) {
            return null;
        }

        const clientName = clientDoc.clientName || clientDoc.client_name || clientDoc.name || null;

        return {
            transactionId: tx.transactionId,
            clientId: tx.clientId,
            clientName,
            boundUserId: tx.userId || null,
        };
    } catch {
        return null;
    }
}

export async function resolveCandidateMfaUser(c: Context): Promise<{ id: string | null; email: string | null } | null> {
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            return {
                id: (sessionResult.user.id || (sessionResult.user as any)._id)?.toString() || null,
                email: sessionResult.user.email || null,
            };
        }
    } catch {
        // no active session
    }

    try {
        const twoFactorCookie = getCookie(c, "better-auth.two_factor");
        if (twoFactorCookie) {
            const database = await getDb();
            const parts = twoFactorCookie.split(".");
            const tokenVal = parts[0];
            const record = await database.collection("verification").findOne({
                $or: [
                    { identifier: twoFactorCookie },
                    { identifier: tokenVal },
                    { value: twoFactorCookie },
                    { value: tokenVal },
                ],
            });
            if (record?.value) {
                const candidateUserId = record.value;
                const userConditions: any[] = [{ id: candidateUserId }, { _id: candidateUserId }];
                if (ObjectId.isValid(candidateUserId)) {
                    userConditions.push({ _id: new ObjectId(candidateUserId) });
                }
                const u = await database.collection("user").findOne({
                    $or: userConditions,
                });
                if (u) {
                    return {
                        id: (u.id || u._id)?.toString() || null,
                        email: u.email || null,
                    };
                }
            }
        }
    } catch {
        // ignore
    }

    return null;
}

export async function recordMfaPublicAppMembership(
    database: any,
    completedUserId: string,
    validatedContext: ValidatedMfaOauthContext | null
): Promise<void> {
    if (!completedUserId || !validatedContext) {
        return;
    }

    if (!validatedContext.boundUserId || validatedContext.boundUserId !== completedUserId) {
        console.warn(`[MFA_OAUTH] Identity binding mismatch or missing: bound ${validatedContext.boundUserId} vs completed ${completedUserId}`);
        return;
    }

    const userConditions: any[] = [{ id: completedUserId }, { _id: completedUserId }];
    if (ObjectId.isValid(completedUserId)) {
        userConditions.push({ _id: new ObjectId(completedUserId) });
    }
    const userDoc = await database.collection("user").findOne({
        $or: userConditions,
    });
    if (!userDoc) {
        return;
    }

    if (isSuperAdmin(userDoc)) {
        return;
    }

    const clientDoc = await database.collection("oauthClient").findOne({ clientId: validatedContext.clientId });
    if (!clientDoc || clientDoc.disabled === true || !clientDoc.isPublic) {
        return;
    }

    const canonicalClientId = clientDoc.clientId;
    await database.collection("user_app_registrations").updateOne(
        { userId: completedUserId, clientId: canonicalClientId },
        { $setOnInsert: { userId: completedUserId, clientId: canonicalClientId, registeredAt: new Date() } },
        { upsert: true }
    );

    await database.collection("oauth_transactions").updateOne(
        { transactionId: validatedContext.transactionId, status: "pending" },
        { $set: { userId: completedUserId } }
    );
}

export interface VerifiedMfaSession {
    sessionId: string | null;
    completedUserId: string | null;
    actor: string | null;
}

export async function resolveVerifiedMfaSession(res: Response): Promise<VerifiedMfaSession> {
    if (res.status >= 400) {
        return { sessionId: null, completedUserId: null, actor: null };
    }

    try {
        const setCookieList: string[] = (res.headers as any).getSetCookie
            ? (res.headers as any).getSetCookie()
            : [res.headers.get("set-cookie") || ""];
        for (const header of setCookieList) {
            const match = header.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
            if (match) {
                const rawToken = decodeURIComponent(match[1]);
                const token = rawToken.split(".")[0];
                const database = await getDb();
                const sessionDoc = await database.collection("session").findOne({ token });
                if (sessionDoc && sessionDoc.userId) {
                    const sessionId = String(sessionDoc._id || sessionDoc.id);
                    const completedUserId = sessionDoc.userId.toString();
                    await database.collection("session").updateOne(
                        { _id: sessionDoc._id },
                        { $set: { twoFactorVerified: true, mfaVerifiedAt: new Date() } }
                    ).catch(() => {});
                    let actor: string | null = null;
                    const u = await database.collection("user").findOne({
                        $or: [{ id: completedUserId }, { _id: completedUserId }],
                    });
                    if (u?.email) {
                        actor = u.email;
                    }
                    return { sessionId, completedUserId, actor };
                }
            }
        }
    } catch {
        // ignore
    }

    return { sessionId: null, completedUserId: null, actor: null };
}
