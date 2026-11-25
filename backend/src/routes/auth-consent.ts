import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOAuthTransaction } from "../db/state";
import { getHeaders, resolveOAuthClient, checkUserHasAppAccess } from "../utils/security";
import { config } from "../config";
import { finalizeAuthorizeCodeWithFence, purgeAuthorizationCodeOnCommitFailure } from "./auth-token-linearize";
import { getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { dispatchRequestWithBrowserEntry, resolveVerifiedBrowserEntry } from "../identity/session-adapter";
import { verifySelectedTransactionStillActive } from "../identity/oauth-selection";

/**
 * Handle OAuth 2.1 user consent endpoint (/oauth2/consent).
 * Enforces session authentication and private application membership boundary.
 */
export async function handleOAuthConsent(c: Context) {
    const body = await c.req.raw.clone().json().catch(() => null);
    let clientId: string | null = null;
    let state: string | null = null;
    if (body?.oauth_query && typeof body.oauth_query === "string") {
        try {
            const queryParams = new URLSearchParams(body.oauth_query);
            clientId = queryParams.get("client_id");
            state = queryParams.get("state");
        } catch {}
    }
    if (!state) state = c.req.query("state") || null;

    const txIdParam = (typeof body?.transaction_id === "string" && body.transaction_id.trim()) || c.req.query("transaction_id") || getCookie(c, "oauth_transaction_id");
    const tx = await getOAuthTransaction({ transactionId: txIdParam || undefined, state: state || undefined });

    const rawBrowserProof = getCookie(c, getBrowserSessionCookieName());
    const database = await getDb();
    let sessionUser: any = null;
    let useSelectedAdapter = false;

    if (tx?.selectedEntryId && tx.browserSetId) {
        try {
            const verified = await resolveVerifiedBrowserEntry(authProvider as any, database, rawBrowserProof, tx.selectedEntryId);
            if (verified.userId !== tx.selectedUserId || verified.sessionId !== tx.selectedSessionId) {
                return c.json({ error: "unauthorized", code: "ERR_SELECTION_MISMATCH" }, 401);
            }
            const userDoc = await database.collection("user").findOne({ $or: [{ id: verified.userId }, { username: verified.label }] });
            sessionUser = { id: verified.userId, role: verified.role, ...userDoc };
            useSelectedAdapter = true;
        } catch {
            return c.json({ error: "unauthorized", code: "ERR_SESSION_REVOKED", message: "Selected session is no longer active" }, 401);
        }
    } else {
        try {
            const sessionResult = await authProvider.api.getSession({ headers: getHeaders(c) });
            if (sessionResult?.user) {
                const userDoc = await database.collection("user").findOne({
                    $or: [{ id: sessionResult.user.id }, { _id: (sessionResult.user as any)._id }, { email: sessionResult.user.email }],
                });
                sessionUser = { ...sessionResult.user, ...userDoc };
            }
        } catch {
            sessionUser = null;
        }
    }

    if (!sessionUser) {
        return c.json({ error: "unauthorized", message: "Authentication required" }, 401);
    }

    if (tx) {
        if (clientId && clientId !== tx.clientId) {
            return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
        }
        clientId = tx.clientId;
    }
    if (!clientId && (body?.client_id || body?.clientId)) {
        clientId = body.client_id || body.clientId;
    }
    if (!clientId) {
        clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
    }

    let resolvedClientDoc: any = null;
    if (clientId) {
        const database = await getDb();
        const clientDoc = await resolveOAuthClient(database, clientId);
        resolvedClientDoc = clientDoc;
        if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
            return c.json({ error: "invalid_client", error_description: "Client application not found, disabled, or ambiguous" }, 400);
        }

        const isPrivateConsent = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
        if (isPrivateConsent) {
            const canonicalClientId = clientDoc.clientId;
            const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

            if (!hasAccess) {
                return c.json({
                    error: "access_denied",
                    error_description: "Access restricted: Your account is not authorized for this private application"
                }, 403);
            }
        } else if (!config.openAppMembershipBypassEnabled) {
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            await database.collection("user_app_registrations").updateOne(
                { userId, clientId: clientDoc.clientId },
                { $setOnInsert: { userId, clientId: clientDoc.clientId, registeredAt: new Date() } },
                { upsert: true }
            ).catch(() => {});
        }
    }

    const res = useSelectedAdapter && tx?.selectedEntryId
        ? await dispatchRequestWithBrowserEntry(authProvider as any, database, rawBrowserProof, tx.selectedEntryId, c.req.raw)
        : await authProvider.handler(c.req.raw);
    if (useSelectedAdapter && tx) {
        const stillValid = await verifySelectedTransactionStillActive(database, rawBrowserProof, tx);
        if (!stillValid) {
            let redirectTarget: string | null = res.headers.get("location");
            if (!redirectTarget && res.status === 200) {
                const j = await res.clone().json().catch(() => null);
                redirectTarget = j?.redirect_uri || j?.url || null;
            }
            const code = redirectTarget ? new URL(redirectTarget, config.auth.baseURL).searchParams.get("code") : null;
            if (code) await purgeAuthorizationCodeOnCommitFailure(database, code).catch(() => {});
            return c.json({ error: "unauthorized", code: "ERR_SESSION_REVOKED" }, 401);
        }
    }
    const committed = await captureAndBindCode(res, tx, sessionUser, clientId, resolvedClientDoc);
    if (!committed) {
        return c.json({
            error: "unauthorized",
            code: "ERR_SESSION_REVOKED",
            error_description: "Selected session revoked, reselected, or client transitioned during consent",
        }, 401);
    }
    return res;
}

/**
 * Handle OAuth 2.1 continuation endpoint (/oauth2/continue).
 * Enforces private application membership verification on continuation flows.
 */
export async function handleOAuthContinue(c: Context) {
    let sessionUser: any = null;
    let clientId: string | null = null;
    let tx: any = null;
    let resolvedClientDoc: any = null;
    try {
        const sessionResult = await authProvider.api.getSession({
            headers: getHeaders(c),
        });
        if (sessionResult?.user) {
            const database = await getDb();
            const userDoc = await database.collection("user").findOne({
                $or: [
                    { id: sessionResult.user.id },
                    { _id: (sessionResult.user as any)._id },
                    { email: sessionResult.user.email },
                ],
            });
            sessionUser = { ...sessionResult.user, ...userDoc };
        }
    } catch {
        sessionUser = null;
    }

    if (sessionUser) {
        const body = await c.req.raw.clone().json().catch(() => null);
        let state: string | null = null;
        if (body?.oauth_query && typeof body.oauth_query === "string") {
            try {
                const queryParams = new URLSearchParams(body.oauth_query);
                clientId = queryParams.get("client_id");
                state = queryParams.get("state");
            } catch {}
        }
        if (!state) state = c.req.query("state") || null;

        const txIdCookie = getCookie(c, "oauth_transaction_id");
        tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
        if (tx) {
            if (clientId && clientId !== tx.clientId) {
                return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
            }
            clientId = tx.clientId;
        }
        if (!clientId && (body?.client_id || body?.clientId)) {
            clientId = body.client_id || body.clientId;
        }
        if (!clientId) {
            clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
        }

        if (clientId) {
            const database = await getDb();
            const clientDoc = await resolveOAuthClient(database, clientId);
            resolvedClientDoc = clientDoc;
            if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
                return c.json({ error: "invalid_client", error_description: "Client application not found, disabled, or ambiguous" }, 400);
            }
            const isPrivateContinue = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
            if (isPrivateContinue) {
                const canonicalClientId = clientDoc.clientId;
                const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

                if (!hasAccess) {
                    return c.json({
                        error: "access_denied",
                        error_description: "Access restricted: Your account is not authorized for this private application"
                    }, 403);
                }
            } else if (!config.openAppMembershipBypassEnabled) {
                const userId = String(sessionUser.id || (sessionUser as any)._id);
                await database.collection("user_app_registrations").updateOne(
                    { userId, clientId: clientDoc.clientId },
                    { $setOnInsert: { userId, clientId: clientDoc.clientId, registeredAt: new Date() } },
                    { upsert: true }
                ).catch(() => {});
            }
        }
    }

    const res = await authProvider.handler(c.req.raw);
    const committed = await captureAndBindCode(res, tx, sessionUser, clientId, resolvedClientDoc);
    if (!committed) return c.json({ error: "invalid_client", error_description: "Client credentials transitioned during continuation" }, 401);
    return res;
}

async function captureAndBindCode(
    res: Response,
    tx: any,
    sessionUser: any,
    clientId: string | null,
    clientDoc: any
): Promise<boolean> {
    try {
        let redirectTarget: string | null = res.headers.get("location");
        if (!redirectTarget && res.status === 200) {
            const clone = res.clone();
            const json = await clone.json().catch(() => null);
            if (json && typeof json.redirect_uri === "string") {
                redirectTarget = json.redirect_uri;
            } else if (json && typeof json.url === "string") {
                redirectTarget = json.url;
            }
        }
        if (redirectTarget) {
            const parsed = new URL(redirectTarget, config.auth.baseURL);
            const code = parsed.searchParams.get("code");
            if (code && sessionUser) {
                const sessionUserId = String(sessionUser.id || sessionUser._id);
                const currentVersion = typeof sessionUser.tokenVersion === "number" ? sessionUser.tokenVersion : 1;
                const database = await getDb();
                const targetCid = clientDoc?.clientId || tx?.clientId || clientId || "";
                if (targetCid) {
                    const sessionFence = (tx?.selectedSessionId && tx?.selectedEntryId) ? {
                        transactionId: tx.transactionId,
                        expectedSelectionRevision: typeof tx.selectionRevision === "number" ? tx.selectionRevision : 1,
                        expectedSessionId: tx.selectedSessionId,
                        expectedEntryId: tx.selectedEntryId,
                        expectedBrowserSetId: tx.browserSetId || undefined,
                        expectedUserId: tx.selectedUserId || sessionUserId,
                    } : undefined;
                    return finalizeAuthorizeCodeWithFence(database, {
                        clientId: targetCid,
                        expectedClientType: clientDoc?.clientType,
                        expectedCredentialVersion: typeof clientDoc?.credentialVersion === "number" ? clientDoc.credentialVersion : 1,
                    }, {
                        code,
                        clientId: targetCid,
                        redirectUri: tx?.redirectUri || (parsed.origin + parsed.pathname),
                        codeChallenge: tx?.codeChallenge,
                        codeChallengeMethod: tx?.codeChallengeMethod || "S256",
                        userId: sessionUserId,
                        tokenVersion: currentVersion,
                        transactionId: tx?.transactionId,
                    }, sessionFence);
                }
            }
        }
    } catch {}
    return true;
}
