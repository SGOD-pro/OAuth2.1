import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOAuthTransaction } from "../db/state";
import { getHeaders, resolveOAuthClient, checkUserHasAppAccess } from "../utils/security";

/**
 * Handle OAuth 2.1 user consent endpoint (/oauth2/consent).
 * Enforces session authentication and private application membership boundary.
 */
export async function handleOAuthConsent(c: Context) {
    let sessionUser: any = null;
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

    if (!sessionUser) {
        return c.json({ error: "unauthorized", message: "Authentication required" }, 401);
    }

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

    const txIdCookie = getCookie(c, "oauth_transaction_id");
    const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
    if (tx) {
        if (clientId && clientId !== tx.clientId) {
            return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
        }
        clientId = tx.clientId;
    }
    if (!clientId) {
        clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
    }

    if (clientId) {
        const database = await getDb();
        const clientDoc = await resolveOAuthClient(database, clientId);
        if (!clientDoc || clientDoc.disabled) {
            return c.json({ error: "invalid_client", error_description: "Client application not found or disabled" }, 400);
        }

        if (!clientDoc.isPublic) {
            const canonicalClientId = clientDoc.clientId;
            const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

            if (!hasAccess) {
                return c.json({
                    error: "access_denied",
                    error_description: "Access restricted: Your account is not authorized for this private application"
                }, 403);
            }
        }
    }

    return authProvider.handler(c.req.raw);
}

/**
 * Handle OAuth 2.1 continuation endpoint (/oauth2/continue).
 * Enforces private application membership verification on continuation flows.
 */
export async function handleOAuthContinue(c: Context) {
    let sessionUser: any = null;
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

        const txIdCookie = getCookie(c, "oauth_transaction_id");
        const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
        if (tx) {
            if (clientId && clientId !== tx.clientId) {
                return c.json({ error: "invalid_request", error_description: "Client ID does not match OAuth transaction" }, 400);
            }
            clientId = tx.clientId;
        }
        if (!clientId) {
            clientId = c.req.query("client_id") || getCookie(c, "current_client_id") || null;
        }

        if (clientId) {
            const database = await getDb();
            const clientDoc = await resolveOAuthClient(database, clientId);
            if (clientDoc && !clientDoc.isPublic) {
                const canonicalClientId = clientDoc.clientId;
                const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

                if (!hasAccess) {
                    return c.json({
                        error: "access_denied",
                        error_description: "Access restricted: Your account is not authorized for this private application"
                    }, 403);
                }
            }
        }
    }

    return authProvider.handler(c.req.raw);
}
