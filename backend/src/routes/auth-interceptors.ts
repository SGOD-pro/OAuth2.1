import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { getOAuthTransaction } from "../db/state";
import {
    getHeaders,
    resolveOAuthClient,
    checkUserHasAppAccess,
    toApprovedDisplayLabel,
    isEmailShaped,
} from "../utils/security";
import { config } from "../config";
import { revokeUserTokensDurable } from "./auth-keys";

/**
 * Creates a route handler for disabled OAuth client management endpoints.
 */
export function handleDisabledEndpoint(description: string) {
    return (c: Context) => c.json({ error: "access_denied", error_description: description }, 403);
}

/**
 * Handle admin list-users privacy projection.
 * Projects display labels rather than raw email identifiers.
 */
export async function handleAdminListUsers(c: Context) {
    const res = await authProvider.handler(c.req.raw);
    if (res.status === 200) {
        try {
            const data = await res.clone().json();
            if (data && Array.isArray(data.users)) {
                data.users = data.users.map((u: any) => ({
                    ...u,
                    displayLabel: toApprovedDisplayLabel(u.email, u.name),
                    email: toApprovedDisplayLabel(u.email),
                    name: isEmailShaped(u.name) ? toApprovedDisplayLabel(u.name) : (u.name || "User"),
                }));
                return c.json(data, 200);
            }
        } catch {}
    }
    return res;
}

/**
 * Wraps an admin mutation route to trigger durable token revocation upon success.
 */
export function handleAdminRevocationRoute(routePath: string) {
    return async (c: Context) => {
        const body = await c.req.raw.clone().json().catch(() => ({}));
        const targetUserId = body.userId || body.id;
        const res = await authProvider.handler(c.req.raw);
        if (res.status < 400 && targetUserId) {
            try {
                const database = await getDb();
                await revokeUserTokensDurable(database, String(targetUserId));
            } catch (err) {
                console.error(`[ADMIN_REVOCATION] Error syncing durable revocation for ${routePath}:`, err);
            }
        }
        return res;
    };
}

/**
 * Social Login Callback App-Isolation & Registration Enforcer.
 * Handles /callback/:provider and /oauth2/callback/:provider.
 */
export async function handleSocialCallback(c: Context) {
    const res = await authProvider.handler(c.req.raw);

    const state = c.req.query("state");
    const txIdCookie = getCookie(c, "oauth_transaction_id");
    let clientId: string | null = null;
    if (state || txIdCookie) {
        const tx = await getOAuthTransaction({ state: state || undefined, transactionId: txIdCookie || undefined });
        if (tx?.clientId) {
            clientId = tx.clientId;
        }
    }
    if (!clientId) {
        clientId = getCookie(c, "current_client_id") || null;
    }

    if (clientId) {
        let database: any;
        try {
            database = await getDb();
        } catch (dbErr) {
            console.error("DB connection error in handleSocialCallback:", dbErr);
            return c.json({ error: "server_error", message: "Database resolution failure" }, 500);
        }

        let clientDoc: any;
        try {
            clientDoc = await resolveOAuthClient(database, clientId);
        } catch (dbErr) {
            console.error("DB query error in resolveOAuthClient:", dbErr);
            return c.json({ error: "server_error", message: "Database resolution failure" }, 500);
        }

        if (clientDoc) {
            const canonicalClientId = clientDoc.clientId;

            // Extract session token from set-cookie header on res or from incoming request cookies
            let sessionToken: string | null = null;
            const setCookieList: string[] = (res.headers as any).getSetCookie
                ? (res.headers as any).getSetCookie()
                : [res.headers.get("set-cookie") || ""];
            for (const header of setCookieList) {
                const match = header.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
                if (match) {
                    sessionToken = decodeURIComponent(match[1]);
                    break;
                }
            }
            if (!sessionToken) {
                sessionToken = getCookie(c, "better-auth.session_token") || getCookie(c, "__Secure-better-auth.session_token") || null;
            }

            const rawSessionToken = sessionToken ? sessionToken.split(".")[0] : null;

            let sessionUser: any = null;
            if (!sessionUser && (sessionToken || rawSessionToken)) {
                try {
                    const sessionDoc = await database.collection("session").findOne({
                        $or: [
                            ...(sessionToken ? [{ token: sessionToken }, { id: sessionToken }] : []),
                            ...(rawSessionToken ? [{ token: rawSessionToken }, { id: rawSessionToken }] : []),
                        ],
                    });
                    if (sessionDoc) {
                        const rawUserId = sessionDoc.userId;
                        let userObjId: any = rawUserId;
                        try {
                            if (ObjectId.isValid(rawUserId)) userObjId = new ObjectId(rawUserId);
                        } catch {}
                        sessionUser = await database.collection("user").findOne({
                            $or: [{ id: String(rawUserId) }, { _id: rawUserId }, { _id: userObjId }],
                        }).catch(() => null);
                        if (!sessionUser) {
                            sessionUser = { id: String(rawUserId), _id: rawUserId };
                        }
                    }
                } catch {
                    sessionUser = null;
                }
            }

            if (!sessionUser) {
                try {
                    const headers = getHeaders(c);
                    if (sessionToken) {
                        headers.set("cookie", `better-auth.session_token=${sessionToken}`);
                    }
                    const sessionResult = await authProvider.api.getSession({ headers });
                    sessionUser = sessionResult?.user ?? null;
                } catch {
                    sessionUser = null;
                }
            }

            if (sessionUser) {
                const userId = String(sessionUser.id || (sessionUser as any)._id);

                const isPrivate = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
                if (isPrivate) {
                    // Private application: verify authorization boundary
                    const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

                    if (!hasAccess) {
                        // CRITICAL: Fail-Closed deterministic cleanup!
                        // Identify and revoke the exact created session, without destroying the user's
                        // entire account or other devices' unrelated sessions.
                        if (sessionToken || rawSessionToken) {
                            await database.collection("session").deleteMany({
                                $or: [
                                    ...(sessionToken ? [{ token: sessionToken }, { id: sessionToken }] : []),
                                    ...(rawSessionToken ? [{ token: rawSessionToken }, { id: rawSessionToken }] : []),
                                ],
                            });
                        }

                        // Clear session cookies so the browser does not retain an authorized session
                        const headers = new Headers(res.headers);
                        headers.delete("set-cookie");
                        headers.append("set-cookie", "better-auth.session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
                        headers.append("set-cookie", "__Secure-better-auth.session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure");
                        headers.append("set-cookie", "current_client_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");

                        const errorRedirectUrl = new URL(`${config.frontendUrl}/auth`);
                        errorRedirectUrl.searchParams.set("error", "access_denied");
                        errorRedirectUrl.searchParams.set(
                            "error_description",
                            "Access restricted: Your account is not authorized for this private application"
                        );
                        headers.set("location", errorRedirectUrl.toString());

                        return new Response(null, {
                            status: 302,
                            headers,
                        });
                    }
                } else if (!config.openAppMembershipBypassEnabled) {
                    // Public application: record membership idempotently
                    await database.collection("user_app_registrations").updateOne(
                        { userId, clientId: canonicalClientId },
                        { $setOnInsert: { userId, clientId: canonicalClientId, registeredAt: new Date() } },
                        { upsert: true }
                    );
                }
            }
        }
    }

    return res;
}
