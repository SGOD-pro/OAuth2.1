import crypto from "crypto";
import { setCookie } from "hono/cookie";
import { ObjectId } from "mongodb";
import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { config } from "../config";
import {
    getHeaders,
    getTrustedClientIp,
    resolveOAuthClient,
    isRegisteredRedirectUri,
    checkUserAppRegistration,
    checkUserHasAppAccess,
} from "../utils/security";
import { checkAccountEligibility } from "../utils/account-eligibility";
import { createOAuthTransaction, recordAuthEvent } from "../db/state";
import { validatePkceAuthorizationParams, bindAuthorizationCode } from "../utils/pkce";

export async function handleOAuthAuthorize(c: any): Promise<Response> {
    const state = c.req.query("state");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");

    // A. CSRF State parameter requirement
    if (!state || state.trim() === "") {
        const errorRedirect = new URL(`${config.frontendUrl}/auth`);
        if (clientId) errorRedirect.searchParams.set("client_id", clientId);
        if (redirectUri) errorRedirect.searchParams.set("redirect_uri", redirectUri);
        errorRedirect.searchParams.set("response_type", c.req.query("response_type") || "code");
        errorRedirect.searchParams.set("error", "state_required");
        errorRedirect.searchParams.set("error_description", "The state parameter is required to prevent CSRF attacks");
        return c.redirect(errorRedirect.toString(), 302);
    }

    if (!clientId) {
        return c.json({ error: "invalid_request", error_description: "client_id is required" }, 400);
    }

    const database = await getDb();
    const client = await resolveOAuthClient(database, clientId);

    // B. Resolve canonical OAuth client & verify not deleted
    if (!client) {
        return c.json({ error: "invalid_client", error_description: "Client application not found" }, 401);
    }

    // C. Verify client is not suspended/deactivated or ambiguous
    if (client.disabled) {
        return c.json({ error: "unauthorized_client", error_description: "Client application is suspended or deactivated" }, 403);
    }
    if (client.isAmbiguous) {
        return c.json({ error: "invalid_client", error_description: "Client configuration is ambiguous and requires administrative review" }, 400);
    }

    // D. Validate requested redirect URI against registered client redirect URI list
    if (!redirectUri) {
        return c.json({ error: "invalid_request", error_description: "redirect_uri is required" }, 400);
    }

    const isValidRedirect = isRegisteredRedirectUri(client, redirectUri);
    if (!isValidRedirect) {
        return c.json({ error: "invalid_request", error_description: "The redirect_uri is not registered for this application" }, 400);
    }

    const canonicalClientId = client.clientId;

    // Validate PKCE S256 parameters for authorization code flows
    const pkceValidation = validatePkceAuthorizationParams({
        codeChallenge: c.req.query("code_challenge"),
        codeChallengeMethod: c.req.query("code_challenge_method"),
        responseType: c.req.query("response_type"),
    });

    if (!pkceValidation.valid) {
        const errorUrl = new URL(redirectUri);
        errorUrl.searchParams.set("error", pkceValidation.error!);
        errorUrl.searchParams.set("error_description", pkceValidation.description!);
        errorUrl.searchParams.set("state", state);
        return c.redirect(errorUrl.toString(), 302);
    }

    // Create server-side OAuth transaction record for multi-tab isolation & tampering prevention
    const transactionId = crypto.randomUUID();

    await createOAuthTransaction({
        transactionId,
        clientId: canonicalClientId,
        redirectUri,
        state,
        codeChallenge: pkceValidation.challenge,
        codeChallengeMethod: pkceValidation.method,
    });

    const cookieOpts = {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax" as const,
        maxAge: 60 * 10,
    };
    setCookie(c, "oauth_transaction_id", transactionId, cookieOpts);
    setCookie(c, "current_client_id", canonicalClientId, cookieOpts);

    // E. Determine authenticated user from session & MongoDB
    let sessionUser: any = null;
    const isPromptLogin = c.req.query("prompt") === "login";
    if (!isPromptLogin) {
        try {
            const sessionResult = await authProvider.api.getSession({
                headers: getHeaders(c),
            });
            if (sessionResult?.user) {
                const sessionUserId = String(sessionResult.user.id || (sessionResult.user as any)._id);
                const userDoc = await database.collection("user").findOne({
                    $or: [
                        { id: sessionUserId },
                        ...(ObjectId.isValid(sessionUserId) && sessionUserId.length === 24 ? [{ _id: new ObjectId(sessionUserId) }] : []),
                    ],
                });

                // Authoritative Account Eligibility Check on Authorize
                // Bound to active session creation timestamp; older session must not survive revocation
                const sessionCreatedAtMs = sessionResult?.session?.createdAt
                    ? new Date(sessionResult.session.createdAt).getTime()
                    : Date.now();
                const sessionCreatedAtSec = Math.floor(sessionCreatedAtMs / 1000);
                const eligibility = checkAccountEligibility(userDoc, {
                    tokenIssuedAtMs: sessionCreatedAtMs,
                    tokenIssuedAtSec: sessionCreatedAtSec,
                    tokenVersion: userDoc?.tokenVersion,
                });
                if (!eligibility.eligible) {
                    const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                    const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                    await recordAuthEvent({
                        eventType: "oauth_authorize",
                        outcome: "denied",
                        userId: sessionUserId,
                        targetIdentifier: userDoc?.email || sessionResult.user.email || null,
                        clientId: canonicalClientId,
                        clientName: client.client_name || client.name || null,
                        ipAddress: safeIp,
                        reason: `account_ineligible_${eligibility.reason}`,
                    });
                    const errorUrl = new URL(redirectUri);
                    errorUrl.searchParams.set("error", "access_denied");
                    errorUrl.searchParams.set("error_description", `Account is not eligible for authorization: ${eligibility.reason}`);
                    errorUrl.searchParams.set("state", state);
                    return c.redirect(errorUrl.toString(), 302);
                }

                sessionUser = { ...sessionResult.user, ...userDoc };
            }
        } catch {
            sessionUser = null;
        }
    }

    const forwardToBetterAuth = async () => {
        let rawReq = c.req.raw;
        if (isPromptLogin) {
            const h = new Headers(rawReq.headers);
            const cookieHeader = h.get("cookie") || "";
            const filteredCookies = cookieHeader
                .split(";")
                .map((part) => part.trim())
                .filter((part) => !part.startsWith("better-auth.session_token=") && !part.startsWith("__Secure-better-auth.session_token="))
                .join("; ");
            if (filteredCookies) {
                h.set("cookie", filteredCookies);
            } else {
                h.delete("cookie");
            }
            rawReq = new Request(rawReq.url, {
                method: rawReq.method,
                headers: h,
                body: rawReq.body,
                redirect: "manual",
            });
        }
        const res = await authProvider.handler(rawReq);
        const headers = new Headers(res.headers);
        headers.append("set-cookie", `oauth_transaction_id=${transactionId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);
        headers.append("set-cookie", `current_client_id=${canonicalClientId}; Path=/; HttpOnly; SameSite=Lax${config.env === "production" ? "; Secure" : ""}; Max-Age=600`);

        let location = headers.get("location");

        // If Better Auth returned a JSON object with { redirect: true, url }, convert it into a standard
        // OAuth 302 Found redirect so browser user-agents seamlessly follow authorization to the callback URL
        if (!location && res.status === 200) {
            try {
                const resClone = res.clone();
                const json = await resClone.json();
                if (json && json.redirect === true && typeof json.url === "string") {
                    location = json.url;
                    headers.set("location", json.url);
                }
            } catch {}
        }

        if (location) {
            try {
                const locUrl = new URL(location, config.auth.baseURL);
                const code = locUrl.searchParams.get("code");
                if (code) {
                    const sessionUserId = sessionUser ? String(sessionUser.id || sessionUser._id) : undefined;
                    const currentVersion = sessionUser && typeof sessionUser.tokenVersion === "number" ? sessionUser.tokenVersion : 1;
                    await bindAuthorizationCode(database, {
                        code,
                        clientId: canonicalClientId,
                        redirectUri,
                        codeChallenge: pkceValidation.challenge,
                        codeChallengeMethod: pkceValidation.method,
                        userId: sessionUserId,
                        tokenVersion: currentVersion,
                        transactionId,
                    }).catch(() => {});
                }
                if (locUrl.pathname.includes("/auth")) {
                    locUrl.searchParams.set("client_id", canonicalClientId);
                    locUrl.searchParams.set("transaction_id", transactionId);
                    locUrl.searchParams.set("state", state);
                    if (!client.isPublic) {
                        locUrl.searchParams.set("is_public", "false");
                    }
                    location = locUrl.toString();
                    headers.set("location", location);
                }
            } catch {}
            return new Response(null, {
                status: 302,
                statusText: "Found",
                headers,
            });
        }

        return new Response(res.body, {
            status: res.status,
            statusText: res.statusText,
            headers,
        });
    };

    // F. Enforce Private Application Mode at OAuth Boundary
    if (!client.isPublic) {
        if (sessionUser) {
            // User is already authenticated with a valid global session
            const hasAccess = await checkUserHasAppAccess(database, sessionUser, canonicalClientId);

            if (!hasAccess) {
                const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
                const safeIp = rawIp && rawIp !== "unknown" ? rawIp : null;
                await recordAuthEvent({
                    eventType: "oauth_authorize",
                    outcome: "denied",
                    userId: String(sessionUser.id || (sessionUser as any)._id),
                    targetIdentifier: sessionUser.email || null,
                    clientId: canonicalClientId,
                    clientName: client.client_name || client.name || null,
                    ipAddress: safeIp,
                    reason: "private_app_unauthorized",
                });
                // Deny authorization immediately! Do NOT issue code or continue to token issuance.
                const errorUrl = new URL(redirectUri);
                errorUrl.searchParams.set("error", "access_denied");
                errorUrl.searchParams.set("error_description", "Access restricted: Your account is not authorized for this private application");
                errorUrl.searchParams.set("state", state);
                return c.redirect(errorUrl.toString(), 302);
            }
        } else {
            // Unauthenticated user attempting OAuth on a private application:
            // Forward to centralized IdP login with registration disabled.
            // DO NOT block unauthenticated users from reaching the IdP login page.
            return forwardToBetterAuth();
        }
    } else {
        // Public Application Mode:
        if (sessionUser) {
            const userId = String(sessionUser.id || (sessionUser as any)._id);
            const isRegistered = await checkUserAppRegistration(database, userId, canonicalClientId);
            if (!isRegistered) {
                await database.collection("user_app_registrations").insertOne({
                    userId,
                    clientId: canonicalClientId,
                    registeredAt: new Date(),
                }).catch((err: any) => {
                    if (err?.code === 11000) return;
                    throw err;
                });
            }
        }
    }

    // Continue normal Better Auth OAuth flow
    return forwardToBetterAuth();
}
