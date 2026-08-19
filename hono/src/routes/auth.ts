import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import { authProvider, validateAuthPasswordBoundary } from "../utils/auth";
import { database } from "../db/mongo";
import { config } from "../config";

const auth = new Hono();

auth.get("/", (c) => c.json({ status: "ok" }));

/**
 * Standard client ID extraction from request context:
 * Checks query string, body, callbackURL, or HTTP Referer header
 */
function extractClientId(c: any, body: any): string | null {
    try {
        const url = new URL(c.req.url);
        const queryCid = url.searchParams.get("client_id") || c.req.query("client_id");
        if (queryCid) return queryCid;
    } catch {}

    if (body?.client_id) return body.client_id;
    if (body?.clientId) return body.clientId;

    if (body?.callbackURL) {
        try {
            const parsed = new URL(body.callbackURL, "http://dummy");
            const cid = parsed.searchParams.get("client_id");
            if (cid) return cid;
        } catch {}
    }

    const referer = c.req.header("referer") || c.req.header("Referer");
    if (referer) {
        try {
            const parsed = new URL(referer);
            const cid = parsed.searchParams.get("client_id");
            if (cid) return cid;
        } catch {}
    }

    return null;
}

// 0. Standard OIDC JWKS Endpoints
auth.get("/jwks.json", async (c) => {
    const jwks = await authProvider.api.getJwks({
        headers: Object.fromEntries(c.req.raw.headers.entries()),
    });
    return c.json(jwks);
});

auth.get("/jwks", async (c) => {
    const jwks = await authProvider.api.getJwks({
        headers: Object.fromEntries(c.req.raw.headers.entries()),
    });
    return c.json(jwks);
});

// 1. RP-Initiated / Secure Client Logout
auth.post("/sign-out-client", async (c) => {
    const { client_id, redirect_uri } = await c.req.json().catch(() => ({}));
    const client = await database.collection("oauthClient").findOne({ clientId: client_id });
    if (!client || !client.redirectUris.includes(redirect_uri)) {
        return c.json({ error: "Invalid redirect URI" }, 400);
    }

    const session = await authProvider.api.getSession({ headers: c.req.raw.headers });
    if (session) {
        await database.collection("session").deleteOne({ token: session.session.token });
    }

    setCookie(c, "better-auth.session_token", "", {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
    });

    return c.json({ success: true, redirect_uri });
});

// 2. Sign-In App-Isolation Check
auth.post("/sign-in/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = extractClientId(c, body);

    if (clientId && body?.email) {
        const user = await database.collection("user").findOne({ email: body.email.toLowerCase() });
        if (user) {
            const reg = await database.collection("user_app_registrations").findOne({
                $or: [
                    { userId: String(user._id), clientId },
                    { userId: user._id, clientId },
                    ...(user.id ? [{ userId: user.id, clientId }] : [])
                ]
            });

            if (!reg) {
                return c.json(
                    {
                        status: false,
                        message: "User is not registered for this application. Please register first.",
                    },
                    400,
                );
            }
        }
    }

    return authProvider.handler(c.req.raw);
});

// 3. Sign-Up App-Isolation Registration
auth.post("/sign-up/email", async (c) => {
    const body = await c.req.raw.clone().json().catch(() => null);
    const clientId = extractClientId(c, body);

    if (body?.email) {
        const user = await database.collection("user").findOne({ email: body.email.toLowerCase() });

        // If user already exists globally
        if (user) {
            const userId = user.id || String(user._id);

            // Check if user is ALREADY registered for this specific application
            if (clientId) {
                const existingReg = await database.collection("user_app_registrations").findOne({
                    $or: [
                        { userId: String(user._id), clientId },
                        { userId: user._id, clientId },
                        ...(user.id ? [{ userId: user.id, clientId }] : [])
                    ]
                });

                if (existingReg) {
                    return c.json(
                        {
                            status: false,
                            message: "An account with this email is already registered for this application. Please sign in instead.",
                        },
                        400,
                    );
                }
            }

            // User exists globally but NOT registered for this application -> verify credentials & register for app
            try {
                const signInRes = await authProvider.api.signInEmail({
                    body: { email: body.email, password: body.password },
                    headers: c.req.raw.headers,
                    asResponse: true,
                });

                if (signInRes.ok) {
                    if (clientId) {
                        await database.collection("user_app_registrations").updateOne(
                            { userId, clientId },
                            { $setOnInsert: { userId, clientId, createdAt: new Date() } },
                            { upsert: true },
                        );
                    }
                    return signInRes;
                } else {
                    return c.json(
                        {
                            status: false,
                            message: "An account with this email already exists with a different password. Please check your credentials.",
                        },
                        400,
                    );
                }
            } catch {
                return c.json(
                    {
                        status: false,
                        message: "An account with this email already exists with a different password. Please check your credentials.",
                    },
                    400,
                );
            }
        }
    }

    // Password policy check
    const passwordError = validateAuthPasswordBoundary(c.req.path, body);
    if (passwordError) {
        return c.json({ error: passwordError }, 400);
    }

    // Standard new user sign up
    const response = await authProvider.handler(c.req.raw);
    if (response.ok && body?.email) {
        const newUser = await database.collection("user").findOne({ email: body.email.toLowerCase() });
        if (newUser && clientId) {
            const userId = newUser.id || String(newUser._id);
            await database.collection("user_app_registrations").updateOne(
                { userId, clientId },
                { $setOnInsert: { userId, clientId, createdAt: new Date() } },
                { upsert: true },
            );
        }
    }
    return response;
});

// 4. OAuth Authorize Interceptor
auth.get("/oauth2/authorize", async (c) => {
    const url = new URL(c.req.url);
    const clientId = url.searchParams.get("client_id");

    // P1-10: Require state parameter to prevent OAuth CSRF / session injection.
    // PKCE prevents code theft but not session injection — state is the correct guard.
    // Per OAuth 2.1 §4.1.1, state is strongly recommended; we enforce it here.
    const state = url.searchParams.get("state");
    if (!state || state.trim().length === 0) {
        const configUrl = config.frontendUrl || "http://localhost:5174";
        return c.redirect(
            `${configUrl}/auth?${url.searchParams.toString()}&error=state_required&error_description=The+state+parameter+is+required+to+prevent+CSRF+attacks`,
        );
    }

    if (clientId) {
        const session = await authProvider.api.getSession({ headers: c.req.raw.headers });
        if (session) {
            const sessUserId = session.user.id || (session.user as any)._id;
            const isRegistered = await database.collection("user_app_registrations").findOne({
                $or: [
                    { userId: String(sessUserId), clientId },
                    ...(sessUserId ? [{ userId: sessUserId, clientId }] : [])
                ]
            });

            if (!isRegistered) {
                const configUrl = config.frontendUrl || "http://localhost:5174";
                return c.redirect(`${configUrl}/auth?${url.searchParams.toString()}&error=not_registered`);
            }
        }
    }

    return authProvider.handler(c.req.raw);
});

// 5. P0-5: UserInfo Interceptor (RFC 6750 §3.1 compliance)
// When Better Auth encounters malformed JWTs (alg=none, wrong key, corrupt payload),
// JOSE throws ERR_JOSE_NOT_SUPPORTED and Better Auth returns 500.
// RFC 6750 §3.1 strictly requires HTTP 401 with WWW-Authenticate: Bearer error="invalid_token".
auth.get("/oauth2/userinfo", async (c) => {
    try {
        const response = await authProvider.handler(c.req.raw);
        if (response.status === 500) {
            return c.json(
                { error: "invalid_token", error_description: "Invalid or unsupported access token" },
                401,
                { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Invalid or unsupported access token"' }
            );
        }
        return response;
    } catch {
        return c.json(
            { error: "invalid_token", error_description: "Token validation failed" },
            401,
            { "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token validation failed"' }
        );
    }
});

// 6. Fallback handler for all other Better Auth endpoints (session, oauth callbacks, etc.)
auth.all("/*", async (c) => {
    if (c.req.method === "POST") {
        const body = await c.req.raw.clone().json().catch(() => null);
        const passwordError = validateAuthPasswordBoundary(c.req.path, body);
        if (passwordError) {
            return c.json({ error: passwordError }, 400);
        }
    }

    return authProvider.handler(c.req.raw);
});

export default auth;
