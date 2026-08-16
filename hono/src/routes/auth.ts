import { Hono } from "hono";
import { authProvider, validateAuthPasswordBoundary } from "../utils/auth";
import { config } from "../config";
import { database } from "../db/mongo";

const auth = new Hono();

auth.get("/", (c) => c.json({ status: "ok" }));

// GET /api/auth/sign-out handler for federated RP logout
auth.get("/sign-out", async (c) => {
    const callbackURL = c.req.query("callbackURL") || config.frontendUrl;

    const cookieHeader = c.req.header("cookie") || "";
    const sessionMatch = cookieHeader.match(/better-auth\.session_token=([^;]+)/);
    if (sessionMatch && sessionMatch[1]) {
        try {
            const token = decodeURIComponent(sessionMatch[1]);
            await database.collection("session").deleteOne({ token });
        } catch (err) {
            console.error("Failed to delete session from DB on sign-out:", err);
        }
    }

    const isProd = config.env === "production";
    const deleteCookieHeader = `better-auth.session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=${isProd ? "None" : "Lax"}${isProd ? "; Secure" : ""}`;
    c.header("Set-Cookie", deleteCookieHeader);
    return c.redirect(callbackURL);
});

auth.all("/*", async (c) => {
    const path = c.req.path;

    if (c.req.method === "POST") {
        const body = await c.req.raw.clone().json().catch(() => null);
        const passwordError = validateAuthPasswordBoundary(path, body);
        if (passwordError) {
            return c.json({ error: passwordError }, 400);
        }
    }

    console.log({
        event: "auth_request",
        method: c.req.method,
        path,
    });

    return authProvider.handler(c.req.raw);
});

export default auth;
