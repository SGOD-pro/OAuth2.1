import { Hono } from "hono";
import { authProvider, validateAuthPasswordBoundary } from "../utils/auth";
import { getTrustedClientIp } from "../utils/security";

const auth = new Hono();

auth.get("/", (c) => c.json({ status: "ok" }));

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
        ip: getTrustedClientIp(c.req.raw.headers),
    });

    return authProvider.handler(c.req.raw);
});

export default auth;
