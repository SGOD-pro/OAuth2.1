import { setCookie } from "hono/cookie";
import { getDb } from "../db/mongo";
import { resolveOAuthClient } from "../utils/security";
import { config } from "../config";

/**
 * Handle OAuth pre-login initiate endpoint (/oauth/initiate).
 * Resolves target OAuth client and sets current_client_id cookie.
 */
export async function handleOAuthInitiate(c: any): Promise<Response> {
    const clientId = c.req.query("client_id");
    const redirect_uri = c.req.query("redirect_uri") || "/";

    if (!clientId || clientId.trim() === "") {
        return c.json(
            {
                status: false,
                error: "invalid_request",
                message: "client_id is required",
            },
            400
        );
    }

    const database = await getDb();
    const clientDoc = await resolveOAuthClient(database, clientId);
    if (!clientDoc || clientDoc.disabled) {
        return c.json(
            {
                status: false,
                error: "invalid_client",
                message: "Client application not found or disabled",
            },
            400
        );
    }

    setCookie(c, "current_client_id", clientDoc.clientId, {
        path: "/",
        httpOnly: true,
        secure: config.env === "production",
        sameSite: "Lax",
        maxAge: 60 * 10,
    });

    return c.json({ success: true, redirect_uri });
}
