import crypto from "crypto";
import { getCookie } from "hono/cookie";
import { getOAuthTransaction } from "../db/state";

export interface ClientContext {
    clientId: string | null;
    isBoundOAuthFlow: boolean;
}

// Helper to extract clientId from various locations with authoritative transaction state resolution
export async function extractClientContext(c: any, body?: any): Promise<ClientContext> {
    const query = c.req.query("client_id") || c.req.query("clientId");
    if (query) return { clientId: query, isBoundOAuthFlow: true };

    if (body?.clientId) return { clientId: body.clientId, isBoundOAuthFlow: true };
    if (body?.client_id) return { clientId: body.client_id, isBoundOAuthFlow: true };

    let state: string | null = c.req.query("state") || null;

    if (body?.callbackURL && typeof body.callbackURL === "string") {
        try {
            const url = new URL(body.callbackURL, "http://localhost");
            const cid = url.searchParams.get("client_id") || url.searchParams.get("clientId");
            if (cid) return { clientId: cid, isBoundOAuthFlow: true };
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    const callbackQuery = c.req.query("callbackURL");
    if (callbackQuery) {
        try {
            const url = new URL(callbackQuery, "http://localhost");
            const cid = url.searchParams.get("client_id") || url.searchParams.get("clientId");
            if (cid) return { clientId: cid, isBoundOAuthFlow: true };
            if (!state) state = url.searchParams.get("state");
        } catch {}
    }

    // Authoritative server-side transaction lookup by state parameter
    if (state) {
        const tx = await getOAuthTransaction({ state });
        if (tx?.clientId) return { clientId: tx.clientId, isBoundOAuthFlow: true };
    }

    // Detect platform (MAuth) sign-in context.
    // Platform sign-in has callbackURL explicitly pointing to /admin or /api/admin.
    // Stale oauth_transaction_id / current_client_id cookies from a prior
    // private-app OAuth flow must NEVER contaminate platform sign-in.
    const rawCallback = body?.callbackURL ?? c.req.query("callbackURL") ?? "";
    let callbackPath = "";
    if (typeof rawCallback === "string" && rawCallback.length > 0) {
        try {
            callbackPath = new URL(rawCallback, "http://localhost").pathname;
        } catch {
            callbackPath = rawCallback;
        }
    }
    const isPlatformSignIn =
        callbackPath.startsWith("/admin") ||
        callbackPath.startsWith("/api/admin");

    if (!isPlatformSignIn) {
        // Only inherit cookie-based client context for ongoing OAuth flows,
        // never for platform sign-in. Cookie fallback requires no explicit
        // client_id or state to be present in the request.
        const txIdCookie = getCookie(c, "oauth_transaction_id");
        if (txIdCookie) {
            const tx = await getOAuthTransaction({ transactionId: txIdCookie });
            if (tx?.clientId) return { clientId: tx.clientId, isBoundOAuthFlow: true };
        }

        const cookieVal = getCookie(c, "current_client_id");
        if (cookieVal) {
            // A bare current_client_id cookie without an active validated transaction
            // is validated for client existence (preventing cookie poisoning), but is not
            // treated as a bound OAuth flow for private app membership blocking.
            return { clientId: cookieVal, isBoundOAuthFlow: false };
        }
    }

    return { clientId: null, isBoundOAuthFlow: false };
}

// Constant-time dummy hash computation to prevent login timing enumeration (Fix B10)
// Uses exact Better-Auth scrypt parameters: N=16384, r=16, p=1, dkLen=64, maxmem=67108864
export async function executeDummyHash(): Promise<void> {
    return new Promise((resolve, reject) => {
        crypto.scrypt(
            "DummyPassword@123!".normalize("NFKC"),
            "dummy_salt_constant_time_98234",
            64,
            { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 },
            (err) => {
                if (err) reject(err);
                else resolve();
            }
        );
    });
}
