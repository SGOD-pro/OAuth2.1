import { getDb } from "../db/mongo";
import { resolveOAuthClient } from "../utils/security";

export interface AuthenticatedClientContext {
    canonicalClientId: string;
    clientDoc: any;
    reqToForward: Request;
    params: URLSearchParams;
}

export type ClientAuthResult =
    | { success: true; context: AuthenticatedClientContext }
    | { success: false; response: Response };

export async function authenticateTokenClient(c: any): Promise<ClientAuthResult> {
    const rawBodyText = await c.req.raw.clone().text().catch(() => "");
    const params = new URLSearchParams(rawBodyText);

    // 1. Authoritative Client Identity Extraction & Conflict Resolution (RFC 6749 Section 2.3 & 5.2)
    const authHeader = c.req.header("authorization");
    let basicClientId: string | null = null;
    let basicClientSecret: string | null = null;
    let hasBasicAuth = false;

    if (authHeader) {
        if (!authHeader.toLowerCase().startsWith("basic ")) {
            return {
                success: false,
                response: c.json({ error: "invalid_client", error_description: "Unsupported HTTP Authorization scheme; expected Basic" }, 400),
            };
        }
        try {
            const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
            const colonIndex = decoded.indexOf(":");
            if (colonIndex === -1) {
                return {
                    success: false,
                    response: c.json({ error: "invalid_client", error_description: "Malformed HTTP Basic authorization credentials" }, 400),
                };
            }
            basicClientId = decoded.slice(0, colonIndex);
            basicClientSecret = decoded.slice(colonIndex + 1);
            hasBasicAuth = true;
        } catch {
            return {
                success: false,
                response: c.json({ error: "invalid_client", error_description: "Malformed HTTP Basic authorization credentials" }, 400),
            };
        }
    }

    const bodyClientId = params.get("client_id");
    const bodyClientSecret = params.get("client_secret");

    // Reject multiple authentication methods or conflicting credentials
    if (hasBasicAuth && bodyClientSecret) {
        return {
            success: false,
            response: c.json({ error: "invalid_client", error_description: "Multiple client credentials submitted; client MUST NOT use more than one authentication method" }, 400),
        };
    }

    if (hasBasicAuth && bodyClientId && bodyClientId !== basicClientId) {
        return {
            success: false,
            response: c.json({ error: "invalid_client", error_description: "Conflicting client identifiers in HTTP Basic header and request body" }, 400),
        };
    }

    // Authoritative client identifier determination
    const authClientId = hasBasicAuth ? basicClientId : bodyClientId;
    if (!authClientId) {
        return {
            success: false,
            response: c.json({ error: "invalid_client", error_description: "Client authentication failed: missing client identifier" }, 400),
        };
    }

    // Canonicalize client identifier against database
    const database = await getDb();
    const clientDoc = await resolveOAuthClient(database, authClientId);
    if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
        const status = (clientDoc?.isAmbiguous || hasBasicAuth) ? 401 : 400;
        const headers = hasBasicAuth ? { "WWW-Authenticate": 'Basic realm="OAuth"' } : undefined;
        return {
            success: false,
            response: c.json(
                {
                    error: "invalid_client",
                    error_description: clientDoc?.isAmbiguous
                        ? "Client configuration is ambiguous and requires administrative review"
                        : "Client application not found or disabled",
                },
                status,
                headers
            ),
        };
    }

    const canonicalClientId = clientDoc.clientId;

    const isPublicClient = clientDoc.clientType === "public" ||
        (clientDoc.isPublic === true && !clientDoc.clientSecret && !clientDoc.client_secret);

    // Public clients MUST NOT supply client credentials (RFC 6749 Section 2.1 & OAuth 2.1)
    if (isPublicClient && (hasBasicAuth || bodyClientSecret)) {
        return {
            success: false,
            response: c.json(
                {
                    error: "invalid_client",
                    error_description: "Public clients must not supply client credentials",
                },
                400
            ),
        };
    }

    // Confidential clients MUST authenticate with credentials (RFC 6749 Section 2.3)
    if (!isPublicClient && !hasBasicAuth && !bodyClientSecret) {
        return {
            success: false,
            response: c.json(
                {
                    error: "invalid_client",
                    error_description: "Confidential clients must authenticate with valid client credentials",
                },
                401,
                { "WWW-Authenticate": 'Basic realm="OAuth"' }
            ),
        };
    }

    // Prepare single authoritative request to forward to Better Auth
    let reqToForward = c.req.raw;
    params.delete("client_secret");
    if (hasBasicAuth || bodyClientSecret) {
        params.delete("client_id");
    } else {
        // Preserve canonical client_id in body for public clients
        params.set("client_id", canonicalClientId);
    }
    const updatedBody = params.toString();

    const forwardHeaders = new Headers(c.req.raw.headers);
    if (hasBasicAuth) {
        const canonicalBasic = Buffer.from(`${canonicalClientId}:${basicClientSecret}`).toString("base64");
        forwardHeaders.set("Authorization", `Basic ${canonicalBasic}`);
    } else if (bodyClientSecret) {
        const canonicalBasic = Buffer.from(`${canonicalClientId}:${bodyClientSecret}`).toString("base64");
        forwardHeaders.set("Authorization", `Basic ${canonicalBasic}`);
    }

    reqToForward = new Request(c.req.raw.url, {
        method: c.req.raw.method,
        headers: forwardHeaders,
        body: updatedBody,
    });

    return {
        success: true,
        context: {
            canonicalClientId,
            clientDoc,
            reqToForward,
            params,
        },
    };
}
