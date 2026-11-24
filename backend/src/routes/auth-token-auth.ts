import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { resolveOAuthClient } from "../utils/security";

export interface AuthenticatedClientContext {
    canonicalClientId: string;
    clientDoc: any;
    reqToForward: Request;
    params: URLSearchParams;
    authMethod: "client_secret_basic" | "client_secret_post" | "none";
    clientSecret?: string;
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

    const registeredPostAuth = clientDoc?.tokenEndpointAuthMethod === "client_secret_post" ||
        clientDoc?.token_endpoint_auth_method === "client_secret_post";

    const authMethod: "client_secret_basic" | "client_secret_post" | "none" = hasBasicAuth
        ? "client_secret_basic"
        : bodyClientSecret
        ? (registeredPostAuth ? "client_secret_post" : "client_secret_basic")
        : "none";
    const clientSecret = hasBasicAuth ? (basicClientSecret || undefined) : (bodyClientSecret || undefined);

    // Prepare single authoritative request to forward to Better Auth
    let reqToForward = c.req.raw;
    const forwardHeaders = new Headers(c.req.raw.headers);

    if (authMethod === "client_secret_basic") {
        params.delete("client_secret");
        params.delete("client_id");
        const canonicalBasic = Buffer.from(`${canonicalClientId}:${clientSecret}`).toString("base64");
        forwardHeaders.set("Authorization", `Basic ${canonicalBasic}`);
    } else if (authMethod === "client_secret_post") {
        params.set("client_id", canonicalClientId);
        params.set("client_secret", bodyClientSecret || "");
        forwardHeaders.delete("authorization");
    } else {
        // Public client
        params.delete("client_secret");
        params.set("client_id", canonicalClientId);
        forwardHeaders.delete("authorization");
    }
    const updatedBody = params.toString();

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
            authMethod,
            clientSecret,
        },
    };
}

/**
 * Authenticate confidential clients through the installed engine before state mutation.
 */
export async function verifyConfidentialClientCredentials(
    c: any,
    clientContext: AuthenticatedClientContext
): Promise<{ success: true } | { success: false; response: Response }> {
    const { canonicalClientId, clientDoc, reqToForward, authMethod, clientSecret } = clientContext;
    const probeUrl = new URL("/api/auth/oauth2/introspect", c.req.raw.url).toString();
    const isPostAuth = authMethod === "client_secret_post" ||
        clientDoc?.tokenEndpointAuthMethod === "client_secret_post" ||
        clientDoc?.token_endpoint_auth_method === "client_secret_post";

    let probeBody: string;
    const probeHeaders = new Headers(reqToForward.headers);
    probeHeaders.set("Content-Type", "application/x-www-form-urlencoded");

    if (isPostAuth) {
        probeHeaders.delete("authorization");
        probeBody = new URLSearchParams({
            token: "swyra_credential_probe_sentinel",
            client_id: canonicalClientId,
            client_secret: clientSecret || "",
        }).toString();
    } else {
        probeBody = "token=swyra_credential_probe_sentinel";
    }

    const probeRequest = new Request(probeUrl, {
        method: "POST",
        headers: probeHeaders,
        body: probeBody,
    });

    const probeRes = await authProvider.handler(probeRequest);
    if (probeRes.status !== 200) {
        const errorBody = await probeRes.clone().json().catch(() => ({
            error: "invalid_client",
            error_description: "Client authentication failed",
        }));
        const headers: Record<string, string> = {};
        const wwwAuth = probeRes.headers.get("www-authenticate");
        if (wwwAuth) {
            headers["WWW-Authenticate"] = wwwAuth;
        } else if (!isPostAuth && reqToForward.headers.get("authorization")?.toLowerCase().startsWith("basic ")) {
            headers["WWW-Authenticate"] = 'Basic realm="OAuth"';
        }
        return {
            success: false,
            response: c.json(errorBody, probeRes.status, headers),
        };
    }

    return { success: true };
}
