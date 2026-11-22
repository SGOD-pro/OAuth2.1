import { ObjectId } from "mongodb";
import { isLoopbackHost, isPrivateOrLocalHost, defaultPort } from "./network-security";

export interface CanonicalOAuthClient {
  _id: any;
  id: string;
  clientId: string;
  client_id?: string;
  clientSecret?: string;
  client_secret?: string;
  name: string;
  client_name?: string;
  redirectUris: string[];
  redirect_uris?: string[];
  allowedOrigins: string[];
  allowed_origins?: string[];
  disabled: boolean;
  isDev: boolean;
  is_dev?: boolean;
  isPublic: boolean;
  is_public?: boolean;
  skipConsent: boolean;
  skip_consent?: boolean;
  [key: string]: any;
}

/**
 * Validate an OAuth redirect URI (or allowed origin URL) before persistence.
 * Rejects non-http(s), wildcards, credentials-in-URL, and private-network
 * hosts in production (see docs/SECURITY.md and docs/ARCHITECTURE.md).
 *
 * If isDev is true in production, loopback addresses (localhost/127.0.0.1)
 * are permitted per RFC 8252, while intranet/private IPs remain blocked.
 */
export function validateRedirectUri(
  uri: string,
  options: { isDev?: boolean; env?: string; allowDevInProd?: boolean } = {},
): boolean {
  try {
    const url = new URL(uri);

    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    if (uri.includes("*")) return false;
    if (uri.includes("#")) return false;
    // userinfo enables open-redirect tricks
    if (url.username || url.password) return false;
    if (!url.hostname) return false;

    const isLoopback = isLoopbackHost(url.hostname);
    const isPrivate = isPrivateOrLocalHost(url.hostname);

    if (options.isDev) {
      if (options.env === "production" && options.allowDevInProd === false) {
        return false;
      }
      if (isLoopback) {
        return true;
      }
      if (url.protocol !== "https:") return false;
      if (isPrivate) return false;
      return true;
    } else {
      if (isLoopback) return false;
      if (url.protocol !== "https:") return false;
      if (isPrivate) return false;
      return true;
    }
  } catch {
    return false;
  }
}

export function validateRedirectUris(
  uris: string[],
  options: { isDev?: boolean; env?: string; allowDevInProd?: boolean } = {},
): string | null {
  for (const uri of uris) {
    if (!validateRedirectUri(uri, options)) return uri;
  }
  return null;
}

/**
 * Automatically derive allowed CORS origins from redirect URIs.
 * Extracts unique web origins (http:// and https:// with host and optional port).
 * Non web schemes (for example, custom mobile app schemes like myapp://callback) are safely skipped.
 */
export function deriveAllowedOriginsFromRedirectUris(redirectUris: string[]): string[] {
  if (!Array.isArray(redirectUris)) return [];

  const originsSet = new Set<string>();

  for (const uri of redirectUris) {
    if (!uri || typeof uri !== "string") continue;
    try {
      const parsed = new URL(uri.trim());
      // Only http and https protocols generate valid web CORS origins
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        if (parsed.origin && parsed.origin !== "null") {
          originsSet.add(parsed.origin);
        }
      }
    } catch {
      // Invalid URL syntax is safely skipped during origin derivation
    }
  }

  return Array.from(originsSet);
}

/**
 * Exact origin equality: parse redirect URI and compare scheme+host+port
 * to the request Origin. Prefix/regex matching is unsafe
 * (e.g. origin https://evil.co matching https://evil.com/...).
 */
export function originMatchesRedirectUri(
  origin: string,
  redirectUri: string,
): boolean {
  try {
    const originUrl = new URL(origin);
    const redirectUrl = new URL(redirectUri);

    if (originUrl.protocol !== redirectUrl.protocol) return false;
    if (originUrl.hostname.toLowerCase() !== redirectUrl.hostname.toLowerCase()) {
      return false;
    }

    const originPort = originUrl.port || defaultPort(originUrl.protocol);
    const redirectPort = redirectUrl.port || defaultPort(redirectUrl.protocol);
    return originPort === redirectPort;
  } catch {
    return false;
  }
}

export function normalizeOrigin(origin: string): string | null {
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    if (url.pathname !== "/" || url.search || url.hash) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * Normalize OAuth client configuration fields so both camelCase and snake_case properties
 * are present, consistent, and cleanly resolved across all data stores and route handlers.
 */
export function normalizeOAuthClientFields<T extends Record<string, any>>(rawClient: T): T & CanonicalOAuthClient {
  if (!rawClient || typeof rawClient !== "object") return rawClient as any;

  const canonicalId = String(rawClient.clientId || rawClient.client_id || rawClient.id || rawClient._id || "");
  const redirectUris = (rawClient.redirectUris || rawClient.redirect_uris || []) as string[];
  const rawOrigins = (rawClient.allowedOrigins || rawClient.allowed_origins || []) as string[];
  const allowedOrigins = rawOrigins.length > 0 ? rawOrigins : deriveAllowedOriginsFromRedirectUris(redirectUris);
  const isPublic = rawClient.isPublic !== false && rawClient.is_public !== false;
  const isDev = Boolean(rawClient.isDev || rawClient.is_dev);
  const disabled = Boolean(rawClient.disabled);
  const name = String(rawClient.name || rawClient.client_name || rawClient.clientName || "Application").trim();
  const clientSecret = rawClient.clientSecret || rawClient.client_secret;
  const skipConsent = Boolean(rawClient.skipConsent || rawClient.skip_consent);

  return {
    ...rawClient,
    id: canonicalId,
    clientId: canonicalId,
    client_id: canonicalId,
    name,
    client_name: name,
    clientName: name,
    redirectUris,
    redirect_uris: redirectUris,
    allowedOrigins,
    allowed_origins: allowedOrigins,
    isDev,
    is_dev: isDev,
    isPublic,
    is_public: isPublic,
    disabled,
    skipConsent,
    skip_consent: skipConsent,
    ...(clientSecret ? { clientSecret, client_secret: clientSecret } : {}),
  } as any;
}

/**
 * Resolve canonical OAuth client from database by id, clientId, or client_id.
 * Normalizes field names (clientId, redirectUris, isPublic, disabled).
 */
export async function resolveOAuthClient(
  db: any,
  clientIdOrId: string,
): Promise<CanonicalOAuthClient | null> {
  if (!clientIdOrId || typeof clientIdOrId !== "string") return null;

  const trimmed = clientIdOrId.trim();
  if (!trimmed) return null;

  const queries: any[] = [
    { clientId: trimmed },
    { client_id: trimmed },
    { id: trimmed },
  ];

  if (ObjectId.isValid(trimmed) && trimmed.length === 24) {
    try {
      queries.push({ _id: new ObjectId(trimmed) });
    } catch {}
  }

  const raw = await db.collection("oauthClient").findOne({
    $or: queries,
  });

  if (!raw) return null;

  return normalizeOAuthClientFields(raw);
}

/**
 * Check if the requested redirect URI matches one of the client's registered redirect URIs.
 * Strict exact matching is enforced per RFC 6749 Section 3.1.2 and OAuth 2.1:
 * - Scheme, host, port, path, and query string must match exactly.
 * - Fragment components ('#') are strictly forbidden per RFC 6749 Section 3.1.2.
 * - Userinfo components ('user:pass@') are strictly forbidden per RFC 6749 Section 3.1.2.
 * - Loopback addresses (localhost, 127.0.0.1, [::1]) may allow variable port ONLY if the client
 *   registered a loopback redirect URI per RFC 8252 Section 7.3.
 */
export function isRegisteredRedirectUri(
  client: CanonicalOAuthClient | null,
  redirectUri: string,
): boolean {
  if (!client || !redirectUri || typeof redirectUri !== "string" || !Array.isArray(client.redirectUris) || client.redirectUris.length === 0) {
    return false;
  }

  // RFC 6749 Section 3.1.2: Redirection endpoint URI MUST NOT include a fragment component
  if (redirectUri.includes("#")) {
    return false;
  }

  try {
    const targetUrl = new URL(redirectUri);

    // RFC 6749 Section 3.1.2: Redirection endpoint URI MUST NOT contain userinfo
    if (targetUrl.username || targetUrl.password) {
      return false;
    }

    const targetHostname = targetUrl.hostname.toLowerCase();

    return client.redirectUris.some((registered: string) => {
      try {
        if (registered.includes("#")) return false;
        const regUrl = new URL(registered);
        if (regUrl.username || regUrl.password) return false;

        // 1. Protocol must match exactly (e.g. https: vs http:)
        if (targetUrl.protocol !== regUrl.protocol) return false;

        // 2. Hostname must match exactly (case-insensitive, no trailing dot mismatches)
        const regHostname = regUrl.hostname.toLowerCase();
        if (targetHostname !== regHostname) return false;

        // 3. Port matching
        const targetPort = targetUrl.port || defaultPort(targetUrl.protocol);
        const regPort = regUrl.port || defaultPort(regUrl.protocol);

        const isLoopback = (
          regHostname === "localhost" ||
          regHostname === "127.0.0.1" ||
          regHostname === "[::1]"
        );

        // RFC 8252 Section 7.3: Native loopback clients may bind to variable ephemeral ports
        if (!isLoopback && targetPort !== regPort) {
          return false;
        }

        // 4. Pathname must match exactly (no trailing slash discrepancies)
        if (targetUrl.pathname !== regUrl.pathname) return false;

        // 5. Query string must match exactly (no arbitrary injected parameters)
        if (targetUrl.search !== regUrl.search) return false;

        return true;
      } catch {
        return false;
      }
    });
  } catch {
    return false;
  }
}
