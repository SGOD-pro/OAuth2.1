import { config } from "../config";
import { ObjectId } from "mongodb";

/**
 * True if hostname is strictly a local loopback interface (localhost, 127.0.0.1, ::1).
 * RFC 8252 permits loopback redirect URIs for local application development.
 */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".localhost")
  );
}

/**
 * Validate an OAuth redirect URI (or allowed origin URL) before persistence.
 * Rejects non-http(s), wildcards, credentials-in-URL, and private-network
 * hosts in production (see boundaries.md / projectrequirement.md).
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
    // https://evil@legit.example/ ?" userinfo enables open-redirect tricks
    if (url.username || url.password) return false;
    if (!url.hostname) return false;

    const currentEnv = options.env ?? config.env;

    if (currentEnv === "production") {
      const allowDev = options.allowDevInProd !== undefined
        ? options.allowDevInProd
        : (process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION === "false" ? false : true);

      if (options.isDev && allowDev) {
        const isLoopback = isLoopbackHost(url.hostname);
        if (!isLoopback) {
          if (url.protocol !== "https:") return false;
          if (isPrivateOrLocalHost(url.hostname)) return false;
        }
      } else {
        if (url.protocol !== "https:") return false;
        if (isPrivateOrLocalHost(url.hostname)) return false;
      }
    }

    return true;
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

export function isStrongPassword(password: string): boolean {
  // Minimum 12 chars ?" must match emailAndPassword.minPasswordLength in auth.ts
  if (password.length < 12 || password.length > 128) return false;
  return (
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

export function safeCallbackURL(value: string | null): string | undefined {
  if (!value) return undefined;
  if (!value.startsWith("/") || value.startsWith("//")) return undefined;

  try {
    const url = new URL(value, "https://callback.invalid");
    if (url.origin !== "https://callback.invalid") return undefined;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return undefined;
  }
}

/** True if hostname is loopback, link-local, or RFC1918 / unique-local. */
export function isPrivateOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (
    host === "localhost" ||
    host === "0.0.0.0" ||
    host === "::" ||
    host === "::1" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return true;
  }

  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split(".").map(Number);
    if (parts.some((p) => p > 255)) return true;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local / AWS metadata
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }

  // IPv6 local / unique-local / link-local
  if (host.includes(":")) {
    if (host === "::1" || host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) {
      return true;
    }
  }

  return false;
}

export function getTrustedClientIp(
  source: any,
  trustedProxyCidrs: string[] = config.trustedProxyCidrs,
): string {
  let headers: Headers;
  if (source instanceof Headers) {
    headers = source;
  } else if (source?.req?.raw?.headers instanceof Headers) {
    headers = source.req.raw.headers;
  } else if (source?.headers instanceof Headers) {
    headers = source.headers;
  } else if (typeof source?.req?.header === "function") {
    headers = new Headers(source.req.header());
  } else {
    headers = new Headers();
  }

  const singleHop =
    headers.get("cf-connecting-ip") ??
    headers.get("true-client-ip") ??
    headers.get("x-real-ip");
  const xff = headers.get("x-forwarded-for");

  if (!xff && !singleHop) {
    return "127.0.0.1";
  }

  if (trustedProxyCidrs.length === 0) {
    return "unknown";
  }

  const chain = [
    ...(xff ? xff.split(",").map((ip) => ip.trim()).filter(Boolean) : []),
    ...(singleHop ? [singleHop.trim()] : []),
  ];

  for (let i = chain.length - 1; i >= 0; i--) {
    const ip = chain[i];
    if (!trustedProxyCidrs.some((cidr) => ipMatchesCidr(ip, cidr))) return ip;
  }

  return chain[0] ?? "127.0.0.1";
}

export function getHeaders(c: any): Headers {
  if (c?.req?.raw?.headers) return c.req.raw.headers;
  if (c?.req?.header) return new Headers(c.req.header());
  return new Headers();
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

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : protocol === "http:" ? "80" : "";
}

/** Constant-time string compare for CSRF tokens (equal length required). */
export function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function ipMatchesCidr(ip: string, cidr: string): boolean {
  const [range, bitsRaw] = cidr.split("/");
  if (!range) return false;
  if (!bitsRaw) return ip === range;

  const ipNum = ipv4ToNumber(ip);
  const rangeNum = ipv4ToNumber(range);
  const bits = Number(bitsRaw);
  if (ipNum === null || rangeNum === null || bits < 0 || bits > 32) return false;

  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}

function ipv4ToNumber(ip: string): number | null {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
  const parts = ip.split(".").map(Number);
  if (parts.some((part) => part > 255)) return null;
  return parts.reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
}

export interface CanonicalOAuthClient {
  _id: any;
  id: string;
  clientId: string;
  clientSecret?: string;
  client_secret?: string;
  name: string;
  redirectUris: string[];
  allowedOrigins: string[];
  disabled: boolean;
  isDev: boolean;
  isPublic: boolean;
  skipConsent: boolean;
  [key: string]: any;
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

  const canonicalId = raw.clientId || raw.client_id || raw.id || String(raw._id);
  const redirectUris = raw.redirectUris || raw.redirect_uris || [];
  const allowedOrigins = raw.allowedOrigins || raw.allowed_origins || [];
  const isPublic = raw.isPublic !== false && raw.is_public !== false;
  const disabled = Boolean(raw.disabled);

  return {
    ...raw,
    id: canonicalId,
    clientId: canonicalId,
    name: raw.name || raw.client_name || "Application",
    redirectUris,
    allowedOrigins,
    isPublic,
    disabled,
  };
}

/**
 * Check if the requested redirect URI matches one of the client's registered redirect URIs.
 * Exact matching of origin and pathname is enforced.
 */
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

/**
 * Check whether a user is registered for an application in user_app_registrations.
 * Uses authenticated server-side userId and canonical client ID.
 */
export async function checkUserAppRegistration(
  db: any,
  userId: string,
  canonicalClientId: string,
): Promise<boolean> {
  if (!userId || !canonicalClientId) return false;

  const reg = await db.collection("user_app_registrations").findOne({
    clientId: canonicalClientId,
    $or: [
      { userId: String(userId) },
      { userId },
      ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : []),
    ],
  });

  return Boolean(reg);
}
