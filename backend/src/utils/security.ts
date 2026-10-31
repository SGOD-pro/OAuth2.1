import crypto from "node:crypto";
import { config } from "../config";
import { ObjectId } from "mongodb";

/**
 * True if hostname is strictly a local loopback interface (localhost, 127.0.0.1, ::1).
 * RFC 8252 permits loopback redirect URIs for local application development.
 */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".localhost")
  ) {
    return true;
  }
  if (host.startsWith("::ffff:")) {
    const rest = host.slice(7);
    if (rest.includes(".")) {
      return rest === "127.0.0.1" || rest.startsWith("127.");
    }
    const parts = rest.split(":");
    if (parts.length === 2) {
      const w1 = parseInt(parts[0], 16);
      return !isNaN(w1) && ((w1 >> 8) & 0xff) === 127;
    }
  }
  return false;
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

export interface TargetOAuthClientConfig {
  client_name?: string;
  name?: string;
  redirect_uris?: string[];
  redirectUris?: string[];
  allowed_origins?: string[];
  allowedOrigins?: string[];
  isDev?: boolean;
  is_dev?: boolean;
  isPublic?: boolean;
  is_public?: boolean;
  application_type?: string;
  applicationType?: string;
  [key: string]: any;
}

export interface ClientConfigValidationOptions {
  serverEnvironment?: string;
  isNewClient?: boolean;
  allowDevClientsInProduction?: boolean;
  /**
   * Set to true when the caller is a verified Super Admin.
   * When true AND all redirect URIs are strict loopback (localhost, 127.0.0.1, ::1),
   * a new isDev=true client may be created on a production IdP without requiring
   * ALLOW_DEV_CLIENTS_IN_PRODUCTION=true globally.
   */
  isSuperAdminOp?: boolean;
}

export interface ClientConfigValidationResult {
  valid: boolean;
  error?: string;
  effectiveRedirectUris: string[];
  effectiveAllowedOrigins: string[];
  effectiveIsDev: boolean;
  effectiveIsPublic: boolean;
  effectiveApplicationType: "native" | "web";
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
 * Central Policy Function: Validates OAuth client configuration across
 * IdP server environment (NODE_ENV) and target OAuth client mode (isDev).
 *
 * Enforces per-client security boundary:
 * - Production client (isDev: false): strictly HTTPS, zero loopback, zero private/intranet IPs.
 * - Development client (isDev: true): dual mode permitted (strict loopback URIs and valid public HTTPS URIs),
 *   while non-loopback HTTP and private/intranet IPs remain strictly forbidden.
 * - Application type is automatically resolved to "native" when loopback or dev mode is active.
 * - isDev and isPublic remain completely independent.
 */
export function validateOAuthClientConfiguration(
  targetState: TargetOAuthClientConfig,
  options: ClientConfigValidationOptions = {},
): ClientConfigValidationResult {
  const serverEnv = options.serverEnvironment ?? config.env;
  const isNewClient = Boolean(options.isNewClient);
  const allowDevInProd = options.allowDevClientsInProduction ?? config.allowDevClientsInProduction;

  const effectiveIsDev = Boolean(targetState.isDev ?? targetState.is_dev);
  const effectiveIsPublic = targetState.isPublic !== false && targetState.is_public !== false;

  const rawRedirectUris = targetState.redirect_uris || targetState.redirectUris;
  const effectiveRedirectUris = Array.isArray(rawRedirectUris) ? rawRedirectUris : [];

  const rawAllowedOrigins = targetState.allowed_origins || targetState.allowedOrigins;
  let effectiveAllowedOrigins = Array.isArray(rawAllowedOrigins) ? [...rawAllowedOrigins] : [];

  // Automatically derive allowed CORS origins from redirect URIs if empty or omitted
  if (effectiveAllowedOrigins.length === 0 && effectiveRedirectUris.length > 0) {
    effectiveAllowedOrigins = deriveAllowedOriginsFromRedirectUris(effectiveRedirectUris);
  }

  const defaultFailResult: ClientConfigValidationResult = {
    valid: false,
    effectiveRedirectUris,
    effectiveAllowedOrigins,
    effectiveIsDev,
    effectiveIsPublic,
    effectiveApplicationType: "web",
  };

  // Must have at least one redirect URI
  if (effectiveRedirectUris.length === 0) {
    return {
      ...defaultFailResult,
      error: "At least one redirect URI is required",
    };
  }

  // When creating a new client in production with isDev=true:
  // - If caller is a verified Super Admin (isSuperAdminOp=true): permit.
  // - Otherwise, fail closed unless ALLOW_DEV_CLIENTS_IN_PRODUCTION=true is explicitly set.
  if (isNewClient && serverEnv === "production" && effectiveIsDev) {
    if (!options.isSuperAdminOp && !allowDevInProd) {
      return {
        ...defaultFailResult,
        error: "Only Super Admins may create new OAuth clients in development mode.",
      };
    }
  }

  // Validate redirect URIs against target client configuration
  for (const uri of effectiveRedirectUris) {
    if (!uri || typeof uri !== "string") {
      return { ...defaultFailResult, error: "Redirect URI must be a non-empty string" };
    }
    if (uri.includes("*")) {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Wildcards are strictly forbidden.` };
    }
    if (uri.includes("#")) {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Redirection endpoint URI MUST NOT include a fragment component.` };
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(uri);
    } catch {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Must be a valid URL.` };
    }

    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Scheme must be http: or https:.` };
    }
    if (parsedUrl.username || parsedUrl.password) {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Userinfo components are strictly forbidden.` };
    }
    if (!parsedUrl.hostname) {
      return { ...defaultFailResult, error: `Invalid redirect URI: "${uri}". Missing hostname.` };
    }

    const isLoopback = isLoopbackHost(parsedUrl.hostname);
    const isPrivate = isPrivateOrLocalHost(parsedUrl.hostname);

    if (effectiveIsDev) {
      // Development client: permits loopback (http/https) and valid public HTTPS
      if (!isLoopback) {
        if (parsedUrl.protocol !== "https:") {
          return {
            ...defaultFailResult,
            error: `Invalid redirect URI: "${uri}". Non-loopback redirect URIs must use HTTPS.`,
          };
        }
        if (isPrivate) {
          return {
            ...defaultFailResult,
            error: `Invalid redirect URI: "${uri}". Private and intranet IP addresses are forbidden.`,
          };
        }
      }
    } else {
      // Production client: strictly HTTPS, zero loopback, zero private IPs
      if (isLoopback) {
        return {
          ...defaultFailResult,
          error: "Loopback redirect URIs are permitted only for development-mode OAuth clients. Switch the application to Development Mode or provide HTTPS redirect URIs.",
        };
      }
      if (isPrivate) {
        return {
          ...defaultFailResult,
          error: `Invalid redirect URI: "${uri}". Private and intranet IP addresses are forbidden.`,
        };
      }
      if (parsedUrl.protocol !== "https:") {
        return {
          ...defaultFailResult,
          error: `Invalid redirect URI: "${uri}". Production OAuth clients require HTTPS redirect URIs.`,
        };
      }
    }
  }

  // Validate allowed origins against target client configuration
  for (const origin of effectiveAllowedOrigins) {
    if (!origin || typeof origin !== "string") {
      return { ...defaultFailResult, error: "Allowed origin must be a non-empty string" };
    }
    if (origin.includes("*")) {
      return { ...defaultFailResult, error: `Invalid allowed origin: "${origin}". Wildcards are strictly forbidden.` };
    }
    if (origin.includes("#")) {
      return { ...defaultFailResult, error: `Invalid allowed origin: "${origin}". Fragments are forbidden.` };
    }

    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(origin);
    } catch {
      return { ...defaultFailResult, error: `Invalid allowed origin: "${origin}". Must be a valid URL.` };
    }

    if (parsedOrigin.protocol !== "http:" && parsedOrigin.protocol !== "https:") {
      return { ...defaultFailResult, error: `Invalid allowed origin: "${origin}". Scheme must be http: or https:.` };
    }
    if (parsedOrigin.username || parsedOrigin.password) {
      return { ...defaultFailResult, error: `Invalid allowed origin: "${origin}". Userinfo components are forbidden.` };
    }

    const isLoopback = isLoopbackHost(parsedOrigin.hostname);
    const isPrivate = isPrivateOrLocalHost(parsedOrigin.hostname);

    if (effectiveIsDev) {
      // Development client: permits loopback (http/https) and valid public HTTPS
      if (!isLoopback) {
        if (parsedOrigin.protocol !== "https:") {
          return {
            ...defaultFailResult,
            error: `Invalid allowed origin: "${origin}". Non-loopback CORS origins must use HTTPS.`,
          };
        }
        if (isPrivate) {
          return {
            ...defaultFailResult,
            error: `Invalid allowed origin: "${origin}". Private and intranet IP addresses are forbidden.`,
          };
        }
      }
    } else {
      // Production client: strictly HTTPS, zero loopback, zero private IPs
      if (isLoopback) {
        return {
          ...defaultFailResult,
          error: "Loopback origins are permitted only for development-mode OAuth clients. Switch the application to Development Mode or provide HTTPS origins.",
        };
      }
      if (isPrivate) {
        return {
          ...defaultFailResult,
          error: `Invalid allowed origin: "${origin}". Private and intranet IP addresses are forbidden.`,
        };
      }
      if (parsedOrigin.protocol !== "https:") {
        return {
          ...defaultFailResult,
          error: `Invalid allowed origin: "${origin}". Production OAuth clients require HTTPS allowed origins.`,
        };
      }
    }
  }

  // Application type determination
  const hasLoopback = effectiveRedirectUris.some((u) => {
    try {
      const parsed = new URL(u);
      return isLoopbackHost(parsed.hostname) || parsed.protocol === "http:";
    } catch {
      return false;
    }
  });

  const effectiveApplicationType: "native" | "web" = (effectiveIsDev || hasLoopback) ? "native" : "web";
  const requestedAppType = targetState.application_type || targetState.applicationType;
  if (requestedAppType === "web" && effectiveApplicationType === "native") {
    console.info("[CLIENT_CONFIG] Requested application_type 'web' overridden to 'native' per RFC 8252 for development/loopback client.");
  }

  return {
    valid: true,
    effectiveRedirectUris,
    effectiveAllowedOrigins,
    effectiveIsDev,
    effectiveIsPublic,
    effectiveApplicationType,
  };
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

  // IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1 or ::ffff:c0a8:101)
  if (host.startsWith("::ffff:")) {
    const rest = host.slice(7);
    if (rest.includes(".")) {
      return isPrivateOrLocalHost(rest);
    }
    const parts = rest.split(":");
    if (parts.length === 2) {
      const w1 = parseInt(parts[0], 16);
      const w2 = parseInt(parts[1], 16);
      if (!isNaN(w1) && !isNaN(w2)) {
        const ipv4 = `${(w1 >> 8) & 0xff}.${w1 & 0xff}.${(w2 >> 8) & 0xff}.${w2 & 0xff}`;
        return isPrivateOrLocalHost(ipv4);
      }
    }
    return true; // Unknown/malformed ::ffff: mapped address, fail closed
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
  const name = String(rawClient.name || rawClient.client_name || "Application").trim();
  const clientSecret = rawClient.clientSecret || rawClient.client_secret;
  const skipConsent = Boolean(rawClient.skipConsent || rawClient.skip_consent);

  return {
    ...rawClient,
    id: canonicalId,
    clientId: canonicalId,
    client_id: canonicalId,
    name,
    client_name: name,
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
 * Detects whether an object or array contains dangerous MongoDB operator keys
 * (keys starting with '$'), dotted path keys (containing '.'), or prototype pollution keys.
 */
export function hasDangerousMongoKeys(input: any): boolean {
  if (!input || typeof input !== "object") return false;

  if (Array.isArray(input)) {
    for (const item of input) {
      if (hasDangerousMongoKeys(item)) return true;
    }
    return false;
  }

  for (const key of Object.keys(input)) {
    if (
      key.startsWith("$") ||
      key.includes(".") ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    ) {
      return true;
    }
    if (typeof input[key] === "object" && input[key] !== null) {
      if (hasDangerousMongoKeys(input[key])) return true;
    }
  }

  return false;
}

/**
 * Validates that an input is a safe non-empty primitive string without operator characters.
 */
export function validateSafePrimitiveString(
  val: any,
  fieldName: string = "parameter",
  options: { minLength?: number; maxLength?: number; allowEmpty?: boolean } = {}
): string | null {
  if (typeof val !== "string") {
    return null;
  }
  const trimmed = val.trim();
  if (!options.allowEmpty && trimmed.length === 0) {
    return null;
  }
  if (options.minLength && trimmed.length < options.minLength) {
    return null;
  }
  if (options.maxLength && trimmed.length > options.maxLength) {
    return null;
  }
  if (trimmed.startsWith("$") || trimmed.includes("\0")) {
    return null;
  }
  return trimmed;
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
  if (typeof userId !== "string" || typeof canonicalClientId !== "string") return false;
  const cleanUserId = userId.trim();
  const cleanClientId = canonicalClientId.trim();
  if (!cleanUserId || !cleanClientId || cleanUserId.startsWith("$") || cleanClientId.startsWith("$")) {
    return false;
  }

  const userConditions: any[] = [
    { userId: cleanUserId },
  ];
  if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(cleanUserId) });
    } catch {}
  }

  const reg = await db.collection("user_app_registrations").findOne({
    clientId: cleanClientId,
    $or: userConditions,
    status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    revoked: { $ne: true },
    disabled: { $ne: true },
    isActive: { $ne: false },
    active: { $ne: false },
  });

  return Boolean(reg);
}

/**
 * Authoritative check for user access to an application.
 *
 * Rules:
 * 1. Super Admin has NO bypass or membership in consumer applications.
 * 2. Explicit revocation/suspension/deactivation in EITHER user_app_registrations
 *    OR app_admins strictly and immediately denies access.
 * 3. Active registration in user_app_registrations grants access.
 * 4. Active administrator record in app_admins grants access.
 * 5. A removed, revoked, or non-existent assignment CANNOT regain access
 *    through user.scopedClientId or cached claims.
 */
export async function checkUserHasAppAccess(
  db: any,
  userOrId: any,
  canonicalClientId: string,
): Promise<boolean> {
  if (!db || !userOrId || !canonicalClientId) return false;
  const cleanClientId = typeof canonicalClientId === "string" ? canonicalClientId.trim() : "";
  if (!cleanClientId || cleanClientId.startsWith("$")) return false;

  const userDoc = typeof userOrId === "object" ? userOrId : null;
  const userIdStr = (
    typeof userOrId === "string"
      ? userOrId
      : (userDoc?.id || userDoc?._id || userDoc?.userId)?.toString()
  ) || "";
  const cleanUserId = userIdStr.trim();
  if (!cleanUserId || cleanUserId.startsWith("$")) return false;

  // USER-REQUIRED POLICY: Super Admin has NO bypass or membership in consumer applications
  if (userDoc) {
    if (userDoc.role === "super-admin" && userDoc.scopedClientId === null) return false;
    if (userDoc.role === "admin" && userDoc.scopedClientId === null) return false;
  }

  const userConditions: any[] = [{ userId: cleanUserId }];
  if (ObjectId.isValid(cleanUserId) && cleanUserId.length === 24) {
    try {
      userConditions.push({ userId: new ObjectId(cleanUserId) });
    } catch {}
  }

  const adminConditions: any[] = [...userConditions];
  if (userDoc?.email && typeof userDoc.email === "string") {
    adminConditions.push({ email: userDoc.email.toLowerCase().trim() });
  }

  const inactiveConditions = [
    { isActive: false },
    { active: false },
    { disabled: true },
    { revoked: true },
    { status: { $in: ["inactive", "revoked", "suspended", "disabled"] } },
  ];

  // 1. Explicit revocation in user_app_registrations
  const revokedReg = await db.collection("user_app_registrations").findOne({
    clientId: cleanClientId,
    $or: userConditions,
    $and: [{ $or: inactiveConditions }],
  });
  if (revokedReg) return false;

  // 2. Explicit revocation in app_admins
  const revokedAdmin = await db.collection("app_admins").findOne({
    clientId: cleanClientId,
    $or: adminConditions,
    $and: [{ $or: inactiveConditions }],
  });
  if (revokedAdmin) return false;

  // 3. Active registration in user_app_registrations
  const activeReg = await db.collection("user_app_registrations").findOne({
    clientId: cleanClientId,
    $or: userConditions,
    status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    revoked: { $ne: true },
    disabled: { $ne: true },
    isActive: { $ne: false },
    active: { $ne: false },
  });
  if (activeReg) return true;

  // 4. Active admin in app_admins
  const activeAdmin = await db.collection("app_admins").findOne({
    clientId: cleanClientId,
    $or: adminConditions,
    status: { $nin: ["inactive", "revoked", "suspended", "disabled"] },
    revoked: { $ne: true },
    disabled: { $ne: true },
    isActive: { $ne: false },
    active: { $ne: false },
  });
  if (activeAdmin) return true;

  // 5. Removed or non-existent assignment: scopedClientId alone NEVER grants access
  return false;
}

/**
 * Computes a SHA-256 hash formatted as base64url or hex.
 * Centralizes token hash generation for OAuth credentials.
 */
export function hashToken(
  token: string,
  encoding: "base64url" | "hex" = "base64url",
): string {
  return crypto.createHash("sha256").update(token).digest(encoding);
}
