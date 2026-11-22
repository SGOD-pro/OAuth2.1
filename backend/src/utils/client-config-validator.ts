import { config } from "../config";
import { isLoopbackHost, isPrivateOrLocalHost } from "./network-security";
import { deriveAllowedOriginsFromRedirectUris } from "./client-resolver";

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
