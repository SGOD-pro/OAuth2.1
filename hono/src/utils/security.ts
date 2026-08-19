import { config } from "../config";

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
  options: { isDev?: boolean; env?: string } = {},
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
      if (options.isDev) {
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
  options: { isDev?: boolean; env?: string } = {},
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
    return xff ? xff.split(",")[0].trim() : (singleHop || "127.0.0.1");
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
