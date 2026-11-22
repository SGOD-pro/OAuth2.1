import { config } from "../config";

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

export function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : protocol === "http:" ? "80" : "";
}

export function ipMatchesCidr(ip: string, cidr: string): boolean {
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

export function ipv4ToNumber(ip: string): number | null {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
  const parts = ip.split(".").map(Number);
  if (parts.some((part) => part > 255)) return null;
  return parts.reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
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
    return "unknown";
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

  return chain[0] ?? "unknown";
}

export function getHeaders(c: any): Headers {
  if (c?.req?.raw?.headers) return c.req.raw.headers;
  if (c?.req?.header) return new Headers(c.req.header());
  return new Headers();
}
