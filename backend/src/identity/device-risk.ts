import crypto from "node:crypto";
import { config } from "../config";
import { getTrustedClientIp } from "../utils/security";

export const DEVICE_BINDING_COOKIE = "swyra_device_id";

export interface CoarseDeviceSignals {
  deviceKeyDigest: string | null;
  uaFamily: string;
  ipPrefix: string;
}

export type DeviceRiskLevel = "normal" | "elevated" | "high";

export interface DeviceRiskAssessment {
  level: DeviceRiskLevel;
  reasons: string[];
}

export function digestDeviceId(rawDeviceId: string): string {
  return crypto
    .createHmac("sha256", `${config.auth.secret}:device-binding-v1`)
    .update(rawDeviceId)
    .digest("hex");
}

export function parseCoarseUaFamily(uaRaw: string | null | undefined): string {
  const ua = (uaRaw || "").toLowerCase();
  if (!ua) return "unknown";
  const browser = ua.includes("edg/") ? "edge"
    : ua.includes("chrome/") || ua.includes("chromium/") ? "chrome"
    : ua.includes("firefox/") ? "firefox"
    : ua.includes("safari/") ? "safari"
    : ua.includes("curl/") ? "curl"
    : "other";
  const os = ua.includes("windows") ? "windows"
    : ua.includes("mac os") || ua.includes("macintosh") ? "macos"
    : ua.includes("linux") ? "linux"
    : ua.includes("android") ? "android"
    : ua.includes("iphone") || ua.includes("ipad") ? "ios"
    : "other";
  return `${browser}:${os}`;
}

export function parseCoarseIpPrefix(ipRaw: string | null | undefined): string {
  const ip = (ipRaw || "").trim();
  if (!ip || ip === "unknown") return "unknown";
  if (ip.includes(".")) {
    const parts = ip.split(".");
    return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : "unknown";
  }
  if (ip.includes(":")) {
    const parts = ip.split(":").slice(0, 3);
    return `${parts.join(":")}::/48`;
  }
  return "unknown";
}

export function extractCoarseDeviceSignals(
  headers: Headers,
  rawDeviceCookie: string | undefined,
  trustedProxyCidrs: string[] = config.trustedProxyCidrs
): CoarseDeviceSignals {
  const ip = getTrustedClientIp(headers, trustedProxyCidrs);
  const cleanCookie = rawDeviceCookie?.trim();
  return {
    deviceKeyDigest: cleanCookie && cleanCookie.length >= 16 ? digestDeviceId(cleanCookie) : null,
    uaFamily: parseCoarseUaFamily(headers.get("user-agent")),
    ipPrefix: parseCoarseIpPrefix(ip),
  };
}

/**
 * Evaluates stolen-session / replay risk using coarse, resettable signals.
 * - VPN/IP drift alone with matching device cookie -> normal.
 * - Missing/mismatched device cookie + same UA family + same IP prefix -> normal (cookie reset).
 * - Missing/mismatched device cookie + changed UA family -> elevated (step-up + alert).
 * - Missing/mismatched device cookie + changed UA family + changed IP prefix -> high (revoke + deny).
 */
export function evaluateSessionDeviceRisk(params: {
  bound: CoarseDeviceSignals | null | undefined;
  current: CoarseDeviceSignals;
}): DeviceRiskAssessment {
  const { bound, current } = params;
  if (!bound || !bound.deviceKeyDigest) {
    return { level: "normal", reasons: [] };
  }
  if (current.deviceKeyDigest && current.deviceKeyDigest === bound.deviceKeyDigest) {
    return { level: "normal", reasons: [] };
  }

  const reasons: string[] = [current.deviceKeyDigest ? "device_cookie_mismatch" : "device_cookie_missing"];
  const uaChanged = bound.uaFamily !== "unknown" && current.uaFamily !== "unknown" && bound.uaFamily !== current.uaFamily;
  const ipChanged = bound.ipPrefix !== "unknown" && current.ipPrefix !== "unknown" && bound.ipPrefix !== current.ipPrefix;

  if (uaChanged) reasons.push("ua_family_changed");
  if (ipChanged) reasons.push("ip_prefix_changed");

  if (uaChanged && ipChanged) {
    return { level: "high", reasons };
  }
  if (uaChanged) {
    return { level: "elevated", reasons };
  }
  return { level: "normal", reasons };
}
