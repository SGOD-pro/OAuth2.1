import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { config } from "../config";
import { getDb } from "../db/mongo";
import { getTrustedClientIp, hasDangerousMongoKeys } from "../utils/security";
import { completeVerifiedRegistration } from "../identity/registration-complete";
import { buildBrowserProofCookieOptions, getBrowserSessionCookieName } from "../identity/browser-session-registry";
import { computeBrowserBindingHash, computeUsernameLookup, digestToken, normalizeUsername } from "../identity/registration-crypto";
import { checkUsernameAvailability, type UsernameBloomFilter } from "../identity/username-bloom-filter";
import { BROWSER_COOKIE, PROOF_COOKIE, cookieSecurityOpts, getRequestId } from "./identity-registration-shared";

export interface UsernameCheckDeps {
  getDb?: () => Promise<any>;
  bloomFilter?: UsernameBloomFilter;
}

export function createUsernameCheckHandler(deps: UsernameCheckDeps = {}) {
  return (c: Context) => runUsernameCheck(c, deps);
}

export async function handleRegistrationComplete(c: Context): Promise<Response> {
  const requestId = getRequestId(c);
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_BODY", requestId }, 400);
  }

  const rawIp = getTrustedClientIp(c.req.raw.headers, config.trustedProxyCidrs);
  const clientIp = rawIp && rawIp !== "unknown" ? rawIp : null;
  const ua = c.req.header("user-agent");
  const userAgent = ua ? ua.slice(0, 128) : null;

  try {
    const result = await completeVerifiedRegistration({
      rawBrowser: getCookie(c, BROWSER_COOKIE),
      rawProof: getCookie(c, PROOF_COOKIE),
      rawBrowserSessionProof: getCookie(c, getBrowserSessionCookieName()),
      username: body.username,
      password: body.password,
      acceptedTermsVersion: body.acceptedTermsVersion,
      idempotencyKey: c.req.header("idempotency-key"),
      clientIp,
      userAgent,
      requestHeaders: c.req.raw.headers,
      requestId,
    });

    if (result.clearProofCookie) {
      setCookie(c, PROOF_COOKIE, "", cookieSecurityOpts(0, "/api/identity"));
    }
    if (result.nextBrowserSessionProof) {
      setCookie(c, getBrowserSessionCookieName(), result.nextBrowserSessionProof, buildBrowserProofCookieOptions() as any);
    }
    for (const cookieHeader of result.sessionSetCookies || []) {
      c.header("Set-Cookie", cookieHeader, { append: true });
    }
    return c.json(result.body, result.status as any);
  } catch (err: any) {
    console.error("[REG_COMPLETE] Unhandled transaction failure:", err?.message || err);
    return c.json({ error: "server_error", code: "ERR_REGISTRATION_FAILED", requestId }, 500);
  }
}

export async function handleUsernameCheck(c: Context): Promise<Response> {
  return runUsernameCheck(c, {});
}

async function runUsernameCheck(c: Context, deps: UsernameCheckDeps): Promise<Response> {
  const requestId = getRequestId(c);
  if (config.identity.registrationMode !== "verified") {
    return c.json({ error: "registration_disabled", code: "ERR_REGISTRATION_DISABLED", requestId }, 403);
  }
  const rawBrowser = getCookie(c, BROWSER_COOKIE);
  const rawProof = getCookie(c, PROOF_COOKIE);
  if (!rawBrowser || !rawProof) {
    return c.json({ error: "unauthorized", code: "ERR_PROOF_REQUIRED", requestId }, 403);
  }
  const body = await c.req.raw.clone().json().catch(() => null);
  if (!body || typeof body !== "object" || hasDangerousMongoKeys(body)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_BODY", requestId }, 400);
  }
  const parsed = normalizeUsername(body.username);
  if (!parsed) {
    return c.json({ available: false, reason: "invalid_syntax", requestId }, 400);
  }
  const database = await (deps.getDb ?? getDb)();
  const intent = await database.collection("registration_intents").findOne({
    browserBindingHash: computeBrowserBindingHash(rawBrowser),
    proofDigest: digestToken(rawProof, "proof"),
    status: "verified",
  });
  if (!intent || Date.now() >= new Date(intent.proofExpiresAt).getTime()) {
    return c.json({ error: "unauthorized", code: "ERR_PROOF_INVALID", requestId }, 403);
  }
  const lookup = computeUsernameLookup(parsed.normalized);
  const checked = await checkUsernameAvailability({
    database,
    normalizedUsername: parsed.normalized,
    keyedLookup: lookup,
    bloomFilter: deps.bloomFilter,
  });
  return c.json({ available: checked.available, normalizedUsername: parsed.normalized, requestId });
}
