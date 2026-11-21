import { Buffer } from "node:buffer";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";

export interface MfaEnrollmentResult {
  cookie: string;
  rawSecret: string;
  b32Secret: string;
}

export async function enrollAndLoginAdminMfa(
  app: any,
  email: string,
  pass: string,
  getTestHeaders?: (custom?: Record<string, string>) => any
): Promise<string> {
  const res = await enrollAndLoginAdminMfaWithSecret(app, email, pass, getTestHeaders);
  return res.cookie;
}

function getCookieFromHeaders(headers: any, nameSubstring: string): string {
  const list: string[] = (headers as any).getSetCookie
    ? (headers as any).getSetCookie()
    : (headers.get("set-cookie") ? [headers.get("set-cookie")] : []);

  for (const item of list) {
    const subItems = item.split(/,(?=\s*[^;]+=[^;]+)/);
    for (const sub of subItems) {
      const trimmed = sub.trim().split(";")[0].trim();
      if (trimmed.includes(nameSubstring)) {
        return trimmed;
      }
    }
  }
  return "";
}

export async function enrollAndLoginAdminMfaWithSecret(
  app: any,
  email: string,
  pass: string,
  getTestHeaders?: (custom?: Record<string, string>) => any
): Promise<MfaEnrollmentResult> {
  const getHeaders = (custom: Record<string, string> = {}) => {
    const base = getTestHeaders ? getTestHeaders(custom) : {};
    const res: Record<string, string> = {};
    const setKey = (k: string, v: string) => {
      for (const existingKey of Object.keys(res)) {
        if (existingKey.toLowerCase() === k.toLowerCase()) {
          delete res[existingKey];
        }
      }
      res[k] = v;
    };

    setKey("Content-Type", "application/json");
    setKey("x-forwarded-for", "127.0.0.1, 10.0.0.1");
    setKey("x-gateway-secret", process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32));
    setKey("Origin", process.env.FRONTEND_URL || "https://oauth21.vercel.app");
    setKey("x-csrf-token", "any");

    if (base instanceof Headers) {
      base.forEach((v, k) => {
        setKey(k, v);
      });
    } else if (typeof base === "object" && base !== null) {
      for (const [k, v] of Object.entries(base)) {
        setKey(k, v as string);
      }
    }
    for (const [k, v] of Object.entries(custom)) {
      setKey(k, v);
    }
    return res;
  };

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  const preCookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  const enableRes = await app.request("/api/auth/two-factor/enable", {
    method: "POST",
    headers: getHeaders({ Cookie: preCookie }),
    body: JSON.stringify({ password: pass }),
  });
  const enableData = await enableRes.json();
  const b32Secret = new URL(enableData.totpURI).searchParams.get("secret")!;
  const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();

  const enrollOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getHeaders({ Cookie: preCookie }),
    body: JSON.stringify({ code: enrollOtp }),
  });

  const challengeLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  const challengeCookie = getCookieFromHeaders(challengeLoginRes.headers, "two_factor=");

  const challengeOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  const verifyChallengeRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getHeaders({ Cookie: challengeCookie }),
    body: JSON.stringify({ code: challengeOtp }),
  });
  const cookie = getCookieFromHeaders(verifyChallengeRes.headers, "session_token=");

  return { cookie, rawSecret, b32Secret };
}

export async function loginEnrolledAdminMfa(
  app: any,
  email: string,
  pass: string,
  rawSecret: string,
  getTestHeaders?: (custom?: Record<string, string>) => any
): Promise<string> {
  const getHeaders = (custom: Record<string, string> = {}) => {
    if (getTestHeaders) return getTestHeaders(custom);
    return {
      "Content-Type": "application/json",
      "x-forwarded-for": "127.0.0.1, 10.0.0.1",
      "x-gateway-secret": process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32),
      Origin: process.env.FRONTEND_URL || "https://oauth21.vercel.app",
      "x-csrf-token": "any",
      ...custom,
    };
  };

  const challengeLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getHeaders({ "content-type": "application/json" }),
    body: JSON.stringify({ email, password: pass }),
  });
  const challengeCookie = getCookieFromHeaders(challengeLoginRes.headers, "two_factor=");

  const challengeOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  const verifyChallengeRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: getHeaders({ Cookie: challengeCookie, "content-type": "application/json" }),
    body: JSON.stringify({ code: challengeOtp }),
  });
  return getCookieFromHeaders(verifyChallengeRes.headers, "session_token=");
}
