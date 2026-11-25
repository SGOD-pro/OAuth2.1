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

let fixtureSessionCounter = 100;

function createFixtureHeadersBuilder(
  fixtureIp: string,
  getTestHeaders?: (custom?: Record<string, string>) => any
) {
  return (custom: Record<string, string> = {}) => {
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
    setKey("x-gateway-secret", process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32));
    setKey("Origin", process.env.FRONTEND_URL || "https://oauth21.vercel.app");
    setKey("x-csrf-token", "any");

    let callerHasIp = false;
    if (base instanceof Headers) {
      base.forEach((v, k) => {
        setKey(k, v);
        if (k.toLowerCase() === "x-forwarded-for") callerHasIp = true;
      });
    } else if (typeof base === "object" && base !== null) {
      for (const [k, v] of Object.entries(base)) {
        setKey(k, v as string);
        if (k.toLowerCase() === "x-forwarded-for") callerHasIp = true;
      }
    }

    for (const [k, v] of Object.entries(custom)) {
      setKey(k, v);
      if (k.toLowerCase() === "x-forwarded-for") callerHasIp = true;
    }

    if (!callerHasIp) {
      setKey("x-forwarded-for", `${fixtureIp}, 10.0.0.1`);
    }

    return res;
  };
}

export async function enrollAndLoginAdminMfaWithSecret(
  app: any,
  email: string,
  pass: string,
  getTestHeaders?: (custom?: Record<string, string>) => any
): Promise<MfaEnrollmentResult> {
  const sessionIpIndex = (++fixtureSessionCounter % 240) + 1;
  const fixtureIp = `198.51.100.${sessionIpIndex}`;
  const buildHeaders = createFixtureHeadersBuilder(fixtureIp, getTestHeaders);

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: buildHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  if (loginRes.status === 429) {
    const text = await loginRes.text();
    throw new Error(`Admin sign in rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!loginRes.ok) {
    const text = await loginRes.text();
    throw new Error(`Admin sign in failed (HTTP ${loginRes.status}) for ${email}: ${text}`);
  }
  const preCookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

  const enableRes = await app.request("/api/auth/two-factor/enable", {
    method: "POST",
    headers: buildHeaders({ Cookie: preCookie }),
    body: JSON.stringify({ password: pass }),
  });
  if (enableRes.status === 429) {
    const text = await enableRes.text();
    throw new Error(`Admin MFA enrollment rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!enableRes.ok) {
    const text = await enableRes.text();
    throw new Error(`Admin MFA enrollment failed (HTTP ${enableRes.status}) for ${email}: ${text}`);
  }
  const enableData = await enableRes.json();
  if (!enableData?.totpURI) {
    throw new Error(`Admin MFA enrollment response missing totpURI for ${email}: ${JSON.stringify(enableData)}`);
  }
  const b32Secret = new URL(enableData.totpURI).searchParams.get("secret");
  if (!b32Secret) {
    throw new Error(`Admin MFA totpURI missing secret parameter for ${email}`);
  }
  const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();

  // Use the previous time step for enrollment verification to avoid a replay collision
  // when the challenge sign-in and its verify-totp happen within the same 30-second window.
  const enrollOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).hotp(Math.floor(Date.now() / 30000) - 1);
  const verifyEnrollRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: buildHeaders({ Cookie: preCookie }),
    body: JSON.stringify({ code: enrollOtp }),
  });
  if (verifyEnrollRes.status === 429) {
    const text = await verifyEnrollRes.text();
    throw new Error(`Admin MFA verify rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!verifyEnrollRes.ok) {
    const text = await verifyEnrollRes.text();
    throw new Error(`Admin MFA verify failed (HTTP ${verifyEnrollRes.status}) for ${email}: ${text}`);
  }

  const challengeLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: buildHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  if (challengeLoginRes.status === 429) {
    const text = await challengeLoginRes.text();
    throw new Error(`Admin challenge sign in rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!challengeLoginRes.ok) {
    const text = await challengeLoginRes.text();
    throw new Error(`Admin challenge sign in failed (HTTP ${challengeLoginRes.status}) for ${email}: ${text}`);
  }
  const challengeCookie = getCookieFromHeaders(challengeLoginRes.headers, "two_factor=");

  const challengeOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  const verifyChallengeRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: buildHeaders({ Cookie: challengeCookie }),
    body: JSON.stringify({ code: challengeOtp }),
  });
  if (verifyChallengeRes.status === 429) {
    const text = await verifyChallengeRes.text();
    throw new Error(`Admin challenge verify rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!verifyChallengeRes.ok) {
    const text = await verifyChallengeRes.text();
    throw new Error(`Admin challenge verify failed (HTTP ${verifyChallengeRes.status}) for ${email}: ${text}`);
  }
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
  const sessionIpIndex = (++fixtureSessionCounter % 240) + 1;
  const fixtureIp = `198.51.100.${sessionIpIndex}`;
  const buildHeaders = createFixtureHeadersBuilder(fixtureIp, getTestHeaders);

  const challengeLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: buildHeaders(),
    body: JSON.stringify({ email, password: pass }),
  });
  if (challengeLoginRes.status === 429) {
    const text = await challengeLoginRes.text();
    throw new Error(`Admin MFA login rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!challengeLoginRes.ok) {
    const text = await challengeLoginRes.text();
    throw new Error(`Admin MFA login failed (HTTP ${challengeLoginRes.status}) for ${email}: ${text}`);
  }
  const challengeCookie = getCookieFromHeaders(challengeLoginRes.headers, "two_factor=");

  const challengeOtp = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  const verifyChallengeRes = await app.request("/api/auth/two-factor/verify-totp", {
    method: "POST",
    headers: buildHeaders({ Cookie: challengeCookie }),
    body: JSON.stringify({ code: challengeOtp }),
  });
  if (verifyChallengeRes.status === 429) {
    const text = await verifyChallengeRes.text();
    throw new Error(`Admin MFA login verify rate limited (HTTP 429) for ${email}: ${text}`);
  }
  if (!verifyChallengeRes.ok) {
    const text = await verifyChallengeRes.text();
    throw new Error(`Admin MFA login verify failed (HTTP ${verifyChallengeRes.status}) for ${email}: ${text}`);
  }
  return getCookieFromHeaders(verifyChallengeRes.headers, "session_token=");
}
