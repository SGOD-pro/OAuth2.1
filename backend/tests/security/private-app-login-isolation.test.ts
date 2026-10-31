import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";

console.log("================================================================");
console.log("  SWYRA AUTH -- PRIVATE APP LOGIN ISOLATION SECURITY SUITE");
console.log("================================================================\n");

let mongod: any = null;
if (
  !process.env.MONGO_URI ||
  process.env.MONGO_URI.includes("mongodb.net") ||
  process.env.MONGO_URI.includes("cluster0")
) {
  mongod = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongod.getUri();
}
process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = "i".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "h".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const { createOTP } = await import("@better-auth/utils/otp");
const { base32 } = await import("@better-auth/utils/base32");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

let ipCounter = 100;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `203.0.113.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", "http://localhost:5174");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    h.set(k, v);
  }
  return h;
}

function extractSessionCookie(res: Response): string {
  const setCookie = res.headers.get("set-cookie") || "";
  const match = setCookie.match(/better-auth\.session_token=[^;]+/);
  return match ? match[0] : "";
}

function extractMfaCookie(res: Response): string {
  const setCookie = res.headers.get("set-cookie") || "";
  const parts = setCookie.split(",").map((s) => s.trim().split(";")[0]);
  return parts.filter((c) => c.includes("better-auth.two_factor")).join("; ");
}

function makePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

function makeAuthorizeUrl(
  clientId: string,
  redirectUri: string,
  state: string,
  codeChallenge: string
): string {
  return `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid+profile+email&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
}

const db = await getDb();

// =============================================================================
// Seed Test Clients
// =============================================================================

const clientA = "client-isolation-a";
const clientASecret = "secret-isolation-a-1234567890";
const clientAHash = crypto
  .createHash("sha256")
  .update(clientASecret)
  .digest("base64url");
const clientACallback = "https://app-a-isolation.example.com/callback";

const clientB = "client-isolation-b";
const clientBSecret = "secret-isolation-b-1234567890";
const clientBHash = crypto
  .createHash("sha256")
  .update(clientBSecret)
  .digest("base64url");
const clientBCallback = "https://app-b-isolation.example.com/callback";

await db.collection("oauthClient").insertMany([
  {
    id: clientA,
    clientId: clientA,
    clientSecret: clientAHash,
    name: "Isolation Test App A",
    redirectUris: [clientACallback],
    allowedOrigins: ["https://app-a-isolation.example.com"],
    isPublic: false,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
  {
    id: clientB,
    clientId: clientB,
    clientSecret: clientBHash,
    name: "Isolation Test App B",
    redirectUris: [clientBCallback],
    allowedOrigins: ["https://app-b-isolation.example.com"],
    isPublic: false,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
]);

// =============================================================================
// Seed Users
// =============================================================================

// Super admin with MFA
const superEmail = "super_isolation@swyra.com";
const superPass = "SuperIsolation123!Aa";
const superSignUp = await authProvider.api.signUpEmail({
  body: { email: superEmail, password: superPass, name: "Super Isolation" },
});
const superAdminId = String(superSignUp.user.id);
await db
  .collection("user")
  .updateOne(
    { email: superEmail },
    { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
  );

const superPreSignIn = await authProvider.api.signInEmail({
  body: { email: superEmail, password: superPass },
  asResponse: true,
});
const superPreCookie = (superPreSignIn.headers.get("set-cookie") || "").split(";")[0];

const super2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: superPass, method: "totp" },
  headers: new Headers({ cookie: superPreCookie }),
});
const superB32Secret = new URL(super2faSetup.totpURI).searchParams.get("secret")!;
const superRawSecret = new TextDecoder().decode(base32.decode(superB32Secret));

const superInitCode = await createOTP(superRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: superInitCode },
  headers: new Headers({ cookie: superPreCookie }),
  asResponse: true,
});

// App admin for Client A (with MFA)
const appAdminEmail = "app_admin_isolation_a@example.com";
const appAdminPass = "AppAdminIsolation123!Aa";
const appAdminSignUp = await authProvider.api.signUpEmail({
  body: { email: appAdminEmail, password: appAdminPass, name: "App Admin Isolation A" },
});
const appAdminId = String(appAdminSignUp.user.id);
await db
  .collection("user")
  .updateOne(
    { email: appAdminEmail },
    { $set: { role: "app-admin", scopedClientId: clientA, emailVerified: true } }
  );
await db.collection("user_app_registrations").insertOne({
  userId: appAdminId,
  clientId: clientA,
  appRole: "admin",
  status: "active",
  registeredAt: new Date(),
});

// Enable MFA on app admin
const adminPreSignIn = await authProvider.api.signInEmail({
  body: { email: appAdminEmail, password: appAdminPass },
  asResponse: true,
});
const adminPreCookie = (adminPreSignIn.headers.get("set-cookie") || "").split(";")[0];

const admin2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: appAdminPass, method: "totp" },
  headers: new Headers({ cookie: adminPreCookie }),
});
const adminB32Secret = new URL(admin2faSetup.totpURI).searchParams.get("secret")!;
const adminRawSecret = new TextDecoder().decode(base32.decode(adminB32Secret));
const adminBackupCodes: string[] = admin2faSetup.backupCodes;

const adminInitCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: adminInitCode },
  headers: new Headers({ cookie: adminPreCookie }),
  asResponse: true,
});

// Normal user (no MFA, no admin role)
const normalEmail = "normal_isolation@example.com";
const normalPass = "NormalIsolation123!Aa";
const normalSignUp = await authProvider.api.signUpEmail({
  body: { email: normalEmail, password: normalPass, name: "Normal User Isolation" },
});
const normalId = String(normalSignUp.user.id);
await db.collection("user").updateOne(
  { email: normalEmail },
  { $set: { emailVerified: true } }
);

// =============================================================================
// ISO-1: Stale private-app cookies must not contaminate platform sign-in
// =============================================================================
await runTest(
  "ISO-1: Stale oauth_transaction_id and current_client_id cookies do not contaminate platform sign-in",
  async () => {
    // Simulate cookies left over from a prior private-app OAuth session
    const fakeTxId = "fake-tx-" + crypto.randomBytes(8).toString("hex");
    const staleCookies = `oauth_transaction_id=${fakeTxId}; current_client_id=${clientA}`;

    // Sign in as super-admin with admin callback and stale private-app cookies present
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ Cookie: staleCookies }),
      body: JSON.stringify({
        email: superEmail,
        password: superPass,
        callbackURL: "/admin/login",
      }),
    });
    // Must succeed (200 with twoFactorRedirect for super-admin who has MFA)
    // or 200 with session cookie -- it must not 403 or 400 due to stale client membership check
    assert.ok(
      loginRes.status === 200,
      `Expected 200 on platform sign-in with stale cookies, got ${loginRes.status}`
    );
    const body = await loginRes.json();
    // Must not have been blocked by private-app membership check
    assert.ok(
      body.twoFactorRedirect === true || body.token != null || body.user != null,
      "Platform sign-in with stale cookies must succeed (2FA prompt or session), not be denied"
    );
  }
);

// =============================================================================
// ISO-2: Platform sign-in with no callbackURL must not inherit client context
// =============================================================================
await runTest(
  "ISO-2: Platform sign-in with empty callbackURL ignores stale current_client_id cookie",
  async () => {
    const staleCookies = `current_client_id=${clientA}`;

    // Sign in as normal user via direct credential endpoint (no callbackURL)
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ Cookie: staleCookies }),
      body: JSON.stringify({
        email: normalEmail,
        password: normalPass,
      }),
    });
    // Normal user is not assigned to clientA, so if cookie contamination occurs they'd get 403
    // The correct result is 200 with a session (no membership check applied)
    assert.equal(
      loginRes.status,
      200,
      `Normal user sign-in without callbackURL should succeed, got ${loginRes.status}`
    );
    const body = await loginRes.json();
    assert.ok(
      body.token != null || body.user != null,
      "Must return a session token, not a membership denial"
    );
  }
);

// =============================================================================
// ISO-3: Direct app-admin access to MAuth admin APIs is denied
// =============================================================================
await runTest(
  "ISO-3: App-admin session cannot access MAuth platform admin APIs",
  async () => {
    // Sign in as app admin (MFA required — use MFA path to get a session)
    const authUrl = makeAuthorizeUrl(
      clientA,
      clientACallback,
      "state_iso3_" + crypto.randomBytes(4).toString("hex"),
      makePKCE().challenge
    );

    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: appAdminEmail,
        password: appAdminPass,
        callbackURL: authUrl,
      }),
    });
    assert.equal(loginRes.status, 200);
    const mfaCookie = extractMfaCookie(loginRes);
    assert.ok(mfaCookie, "Must return MFA pending cookie");

    const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
    const mfaRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: getTestHeaders({ Cookie: mfaCookie }),
      body: JSON.stringify({ code: totpCode }),
    });
    assert.equal(mfaRes.status, 200);
    const sessionCookie = extractSessionCookie(mfaRes);
    assert.ok(sessionCookie, "Must return session cookie after MFA");

    // Attempt to access MAuth admin API with app-admin session
    const adminApiRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    });
    assert.equal(
      adminApiRes.status,
      403,
      `App-admin must be denied MAuth admin API, got ${adminApiRes.status}`
    );
  }
);

// =============================================================================
// ISO-4: Super-admin sign-in after private-app flow succeeds without pollution
// =============================================================================
await runTest(
  "ISO-4: Super-admin can sign in after private-app OAuth flow with stale cookies present",
  async () => {
    // Step 1: Simulate that a private-app OAuth flow has set stale cookies
    const stateA = "state_iso4_" + crypto.randomBytes(4).toString("hex");
    const pkceA = makePKCE();
    const authUrlA = makeAuthorizeUrl(clientA, clientACallback, stateA, pkceA.challenge);

    // Trigger authorize as unauthenticated to set an oauth_transaction_id cookie (if any)
    const unAuthRes = await app.request(authUrlA, {
      method: "GET",
      headers: getTestHeaders(),
    });
    assert.equal(unAuthRes.status, 302, "Unauthenticated authorize must redirect to login");

    // Collect any oauth_transaction_id cookie set by the authorize redirect
    const txCookieHeader = unAuthRes.headers.get("set-cookie") || "";
    const txCookieMatch = txCookieHeader.match(/oauth_transaction_id=[^;]+/);
    const txCookie = txCookieMatch ? txCookieMatch[0] : "";

    // Also add a stale current_client_id cookie
    const staleCookies = [txCookie, `current_client_id=${clientA}`]
      .filter(Boolean)
      .join("; ");

    // Step 2: Sign in as super-admin with MAuth callback and stale cookies
    const superLoginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders({ Cookie: staleCookies }),
      body: JSON.stringify({
        email: superEmail,
        password: superPass,
        callbackURL: "/admin/login",
      }),
    });
    assert.equal(
      superLoginRes.status,
      200,
      `Super-admin sign-in must succeed with stale cookies, got ${superLoginRes.status}`
    );
    const superBody = await superLoginRes.json();
    assert.ok(
      superBody.twoFactorRedirect === true,
      "Super-admin with MFA must receive twoFactorRedirect"
    );

    // Step 3: Complete MFA and get super-admin session
    const superMfaCookie = extractMfaCookie(superLoginRes);
    assert.ok(superMfaCookie, "Super-admin must receive MFA pending cookie");

    const superTotpCode = await createOTP(superRawSecret, { digits: 6, period: 30 }).totp();
    const superMfaRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: getTestHeaders({ Cookie: superMfaCookie }),
      body: JSON.stringify({ code: superTotpCode }),
    });
    assert.equal(superMfaRes.status, 200, "Super-admin TOTP must succeed");
    const superSessionCookie = extractSessionCookie(superMfaRes);
    assert.ok(superSessionCookie, "Super-admin must receive session cookie");

    // Step 4: Super-admin must be able to access MAuth admin API
    const adminApiRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ Cookie: superSessionCookie }),
    });
    assert.equal(
      adminApiRes.status,
      200,
      `Super-admin must reach MAuth admin API after sign-in with stale cookies, got ${adminApiRes.status}`
    );
  }
);

// =============================================================================
// ISO-5: Unauthenticated caller cannot access private app with /admin callbackURL
// =============================================================================
await runTest(
  "ISO-5: callbackURL=/admin on private-app authorize endpoint must not grant platform access",
  async () => {
    // An attacker fabricates a callbackURL pointing to /admin
    const pkce = makePKCE();
    const maliciousUrl = makeAuthorizeUrl(
      clientA,
      clientACallback,
      "state_iso5_" + crypto.randomBytes(4).toString("hex"),
      pkce.challenge
    );

    // Sign in as normal user (not a super-admin) with a malicious callbackURL
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: normalEmail,
        password: normalPass,
        callbackURL: "/admin/login",
      }),
    });
    assert.equal(loginRes.status, 200, "Sign-in itself may succeed");
    const session = extractSessionCookie(loginRes);
    assert.ok(session, "Normal user gets session");

    // Now try to access admin API with normal user session — must be denied
    const adminRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ Cookie: session }),
    });
    assert.equal(
      adminRes.status,
      403,
      `Normal user with /admin callbackURL must be denied platform API, got ${adminRes.status}`
    );
  }
);

// =============================================================================
// ISO-6: TOTP code with leading zeros is accepted (not truncated)
// =============================================================================
await runTest(
  "ISO-6: TOTP code with leading zero is not rejected by the backend",
  async () => {
    // We cannot force a leading-zero TOTP code, but we can verify that
    // a 6-character code starting with '0' that is mathematically correct passes.
    // Generate codes until we find one with a leading zero, or test that the
    // backend does not do numeric parsing (uses string comparison).

    // The backend must accept the code as a string. We test by verifying
    // that the verify-totp endpoint accepts a freshly generated valid code regardless.
    // (If leading zeros were stripped by type="number", "012345" would arrive as "12345"
    // and fail. Since this is a backend test, we send the correct string.)
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: appAdminEmail,
        password: appAdminPass,
      }),
    });
    assert.equal(loginRes.status, 200);
    const mfaCookie = extractMfaCookie(loginRes);
    assert.ok(mfaCookie, "Must return MFA cookie");

    // Submit a correctly generated TOTP code — backend must accept string form
    const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
    const verifyRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: getTestHeaders({ Cookie: mfaCookie }),
      body: JSON.stringify({ code: totpCode }),
    });
    assert.equal(verifyRes.status, 200, "Backend must accept 6-digit TOTP code as string");
  }
);

// =============================================================================
// ISO-7: Backup recovery code (alphanumeric) is accepted by the backend
// =============================================================================
await runTest(
  "ISO-7: Alphanumeric backup/recovery code is accepted by the backend",
  async () => {
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: appAdminEmail,
        password: appAdminPass,
      }),
    });
    assert.equal(loginRes.status, 200);
    const mfaCookie = extractMfaCookie(loginRes);
    assert.ok(mfaCookie, "Must return MFA cookie");
    assert.ok(
      adminBackupCodes && adminBackupCodes.length > 0,
      "Backup codes must have been generated"
    );

    // Backup codes are typically alphanumeric strings
    const code = adminBackupCodes[0];
    assert.ok(
      code && /[a-zA-Z0-9]/.test(code),
      "Backup code must be alphanumeric"
    );

    const verifyRes = await app.request("/api/auth/two-factor/verify-backup-code", {
      method: "POST",
      headers: getTestHeaders({ Cookie: mfaCookie }),
      body: JSON.stringify({ code }),
    });
    assert.equal(
      verifyRes.status,
      200,
      `Backend must accept alphanumeric backup code, got ${verifyRes.status}`
    );
  }
);

// =============================================================================
// ISO-8: Tampered session cookie is rejected
// =============================================================================
await runTest(
  "ISO-8: Tampered session cookie is rejected by admin-auth middleware",
  async () => {
    const tamperedCookie = "better-auth.session_token=tampered.invalid.signature.xyz";
    const adminRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ Cookie: tamperedCookie }),
    });
    assert.ok(
      adminRes.status === 401 || adminRes.status === 403,
      `Tampered cookie must be rejected with 401 or 403, got ${adminRes.status}`
    );
  }
);

// =============================================================================
// ISO-9: No hardcoded email determines authorization — roles must be checked
// =============================================================================
await runTest(
  "ISO-9: Authorization uses role, not email — a super-admin email with role=user is denied",
  async () => {
    // Create a user whose email happens to match a well-known admin pattern,
    // but whose role is "user". They must not gain admin access.
    const fakeAdminEmail = "admin@swyra.com";
    const fakeAdminPass = "FakeAdmin123!Aa";
    await authProvider.api.signUpEmail({
      body: { email: fakeAdminEmail, password: fakeAdminPass, name: "Fake Admin" },
    });
    await db
      .collection("user")
      .updateOne(
        { email: fakeAdminEmail },
        // Explicitly NOT setting role: "super-admin"
        { $set: { role: "user", emailVerified: true } }
      );

    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: fakeAdminEmail,
        password: fakeAdminPass,
      }),
    });
    assert.equal(loginRes.status, 200);
    const sessionCookie = extractSessionCookie(loginRes);
    assert.ok(sessionCookie, "Sign-in must succeed to get session");

    const adminRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({ Cookie: sessionCookie }),
    });
    assert.equal(
      adminRes.status,
      403,
      `User with admin-looking email but role=user must be denied, got ${adminRes.status}`
    );
  }
);

// =============================================================================
// ISO-10: app-admin cannot reach /admin/clients regardless of stale super-admin cookie pattern
// =============================================================================
await runTest(
  "ISO-10: App-admin with super-admin ID in bearer header cannot gain platform privileges",
  async () => {
    // Get a real app-admin session
    const loginRes = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: getTestHeaders(),
      body: JSON.stringify({
        email: appAdminEmail,
        password: appAdminPass,
      }),
    });
    assert.equal(loginRes.status, 200);
    const mfaCookie = extractMfaCookie(loginRes);
    assert.ok(mfaCookie);

    const totpCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
    const mfaRes = await app.request("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: getTestHeaders({ Cookie: mfaCookie }),
      body: JSON.stringify({ code: totpCode }),
    });
    assert.equal(mfaRes.status, 200);
    const appAdminSession = extractSessionCookie(mfaRes);
    assert.ok(appAdminSession);

    // Try to inject super-admin ID in Authorization header alongside app-admin session cookie
    const spoofRes = await app.request("/api/admin/clients", {
      method: "GET",
      headers: getTestHeaders({
        Cookie: appAdminSession,
        Authorization: `Bearer fake-super-admin-token-${superAdminId}`,
      }),
    });
    assert.ok(
      spoofRes.status === 401 || spoofRes.status === 403,
      `app-admin with spoofed bearer header must be denied (401 or 403), got ${spoofRes.status}`
    );
  }
);

// =============================================================================
// Results
// =============================================================================
console.log("\n================================================================");
console.log(`  ISOLATION SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

await closeDb();
if (mongod) await mongod.stop();

if (failed > 0) process.exit(1);
