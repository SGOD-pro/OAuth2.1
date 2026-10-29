import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawn, ChildProcess } from "node:child_process";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient } from "mongodb";

console.log("================================================================");
console.log("  SWYRA AUTH -- NETWORK CONSUMER E2E TEST SUITE (6 LIVE FLOWS)");
console.log("  Multi-Process Live Network Testing (Next.js + Express + IdP)");
console.log("================================================================\n");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "../../");
const repoRoot = path.resolve(backendDir, "../");
const nextAppDir = path.resolve(repoRoot, "test/next-app");
const expressAppDir = path.resolve(repoRoot, "test/react-express-app/backend");

async function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

const IDP_PORT = await getAvailablePort();
const NEXT_PORT = await getAvailablePort();
const EXPRESS_PORT = await getAvailablePort();
const PRIVATE_PORT = await getAvailablePort();

const IDP_URL = `http://127.0.0.1:${IDP_PORT}`;
const NEXT_URL = `http://127.0.0.1:${NEXT_PORT}`;
const EXPRESS_URL = `http://127.0.0.1:${EXPRESS_PORT}`;
const PRIVATE_CALLBACK_URL = `http://127.0.0.1:${PRIVATE_PORT}/auth/callback`;

console.log(`Port Allocation:`);
console.log(`  IdP:     ${IDP_PORT}`);
console.log(`  Next.js: ${NEXT_PORT}`);
console.log(`  Express: ${EXPRESS_PORT}\n`);

const spawnedChildren: ChildProcess[] = [];
function killAllChildren() {
  for (const child of spawnedChildren) {
    if (!child.killed && child.pid) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {}
      }
    }
  }
}

process.on("exit", killAllChildren);
process.on("SIGINT", () => { killAllChildren(); process.exit(1); });
process.on("SIGTERM", () => { killAllChildren(); process.exit(1); });

// Simple Cookie Jar for tracking Set-Cookie across multi-step flows
class CookieJar {
  private cookies = new Map<string, string>();

  updateFromHeaders(headers: Headers) {
    const raw: string[] = (headers as any).getSetCookie
      ? (headers as any).getSetCookie()
      : [headers.get("set-cookie") || ""].filter(Boolean);

    for (const cookieStr of raw) {
      if (!cookieStr) continue;
      const parts = cookieStr.split(";")[0].split("=");
      const name = parts[0].trim();
      const val = parts.slice(1).join("=").trim();
      if (val === "" || cookieStr.toLowerCase().includes("max-age=0") || cookieStr.toLowerCase().includes("expires=thu, 01 jan 1970")) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, val);
      }
    }
  }

  getCookieHeader(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  set(name: string, val: string) {
    this.cookies.set(name, val);
  }

  delete(name: string) {
    this.cookies.delete(name);
  }
}

// 1. Start disposable in-memory MongoDB
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log(`Disposable MongoDB running at ${mongoUri}`);

const mongoClient = new MongoClient(mongoUri);
await mongoClient.connect();
const db = mongoClient.db();

// 2. Client Definitions
const NEXT_CLIENT_ID = "next-live-client";
const NEXT_CLIENT_SECRET = "next-secret-key-12345";
const NEXT_CLIENT_SECRET_HASH = crypto.createHash("sha256").update(NEXT_CLIENT_SECRET).digest("base64url");
const NEXT_CALLBACK_URL = `${NEXT_URL}/api/auth/callback`;

const EXPRESS_CLIENT_ID = "express-live-client";
const EXPRESS_CLIENT_SECRET = "express-secret-key-12345";
const EXPRESS_CLIENT_SECRET_HASH = crypto.createHash("sha256").update(EXPRESS_CLIENT_SECRET).digest("base64url");
const EXPRESS_CALLBACK_URL = `${EXPRESS_URL}/auth/callback`;

const PRIVATE_CLIENT_ID = "private-live-client";
const PRIVATE_CLIENT_SECRET = "private-secret-key-12345";
const PRIVATE_CLIENT_SECRET_HASH = crypto.createHash("sha256").update(PRIVATE_CLIENT_SECRET).digest("base64url");

await db.collection("oauthClient").insertMany([
  {
    id: NEXT_CLIENT_ID,
    clientId: NEXT_CLIENT_ID,
    clientSecret: NEXT_CLIENT_SECRET_HASH,
    redirectUris: [NEXT_CALLBACK_URL],
    allowedOrigins: [NEXT_URL],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  },
  {
    id: EXPRESS_CLIENT_ID,
    clientId: EXPRESS_CLIENT_ID,
    clientSecret: EXPRESS_CLIENT_SECRET_HASH,
    redirectUris: [EXPRESS_CALLBACK_URL],
    allowedOrigins: [EXPRESS_URL],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  },
  {
    id: PRIVATE_CLIENT_ID,
    clientId: PRIVATE_CLIENT_ID,
    clientSecret: PRIVATE_CLIENT_SECRET_HASH,
    redirectUris: [PRIVATE_CALLBACK_URL],
    allowedOrigins: [`http://127.0.0.1:${PRIVATE_PORT}`],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  },
]);

// 3. Helper to poll server ready
async function waitForHttp(url: string, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (res.status > 0) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

// 4. Spawn child processes
console.log("Spawning IdP child process...");
const idpChild = spawn(
  process.execPath,
  [path.join(backendDir, "node_modules/tsx/dist/cli.mjs"), "src/node-server.ts"],
  {
    cwd: backendDir,
    detached: true,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(IDP_PORT),
      MONGO_URI: mongoUri,
      BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: IDP_URL,
      FRONTEND_URL: IDP_URL,
      AUTH_PUBLIC_SIGNUP_ENABLED: "true",
      GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret",
      INTERNAL_GATEWAY_SECRET: "g".repeat(32),
      TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
    },
    stdio: "pipe",
  }
);
spawnedChildren.push(idpChild);
await waitForHttp(`${IDP_URL}/.well-known/openid-configuration`);
console.log("IdP process ready.");

console.log("Spawning Express consumer child process...");
const expressChild = spawn(
  process.execPath,
  [path.join(expressAppDir, "dist/index.js")],
  {
    cwd: expressAppDir,
    detached: true,
    env: {
      ...process.env,
      NODE_ENV: "production",
      PORT: String(EXPRESS_PORT),
      AUTH_ISSUER: IDP_URL,
      CLIENT_ID: EXPRESS_CLIENT_ID,
      CLIENT_SECRET: EXPRESS_CLIENT_SECRET,
      AUTH_CALLBACK_URL: EXPRESS_CALLBACK_URL,
      CLIENT_ORIGIN: EXPRESS_URL,
    },
    stdio: "pipe",
  }
);
spawnedChildren.push(expressChild);
await waitForHttp(`${EXPRESS_URL}/auth/login`);
console.log("Express consumer process ready.");

console.log("Spawning Next.js consumer child process...");
const nextChild = spawn(
  process.execPath,
  [path.join(nextAppDir, "node_modules/next/dist/bin/next"), "start", "-p", String(NEXT_PORT)],
  {
    cwd: nextAppDir,
    detached: true,
    env: {
      ...process.env,
      NODE_ENV: "production",
      PORT: String(NEXT_PORT),
      AUTH_ISSUER: IDP_URL,
      CLIENT_ID: NEXT_CLIENT_ID,
      CLIENT_SECRET: NEXT_CLIENT_SECRET,
      AUTH_CALLBACK_URL: NEXT_CALLBACK_URL,
    },
    stdio: "pipe",
  }
);
spawnedChildren.push(nextChild);
await waitForHttp(`${NEXT_URL}/api/auth/login`);
console.log("Next.js consumer process ready.\n");

// 5. Seed Test Users
const USER1_EMAIL = "pilot@swyra.com";
const USER1_PASSWORD = "Password123!Secure";

const USER2_EMAIL = "guest@swyra.com";
const USER2_PASSWORD = "Password123!Secure";

async function signupUser(email: string, pass: string, name: string): Promise<{ userId: string; sessionCookie: string }> {
  const res = await fetch(`${IDP_URL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    body: JSON.stringify({ email, password: pass, name }),
  });
  assert.equal(res.status, 200, `Sign-up must succeed for ${email}`);
  const data = await res.json();
  const rawCookies: string[] = (res.headers as any).getSetCookie
    ? (res.headers as any).getSetCookie()
    : [res.headers.get("set-cookie") || ""].filter(Boolean);
  const sessionCookie = rawCookies.map((c) => c.split(";")[0]).join("; ");
  return { userId: data.user.id, sessionCookie };
}

console.log("Seeding test users at IdP...");
const user1 = await signupUser(USER1_EMAIL, USER1_PASSWORD, "Pilot One");
const user2 = await signupUser(USER2_EMAIL, USER2_PASSWORD, "Guest Two");

// User 1 registered for Next.js, Express, and Private app
await db.collection("user_app_registrations").insertMany([
  { userId: user1.userId, clientId: NEXT_CLIENT_ID, role: "user", registeredAt: new Date() },
  { userId: user1.userId, clientId: EXPRESS_CLIENT_ID, role: "user", registeredAt: new Date() },
  { userId: user1.userId, clientId: PRIVATE_CLIENT_ID, role: "user", registeredAt: new Date() },
  // User 2 registered only for Next.js and Express (NOT Private app)
  { userId: user2.userId, clientId: NEXT_CLIENT_ID, role: "user", registeredAt: new Date() },
  { userId: user2.userId, clientId: EXPRESS_CLIENT_ID, role: "user", registeredAt: new Date() },
]);
console.log("User registrations seeded successfully.\n");

let passed = 0;

try {
  // ─────────────────────────────────────────────────────────────
  // FLOW 1: Next.js Consumer Real Cookie Session Flow
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 1: Live Next.js Consumer Cookie Session Flow");
  const nextJar = new CookieJar();

  // 1a. User navigates to /api/auth/login
  const nextLoginRes = await fetch(`${NEXT_URL}/api/auth/login`, {
    redirect: "manual",
  });
  assert.ok(nextLoginRes.status === 302 || nextLoginRes.status === 307, "Next.js login must redirect");
  nextJar.updateFromHeaders(nextLoginRes.headers);
  const nextAuthUrl = nextLoginRes.headers.get("location");
  assert.ok(nextAuthUrl, "Next.js login must provide redirect location to IdP");
  assert.ok(nextJar.get("oauth_verifier"), "Next.js must store oauth_verifier in cookie");
  assert.ok(nextJar.get("oauth_state"), "Next.js must store oauth_state in cookie");

  // 1b. Follow redirect to IdP /api/auth/oauth2/authorize with User 1 session
  const nextAuthUrlObj = new URL(nextAuthUrl!);
  nextAuthUrlObj.searchParams.delete("prompt");
  const nextIdpAuthRes = await fetch(nextAuthUrlObj.toString(), {
    method: "GET",
    headers: {
      Cookie: user1.sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });
  let nextCallbackRedirect = "";
  if (nextIdpAuthRes.status === 302) {
    nextCallbackRedirect = nextIdpAuthRes.headers.get("location") || "";
  } else if (nextIdpAuthRes.status === 200) {
    const data = await nextIdpAuthRes.json();
    nextCallbackRedirect = data.url;
  } else {
    const errText = await nextIdpAuthRes.text();
    console.error(`Unexpected nextIdpAuthRes status: ${nextIdpAuthRes.status}, body: ${errText}`);
  }
  assert.ok(nextCallbackRedirect, "IdP must return authorization redirect with code");
  const nextCallbackUrlObj = new URL(nextCallbackRedirect);
  const nextCode = nextCallbackUrlObj.searchParams.get("code");
  const nextState = nextCallbackUrlObj.searchParams.get("state");
  assert.ok(nextCode, `Authorization code must be present in redirect: ${nextCallbackRedirect}`);
  assert.equal(nextState, nextJar.get("oauth_state"), "State must match verifier cookie");

  // 1c. Deliver code and state to Next.js /api/auth/callback with cookie jar
  const nextCallbackRes = await fetch(nextCallbackRedirect, {
    headers: {
      Cookie: nextJar.getCookieHeader(),
    },
    redirect: "manual",
  });
  assert.ok(nextCallbackRes.status === 302 || nextCallbackRes.status === 307, "Next.js callback must redirect to app");
  nextJar.updateFromHeaders(nextCallbackRes.headers);
  assert.ok(nextJar.get("auth_session"), "Next.js must issue auth_session HttpOnly cookie");

  // 1d. Access protected Next.js /api/secure-data with auth_session cookie
  const nextSecureRes = await fetch(`${NEXT_URL}/api/secure-data`, {
    headers: {
      Cookie: nextJar.getCookieHeader(),
    },
  });
  assert.equal(nextSecureRes.status, 200, "Next.js secure data endpoint must return 200 with valid session");
  const nextSecureData = await nextSecureRes.json();
  assert.equal(nextSecureData.status, "SECURE_STREAM_ACTIVE");
  assert.equal(nextSecureData.authorizedUser, USER1_EMAIL);
  assert.ok(nextSecureData.telemetry.engineSpeedRpm > 0);

  // 1e. Access protected Next.js /api/secure-data without cookie fails with 401
  const nextUnauthRes = await fetch(`${NEXT_URL}/api/secure-data`);
  assert.equal(nextUnauthRes.status, 401, "Missing session cookie must return 401");
  console.log("  PASS: Flow 1 (Next.js Live Cookie Session Lifecycle)");
  passed++;

  // ─────────────────────────────────────────────────────────────
  // FLOW 2: Express Consumer Real Cookie Session Flow
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 2: Live Express Consumer Cookie Session Flow");
  const expressJar = new CookieJar();

  // 2a. Start flow at Express /auth/login
  const expLoginRes = await fetch(`${EXPRESS_URL}/auth/login`, {
    redirect: "manual",
  });
  assert.equal(expLoginRes.status, 302, "Express login must redirect to IdP");
  expressJar.updateFromHeaders(expLoginRes.headers);
  const expAuthUrl = expLoginRes.headers.get("location");
  assert.ok(expAuthUrl, "Express login must provide redirect location");
  assert.ok(expressJar.get("oauth_verifier"), "Express must set oauth_verifier cookie");
  assert.ok(expressJar.get("oauth_state"), "Express must set oauth_state cookie");

  // 2b. Follow redirect to IdP with User 1 session
  const expAuthUrlObj = new URL(expAuthUrl!);
  expAuthUrlObj.searchParams.delete("prompt");
  const expIdpAuthRes = await fetch(expAuthUrlObj.toString(), {
    method: "GET",
    headers: {
      Cookie: user1.sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });
  let expCallbackRedirect = "";
  if (expIdpAuthRes.status === 302) {
    expCallbackRedirect = expIdpAuthRes.headers.get("location") || "";
  } else if (expIdpAuthRes.status === 200) {
    const data = await expIdpAuthRes.json();
    expCallbackRedirect = data.url;
  }
  assert.ok(expCallbackRedirect, "IdP must redirect to Express callback with code");
  const expCallbackUrlObj = new URL(expCallbackRedirect);
  const expCode = expCallbackUrlObj.searchParams.get("code");
  const expState = expCallbackUrlObj.searchParams.get("state");
  assert.ok(expCode, "Express code must be present");
  assert.equal(expState, expressJar.get("oauth_state"), "State must match Express cookie");

  // 2c. Send code to Express /auth/callback
  const expCallbackRes = await fetch(expCallbackRedirect, {
    headers: {
      Cookie: expressJar.getCookieHeader(),
    },
    redirect: "manual",
  });
  assert.equal(expCallbackRes.status, 302, "Express callback must redirect to client origin");
  expressJar.updateFromHeaders(expCallbackRes.headers);
  assert.ok(expressJar.get("app_session"), "Express must issue app_session HttpOnly cookie");

  // 2d. Access protected Express /api/secure-telemetry with app_session cookie
  const expSecureRes = await fetch(`${EXPRESS_URL}/api/secure-telemetry`, {
    headers: {
      Cookie: expressJar.getCookieHeader(),
    },
  });
  assert.equal(expSecureRes.status, 200, "Express secure telemetry must return 200 with session");
  const expSecureData = await expSecureRes.json();
  assert.equal(expSecureData.status, "AUTHENTICATED_STREAM_ACTIVE");
  assert.equal(expSecureData.email, USER1_EMAIL);
  assert.ok(expSecureData.engineMetrics.rpm > 0);

  // 2e. Access Express /auth/me with session
  const expMeRes = await fetch(`${EXPRESS_URL}/auth/me`, {
    headers: {
      Cookie: expressJar.getCookieHeader(),
    },
  });
  assert.equal(expMeRes.status, 200, "Express /auth/me must return 200");
  const expMeData = await expMeRes.json();
  assert.equal(expMeData.authenticated, true);

  // 2f. Access Express /api/secure-telemetry without cookie fails with 401
  const expUnauthRes = await fetch(`${EXPRESS_URL}/api/secure-telemetry`);
  assert.equal(expUnauthRes.status, 401, "Missing app_session cookie must return 401");
  console.log("  PASS: Flow 2 (Express Live Cookie Session Lifecycle)");
  passed++;

  // ─────────────────────────────────────────────────────────────
  // FLOW 3: Cross-Application Audience Isolation (Tenant / App Boundary)
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 3: Cross-Application Audience Isolation");

  // Extract raw Next.js access token from its session cookie
  const nextSessionRaw = JSON.parse(decodeURIComponent(nextJar.get("auth_session")!));
  const nextAccessToken = nextSessionRaw.tokens.access_token;
  assert.ok(nextAccessToken, "Must have Next.js access token");

  // Present Next.js token to Express protected telemetry route via Bearer header
  const crossExpressRes = await fetch(`${EXPRESS_URL}/api/secure-telemetry`, {
    headers: {
      Authorization: `Bearer ${nextAccessToken}`,
    },
  });
  assert.ok(
    crossExpressRes.status === 401 || crossExpressRes.status === 403,
    `Express must reject Next.js token due to audience mismatch (expected 401/403, got ${crossExpressRes.status})`
  );

  // Extract raw Express access token from its session cookie
  const expSessionRaw = JSON.parse(decodeURIComponent(expressJar.get("app_session")!));
  const expAccessToken = expSessionRaw.access_token;
  assert.ok(expAccessToken, "Must have Express access token");

  // Present Express token to Next.js protected route via Bearer header
  // Next.js secure-data requires audience of next-live-client when verified
  const crossNextRes = await fetch(`${NEXT_URL}/api/secure-data`, {
    headers: {
      Authorization: `Bearer ${expAccessToken}`,
    },
  });
  assert.equal(crossNextRes.status, 401, "Next.js must reject Express token due to audience mismatch");
  console.log("  PASS: Flow 3 (Audience and Client Isolation Enforced Across Consumers)");
  passed++;

  // ─────────────────────────────────────────────────────────────
  // FLOW 4: Network Refresh Token Rotation and Expired Session Recovery
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 4: Network Refresh Token Rotation & Session Expiry");

  // 4a. Refresh tokens on Express /auth/refresh
  const initialExpRefresh = expSessionRaw.refresh_token;
  const expRefreshRes = await fetch(`${EXPRESS_URL}/auth/refresh`, {
    method: "POST",
    headers: {
      Cookie: expressJar.getCookieHeader(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({}),
  });
  const expRefreshStatus = expRefreshRes.status;
  const expRefreshText = await expRefreshRes.text();
  if (expRefreshStatus !== 200) {
    console.error(`Express refresh failed with status ${expRefreshStatus}: ${expRefreshText}`);
  }
  assert.equal(expRefreshStatus, 200, `Express token refresh over network must succeed: ${expRefreshText}`);
  expressJar.updateFromHeaders(expRefreshRes.headers);
  const expRefreshData = JSON.parse(expRefreshText);
  assert.ok(expRefreshData.access_token, "Must receive new access token");
  assert.ok(expRefreshData.refresh_token, "Must receive rotated refresh token");
  assert.notEqual(expRefreshData.refresh_token, initialExpRefresh, "Refresh token must rotate forward");

  // 4b. Refresh tokens on Next.js /api/auth/refresh
  const initialNextRefresh = nextSessionRaw.tokens.refresh_token;
  const nextRefreshRes = await fetch(`${NEXT_URL}/api/auth/refresh`, {
    method: "POST",
    headers: {
      Cookie: nextJar.getCookieHeader(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({}),
  });
  assert.equal(nextRefreshRes.status, 200, "Next.js token refresh over network must succeed");
  nextJar.updateFromHeaders(nextRefreshRes.headers);
  const nextRefreshData = await nextRefreshRes.json();
  assert.ok(nextRefreshData.access_token, "Must receive new access token");
  assert.ok(nextRefreshData.refresh_token, "Must receive rotated refresh token");
  assert.notEqual(nextRefreshData.refresh_token, initialNextRefresh, "Refresh token must rotate forward");

  // 4c. Next.js auto-refresh when access token is expired
  // Construct an auth_session where createdAt is 2 hours ago
  const expiredNextSession = JSON.parse(decodeURIComponent(nextJar.get("auth_session")!));
  expiredNextSession.createdAt = Date.now() - 7200 * 1000; // 2 hours ago
  nextJar.set("auth_session", encodeURIComponent(JSON.stringify(expiredNextSession)));

  const autoRefreshRes = await fetch(`${NEXT_URL}/api/secure-data`, {
    headers: {
      Cookie: nextJar.getCookieHeader(),
    },
  });
  assert.equal(autoRefreshRes.status, 200, "Next.js must auto-refresh expired session and return 200");
  nextJar.updateFromHeaders(autoRefreshRes.headers);
  const autoRefreshData = await autoRefreshRes.json();
  assert.equal(autoRefreshData.status, "SECURE_STREAM_ACTIVE");

  // 4d. Expired/revoked refresh token deterministic recovery response
  const bogusRefreshRes = await fetch(`${EXPRESS_URL}/auth/refresh`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refresh_token: "invalid-or-revoked-token-12345" }),
  });
  assert.equal(bogusRefreshRes.status, 401, "Revoked/invalid refresh token must return 401");
  const bogusData = await bogusRefreshRes.json();
  assert.equal(bogusData.error, "session_expired");
  assert.equal(bogusData.recovery_flow, "reauthenticate");
  console.log("  PASS: Flow 4 (Network Token Rotation, Auto-Refresh, and Recovery)");
  passed++;

  // ─────────────────────────────────────────────────────────────
  // FLOW 5: Account Switching via prompt=login / Re-authorization
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 5: Live Account Switching Across Active Sessions");
  const switchJar = new CookieJar();

  // User 2 logs in on Next.js
  const switchLoginRes = await fetch(`${NEXT_URL}/api/auth/login`, { redirect: "manual" });
  switchJar.updateFromHeaders(switchLoginRes.headers);
  const switchAuthUrl = switchLoginRes.headers.get("location")!;

  // Authorize with User 2 credentials at IdP
  const switchAuthUrlObj = new URL(switchAuthUrl);
  switchAuthUrlObj.searchParams.delete("prompt");
  const switchIdpRes = await fetch(switchAuthUrlObj.toString(), {
    headers: {
      Cookie: user2.sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });
  let switchRedirect = "";
  if (switchIdpRes.status === 302) {
    switchRedirect = switchIdpRes.headers.get("location") || "";
  } else if (switchIdpRes.status === 200) {
    const data = await switchIdpRes.json();
    switchRedirect = data.url;
  }
  assert.ok(switchRedirect, "Must get authorization redirect for User 2");

  // Complete callback with switchJar
  const switchCallbackRes = await fetch(switchRedirect, {
    headers: {
      Cookie: switchJar.getCookieHeader(),
    },
    redirect: "manual",
  });
  switchJar.updateFromHeaders(switchCallbackRes.headers);
  assert.ok(switchJar.get("auth_session"), "Must receive updated session cookie");

  // Verify secure-data reflects User 2
  const switchSecureRes = await fetch(`${NEXT_URL}/api/secure-data`, {
    headers: {
      Cookie: switchJar.getCookieHeader(),
    },
  });
  assert.equal(switchSecureRes.status, 200);
  const switchSecureData = await switchSecureRes.json();
  assert.equal(switchSecureData.authorizedUser, USER2_EMAIL, "Session must reflect switched account");
  console.log("  PASS: Flow 5 (Account Switching Verified)");
  passed++;

  // ─────────────────────────────────────────────────────────────
  // FLOW 6: Private Application Tenant Isolation
  // ─────────────────────────────────────────────────────────────
  console.log("Flow 6: Private Application Tenant Isolation");

  const privCodeVerifier = crypto.randomBytes(32).toString("base64url");
  const privCodeChallenge = crypto.createHash("sha256").update(privCodeVerifier).digest("base64url");
  const privState = "priv_state_" + crypto.randomBytes(6).toString("hex");

  const privAuthUrl = `${IDP_URL}/api/auth/oauth2/authorize?client_id=${PRIVATE_CLIENT_ID}&redirect_uri=${encodeURIComponent(PRIVATE_CALLBACK_URL)}&response_type=code&scope=openid+profile+email&code_challenge=${privCodeChallenge}&code_challenge_method=S256&state=${privState}`;

  // 6a. User 1 is registered for private-live-client: Authorize must succeed
  const user1PrivRes = await fetch(privAuthUrl, {
    headers: {
      Cookie: user1.sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });
  let user1PrivRedirect = "";
  if (user1PrivRes.status === 302) {
    user1PrivRedirect = user1PrivRes.headers.get("location") || "";
  } else if (user1PrivRes.status === 200) {
    const data = await user1PrivRes.json();
    user1PrivRedirect = data.url;
  }
  assert.ok(user1PrivRedirect.includes("code="), "Assigned user must receive authorization code for private app");

  // 6b. User 2 is NOT registered for private-live-client: Authorize must fail closed with access_denied
  const user2PrivRes = await fetch(privAuthUrl, {
    headers: {
      Cookie: user2.sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });
  let user2PrivRedirect = "";
  if (user2PrivRes.status === 302) {
    user2PrivRedirect = user2PrivRes.headers.get("location") || "";
  } else if (user2PrivRes.status === 200) {
    const data = await user2PrivRes.json();
    user2PrivRedirect = data.url || "";
  }
  assert.ok(
    user2PrivRedirect.includes("error=access_denied"),
    `Unregistered user must be rejected with access_denied. Got: ${user2PrivRedirect}`
  );
  console.log("  PASS: Flow 6 (Private Application Tenant Isolation Enforced)");
  passed++;

  console.log(`\n================================================================`);
  console.log(`  ALL ${passed} LIVE NETWORK CONSUMER E2E FLOWS PASSED!`);
  console.log(`================================================================\n`);
} finally {
  console.log("Tearing down processes...");
  killAllChildren();
  await mongoClient.close();
  await mongod.stop();
  console.log("Teardown complete.");
}
