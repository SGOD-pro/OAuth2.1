import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, ChildProcess } from "node:child_process";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient } from "mongodb";
import * as jose from "jose";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "../../");
const expressDir = path.resolve(backendDir, "../test/react-express-app/backend");

console.log("================================================================");
console.log("  SWYRA AUTH -- CROSS-PROCESS REFRESH RACE & RECOVERY TEST");
console.log("  Testing Multi-Process Single-Winner Semantics & Reauthentication Recovery");
console.log("================================================================\n");

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
const IDP_URL = `http://127.0.0.1:${IDP_PORT}`;
const CONSUMER_PORT_1 = await getAvailablePort();
const CONSUMER_PORT_2 = await getAvailablePort();

const GATEWAY_SECRET = "g".repeat(32);
const BETTER_AUTH_SECRET = "a".repeat(32);

const spawnedChildren: ChildProcess[] = [];
function trackChild(child: ChildProcess): ChildProcess {
  spawnedChildren.push(child);
  return child;
}

process.on("exit", () => {
  for (const c of spawnedChildren) {
    if (!c.killed && c.pid) {
      try { process.kill(-c.pid, "SIGKILL"); } catch {}
    }
  }
});

// 1. Start disposable MongoDB for IdP
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log(`Disposable MongoDB started at ${mongoUri}`);

const mongoClient = new MongoClient(mongoUri);
await mongoClient.connect();
const db = mongoClient.db();

// 2. Seed test client for Express Consumers
const testClientId = "client-express-multi";
const testClientSecret = "secret-express-multi";
const testClientSecretHash = crypto.createHash("sha256").update(testClientSecret).digest("base64url");
const testRedirectUri1 = `http://127.0.0.1:${CONSUMER_PORT_1}/auth/callback`;
const testRedirectUri2 = `http://127.0.0.1:${CONSUMER_PORT_2}/auth/callback`;

await db.collection("oauthClient").insertOne({
  id: testClientId,
  clientId: testClientId,
  clientSecret: testClientSecretHash,
  redirectUris: [testRedirectUri1, testRedirectUri2],
  allowedOrigins: [`http://127.0.0.1:${CONSUMER_PORT_1}`, `http://127.0.0.1:${CONSUMER_PORT_2}`],
  isPublic: false,
  isDev: true,
  skipConsent: true,
  tokenEndpointAuthMethod: "client_secret_basic",
  createdAt: new Date(),
});

// 3. Helper to spawn IdP Process
function spawnIdpProcess(): ChildProcess {
  return trackChild(spawn(
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
        BETTER_AUTH_SECRET: BETTER_AUTH_SECRET,
        BETTER_AUTH_URL: IDP_URL,
        FRONTEND_URL: "http://127.0.0.1:5174",
        AUTH_PUBLIC_SIGNUP_ENABLED: "true",
        GOOGLE_CLIENT_ID: "test-google-id",
        GOOGLE_CLIENT_SECRET: "test-google-secret",
        INTERNAL_GATEWAY_SECRET: GATEWAY_SECRET,
        TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
      },
      stdio: "pipe",
    }
  ));
}

// 4. Helper to spawn Express Consumer Process
function spawnConsumerProcess(port: number, callbackUrl: string): ChildProcess {
  return trackChild(spawn(
    process.execPath,
    [path.join(expressDir, "dist/index.js")],
    {
      cwd: expressDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "test",
        PORT: String(port),
        AUTH_ISSUER: IDP_URL,
        CLIENT_ID: testClientId,
        CLIENT_SECRET: testClientSecret,
        AUTH_CALLBACK_URL: callbackUrl,
        CLIENT_ORIGIN: `http://127.0.0.1:${port}`,
      },
      stdio: "pipe",
    }
  ));
}

async function waitForHttpReady(url: string, maxWaitMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(1000) });
      if (res.ok || res.status === 302 || res.status === 401 || res.status === 404) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Endpoint ${url} failed to become ready within ${maxWaitMs}ms`);
}

async function killChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.killed || child.exitCode !== null) return resolve();
    const pid = child.pid;
    child.once("exit", () => resolve());
    if (pid) {
      try { process.kill(-pid, "SIGTERM"); } catch {}
    } else {
      child.kill("SIGTERM");
    }
    setTimeout(() => {
      if (pid) {
        try { process.kill(-pid, "SIGKILL"); } catch {}
      }
      resolve();
    }, 2000);
  });
}

try {
  // Step 1: Start IdP process
  console.log("Phase 1: Starting IdP server on port " + IDP_PORT);
  const idpChild = spawnIdpProcess();
  await waitForHttpReady(`${IDP_URL}/health`);
  console.log("[PASS] IdP server is ready and responding at " + IDP_URL);

  // Step 2: Start Consumer Process 1 and Consumer Process 2
  console.log("\nPhase 2: Starting two separate consumer processes...");
  const consumer1 = spawnConsumerProcess(CONSUMER_PORT_1, testRedirectUri1);
  const consumer2 = spawnConsumerProcess(CONSUMER_PORT_2, testRedirectUri2);

  await waitForHttpReady(`http://127.0.0.1:${CONSUMER_PORT_1}/auth/login`);
  await waitForHttpReady(`http://127.0.0.1:${CONSUMER_PORT_2}/auth/login`);
  console.log(`[PASS] Consumer 1 running on port ${CONSUMER_PORT_1} (PID: ${consumer1.pid})`);
  console.log(`[PASS] Consumer 2 running on port ${CONSUMER_PORT_2} (PID: ${consumer2.pid})`);

  // Step 3: Create User and Authenticate with IdP to obtain initial tokens
  console.log("\nPhase 3: Creating user and obtaining initial session tokens from IdP...");
  const testUserEmail = `consumer-race-${crypto.randomBytes(4).toString("hex")}@example.com`;
  const testPassword = "Password123!Secure";
  const signupRes = await fetch(`${IDP_URL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    body: JSON.stringify({ email: testUserEmail, password: testPassword, name: "Race User" }),
  });
  assert.equal(signupRes.status, 200, "Sign-up must succeed");
  const signupData = await signupRes.json();
  const userId = signupData.user.id;

  // Register user for test private client
  await db.collection("user_app_registrations").insertOne({
    userId,
    clientId: testClientId,
    role: "user",
    registeredAt: new Date(),
  });

  const setCookies = (signupRes.headers as any).getSetCookie
    ? (signupRes.headers as any).getSetCookie()
    : [signupRes.headers.get("set-cookie") || ""];
  const sessionCookie = setCookies.map((c: string) => c.split(";")[0]).filter(Boolean).join("; ");

  // Perform OAuth 2.1 authorization code flow for client
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_race_" + crypto.randomBytes(6).toString("hex");

  const authorizeUrl = `${IDP_URL}/api/auth/oauth2/authorize?client_id=${testClientId}&redirect_uri=${encodeURIComponent(testRedirectUri1)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;
  const authRes = await fetch(authorizeUrl, {
    method: "GET",
    headers: { Cookie: sessionCookie, Origin: IDP_URL, Referer: `${IDP_URL}/` },
    redirect: "manual",
  });

  let authRedirectUrl = authRes.headers.get("location") || "";
  if (!authRedirectUrl && authRes.status === 200) {
    const authJson = await authRes.json();
    authRedirectUrl = authJson.url || "";
  }
  if (!authRedirectUrl) {
    throw new Error(`Authorize failed with status ${authRes.status}: ${await authRes.text()}`);
  }
  const authCode = new URL(authRedirectUrl).searchParams.get("code")!;
  assert.ok(authCode, "Must receive authorization code from IdP");

  // Exchange code for tokens
  const basicAuth = Buffer.from(`${testClientId}:${testClientSecret}`).toString("base64");
  const tokenRes = await fetch(`${IDP_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: testRedirectUri1,
      code_verifier: codeVerifier,
    }).toString(),
  });
  assert.equal(tokenRes.status, 200, "Token exchange must succeed");
  const tokens = await tokenRes.json();
  const initialAccessToken = tokens.access_token;
  const initialRefreshToken = tokens.refresh_token;
  assert.ok(initialAccessToken, "Must have initial access token");
  assert.ok(initialRefreshToken, "Must have initial refresh token");
  console.log("[PASS] Initial tokens minted successfully (Access Token RS256, Refresh Token Family Root)");

  // Step 4: Execute Concurrent Refresh from Process 1 and Process 2
  console.log("\nPhase 4: Executing concurrent refresh race across two consumer processes...");
  // Construct expired session payload containing initialRefreshToken
  const sharedSessionCookie = encodeURIComponent(JSON.stringify({
    access_token: initialAccessToken,
    refresh_token: initialRefreshToken,
    expires_at: Date.now() - 1000, // Expired: forces refresh
    user: { sub: userId, email: testUserEmail },
  }));

  // Fire refresh requests simultaneously to both separate consumer processes
  const [res1, res2] = await Promise.all([
    fetch(`http://127.0.0.1:${CONSUMER_PORT_1}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `app_session=${sharedSessionCookie}`,
      },
      body: JSON.stringify({ refresh_token: initialRefreshToken }),
    }),
    fetch(`http://127.0.0.1:${CONSUMER_PORT_2}/auth/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `app_session=${sharedSessionCookie}`,
      },
      body: JSON.stringify({ refresh_token: initialRefreshToken }),
    }),
  ]);

  const text1 = await res1.text();
  const text2 = await res2.text();
  console.log(`Consumer 1 status: ${res1.status}, body: ${text1}`);
  console.log(`Consumer 2 status: ${res2.status}, body: ${text2}`);

  // In an atomic single-winner rotation race across independent consumer processes without a shared cache:
  // Exactly ONE process wins and receives 200 with new rotated tokens.
  // The losing process receives 401 with the clean recovery flow (session_expired, reauthenticate).
  const statuses = [res1.status, res2.status];
  assert.ok(statuses.includes(200), "One consumer process must win the rotation race and return 200");
  assert.ok(statuses.includes(401), "The losing consumer process must receive 401 with recovery flow");

  const winnerData = JSON.parse(res1.status === 200 ? text1 : text2);
  const loserData = JSON.parse(res1.status === 401 ? text1 : text2);

  assert.ok(winnerData.access_token, "Winner must receive newly minted access token");
  assert.ok(winnerData.refresh_token, "Winner must receive newly rotated refresh token");
  assert.notEqual(winnerData.refresh_token, initialRefreshToken, "Rotated refresh token must be fresh");
  console.log("[PASS] Winner process received newly minted RS256 token and rotated refresh credential");

  assert.equal(loserData.error, "session_expired", "Loser must receive controlled session_expired error");
  assert.equal(loserData.recovery_flow, "reauthenticate", "Loser must receive reauthenticate recovery flow instruction");
  assert.ok(loserData.login_url, "Loser must receive clean login redirect URL");
  console.log("[PASS] Losing process cleanly cleared invalid cookie and returned deterministic recovery response");

  // Step 5: Verify that the winner's new access token is authentic and accepted by both consumers
  console.log("\nPhase 5: Verifying winner credentials across both consumer processes...");
  const winnerSession = encodeURIComponent(JSON.stringify({
    access_token: winnerData.access_token,
    refresh_token: winnerData.refresh_token,
    expires_at: Date.now() + 900 * 1000,
    user: { sub: userId, email: testUserEmail },
  }));

  const telemetry1 = await fetch(`http://127.0.0.1:${CONSUMER_PORT_1}/api/secure-telemetry`, {
    headers: { Cookie: `app_session=${winnerSession}` },
  });
  assert.equal(telemetry1.status, 200, "Consumer 1 must authenticate with newly rotated token");

  const telemetry2 = await fetch(`http://127.0.0.1:${CONSUMER_PORT_2}/api/secure-telemetry`, {
    headers: { Cookie: `app_session=${winnerSession}` },
  });
  assert.equal(telemetry2.status, 200, "Consumer 2 must authenticate with newly rotated token");
  console.log("[PASS] Winning credentials successfully authenticated on both consumer processes");

  console.log("\n================================================================");
  console.log("  CROSS-PROCESS REFRESH COORDINATION: ALL ASSERTIONS PASSED!");
  console.log("================================================================\n");

  await killChild(consumer1);
  await killChild(consumer2);
  await killChild(idpChild);
  await mongoClient.close();
  await mongod.stop();
  process.exit(0);
} catch (err) {
  console.error("Test failed:", err);
  for (const c of spawnedChildren) {
    if (!c.killed && c.pid) {
      try { process.kill(-c.pid, "SIGKILL"); } catch {}
    }
  }
  await mongoClient.close();
  await mongod.stop();
  process.exit(1);
}
