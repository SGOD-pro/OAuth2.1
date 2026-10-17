import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, ChildProcess } from "node:child_process";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient } from "mongodb";
import * as jose from "jose";

console.log("================================================================");
console.log("  SWYRA AUTH -- REAL IDP PROCESS RESTART E2E TEST");
console.log("  Verifying Process Lifecycle Restart Retaining Disposable DB");
console.log("================================================================\n");

import net from "node:net";

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

const PORT = await getAvailablePort();
const IDP_URL = `http://127.0.0.1:${PORT}`;
const GATEWAY_SECRET = "g".repeat(32);
const BETTER_AUTH_SECRET = "a".repeat(32);

let activeIdpChild: ChildProcess | null = null;
process.on("exit", () => {
  if (activeIdpChild && !activeIdpChild.killed && activeIdpChild.pid) {
    try { process.kill(-activeIdpChild.pid, "SIGKILL"); } catch {}
  }
});
process.on("SIGINT", () => process.exit(1));
process.on("SIGTERM", () => process.exit(1));

// 1. Start disposable in-memory MongoDB that outlives the IdP process
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log(`Disposable MongoDB started at ${mongoUri}`);

const mongoClient = new MongoClient(mongoUri);
await mongoClient.connect();
const db = mongoClient.db();

// 2. Seed test client and user
const testClientId = "client-restart-test";
const testClientSecret = "secret-restart-test";
const testClientSecretHash = crypto.createHash("sha256").update(testClientSecret).digest("base64url");
const testRedirectUri = "http://127.0.0.1:3001/callback";
const basicAuth = Buffer.from(`${testClientId}:${testClientSecret}`).toString("base64");

await db.collection("oauthClient").insertOne({
  id: testClientId,
  clientId: testClientId,
  clientSecret: testClientSecretHash,
  redirectUris: [testRedirectUri],
  allowedOrigins: ["http://127.0.0.1:3001"],
  isPublic: false,
  skipConsent: true,
  tokenEndpointAuthMethod: "client_secret_basic",
  createdAt: new Date(),
});

const testUserId = "user-restart-" + crypto.randomBytes(6).toString("hex");
const testUserEmail = `restart-${testUserId}@example.com`;

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "../../");

// Helper to spawn IdP process
function spawnIdpProcess(): ChildProcess {
  const child = spawn(
    process.execPath,
    [path.join(backendDir, "node_modules/tsx/dist/cli.mjs"), "src/node-server.ts"],
    {
      cwd: backendDir,
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: "test",
        PORT: String(PORT),
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
  );

  activeIdpChild = child;
  return child;
}

async function waitForIdpReady(maxWaitMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await fetch(`${IDP_URL}/health`);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`IdP process on ${IDP_URL} failed to become ready within ${maxWaitMs}ms`);
}

async function terminateProcess(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.killed || child.exitCode !== null) {
      resolve();
      return;
    }
    const pid = child.pid;
    child.once("exit", () => resolve());
    if (pid) {
      try {
        process.kill(-pid, "SIGTERM");
      } catch {
        try { child.kill("SIGTERM"); } catch {}
      }
    } else {
      child.kill("SIGTERM");
    }
    setTimeout(() => {
      if (pid) {
        try {
          process.kill(-pid, "SIGKILL");
        } catch {
          try { child.kill("SIGKILL"); } catch {}
        }
      }
      resolve();
    }, 2000);
  });
}

try {
  // Step 1: Start initial IdP Process
  console.log("Phase 1: Starting initial IdP process...");
  let idpProcess = spawnIdpProcess();
  await waitForIdpReady();
  console.log("Initial IdP process is healthy and listening on port " + PORT);

  // Authenticate and issue credentials before restart
  const testPassword = "Password123!Secure";
  const signupRes = await fetch(`${IDP_URL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    body: JSON.stringify({
      email: testUserEmail,
      password: testPassword,
      name: "Restart User",
    }),
  });
  const signupStatus = signupRes.status;
  const signupText = await signupRes.text();
  if (signupStatus !== 200) {
    console.error("Signup failed with status:", signupStatus, "body:", signupText);
  }
  assert.equal(signupStatus, 200, "Sign-up must succeed");
  const signupData = JSON.parse(signupText);
  const createdUserId = signupData.user.id;

  // Ensure user is registered for the test application
  await db.collection("user_app_registrations").insertOne({
    userId: createdUserId,
    clientId: testClientId,
    role: "user",
    registeredAt: new Date(),
  });

  const setCookies = (signupRes.headers as any).getSetCookie
    ? (signupRes.headers as any).getSetCookie()
    : [signupRes.headers.get("set-cookie") || ""];
  const sessionCookie = setCookies.map((c: string) => c.split(";")[0]).filter(Boolean).join("; ");
  assert.ok(sessionCookie, "Must obtain signed session cookie");

  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = "state_restart_" + crypto.randomBytes(6).toString("hex");

  const authorizeUrl = `${IDP_URL}/api/auth/oauth2/authorize?client_id=${testClientId}&redirect_uri=${encodeURIComponent(testRedirectUri)}&response_type=code&scope=openid+profile+email+offline_access&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${state}`;

  const authRes = await fetch(authorizeUrl, {
    method: "GET",
    headers: {
      Cookie: sessionCookie,
      Origin: IDP_URL,
      Referer: `${IDP_URL}/`,
    },
    redirect: "manual",
  });

  let redirectLoc: string = "";
  if (authRes.status === 302) {
    redirectLoc = authRes.headers.get("location") || "";
  } else if (authRes.status === 200) {
    const authData = await authRes.json();
    assert.equal(authData.redirect, true, "Must have redirect: true");
    redirectLoc = authData.url;
  } else {
    throw new Error(`Unexpected authorize status ${authRes.status}: ${await authRes.text()}`);
  }
  assert.ok(redirectLoc, "Must obtain redirect location");
  const authCode = new URL(redirectLoc).searchParams.get("code")!;
  assert.ok(authCode, "Must extract authorization code");

  // Exchange code for tokens
  const tokenRes = await fetch(`${IDP_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: testRedirectUri,
      code_verifier: codeVerifier,
    }).toString(),
  });

  assert.equal(tokenRes.status, 200, "Token exchange must succeed on initial IdP process");
  const preTokens = await tokenRes.json();
  const preAccessToken = preTokens.access_token;
  const preRefreshToken = preTokens.refresh_token;
  assert.ok(preAccessToken, "Must have pre-restart access token");
  assert.ok(preRefreshToken, "Must have pre-restart refresh token");

  // Verify access token offline
  const jwksRes = await fetch(`${IDP_URL}/.well-known/jwks.json`);
  const jwksData = await jwksRes.json();
  const jwks = jose.createLocalJWKSet(jwksData);
  const verify1 = await jose.jwtVerify(preAccessToken, jwks);
  assert.equal(verify1.payload.sub, createdUserId, "JWT payload sub must match user id");

  console.log("Tokens issued and verified before restart.");

  // Step 2: STOP the IdP Process (Operating System Process Exit)
  console.log("\nPhase 2: Stopping IdP process (retaining disposable MongoDB)...");
  await terminateProcess(idpProcess);
  console.log("IdP process successfully terminated.");

  // Verify that HTTP endpoint is down
  let portClosed = false;
  try {
    await fetch(`${IDP_URL}/health`, { signal: AbortSignal.timeout(1000) });
  } catch {
    portClosed = true;
  }
  assert.ok(portClosed, "IdP port must be closed after termination");

  // Step 3: START a Fresh IdP Process against the same MongoDB
  console.log("\nPhase 3: Restarting fresh IdP process against retained MongoDB...");
  idpProcess = spawnIdpProcess();
  await waitForIdpReady();
  console.log("Restarted IdP process is healthy and listening on port " + PORT);

  // Step 4: Verify post-restart invariants
  console.log("\nPhase 4: Verifying session, JWKS, and refresh continuity across restart...");

  // 1. Existing access token verifies against restarted IdP's JWKS
  const restartedJwksRes = await fetch(`${IDP_URL}/.well-known/jwks.json`);
  const restartedJwksData = await restartedJwksRes.json();
  const restartedJwks = jose.createLocalJWKSet(restartedJwksData);
  const verify2 = await jose.jwtVerify(preAccessToken, restartedJwks);
  assert.equal(verify2.payload.sub, createdUserId, "Pre-restart access token must verify against restarted JWKS");
  console.log("[PASS] Pre-restart RS256 JWT verifies against restarted IdP JWKS");

  // 2. Pre-restart refresh token successfully rotates on restarted IdP
  const refreshRes = await fetch(`${IDP_URL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: preRefreshToken,
    }).toString(),
  });

  assert.equal(refreshRes.status, 200, "Pre-restart refresh token must rotate successfully on restarted IdP");
  const postTokens = await refreshRes.json();
  assert.ok(postTokens.access_token, "Must receive new access token after restart refresh");
  assert.ok(postTokens.refresh_token, "Must receive rotated refresh token after restart refresh");
  assert.notEqual(postTokens.refresh_token, preRefreshToken, "Refresh token must rotate to a new credential");

  const verify3 = await jose.jwtVerify(postTokens.access_token, restartedJwks);
  assert.equal(verify3.payload.sub, createdUserId, "Rotated access token sub must match user id");
  console.log("[PASS] Pre-restart refresh token rotated into authentic RS256 JWT on restarted IdP");

  // 3. User info request with newly minted token
  const userinfoRes = await fetch(`${IDP_URL}/api/auth/oauth2/userinfo`, {
    headers: {
      Authorization: `Bearer ${postTokens.access_token}`,
    },
  });
  assert.equal(userinfoRes.status, 200, "Userinfo endpoint must succeed with rotated token");
  const userinfo = await userinfoRes.json();
  assert.equal(userinfo.sub, createdUserId, "Userinfo sub must match user id");
  console.log("[PASS] User profile retrieved from restarted IdP");

  console.log("\n================================================================");
  console.log("  REAL IDP PROCESS RESTART E2E TEST: ALL ASSERTIONS PASSED!");
  console.log("================================================================\n");

  await terminateProcess(idpProcess);
  await mongoClient.close();
  await mongod.stop();
  process.exit(0);
} catch (err) {
  console.error("Test failed:", err);
  await mongoClient.close();
  await mongod.stop();
  process.exit(1);
}
