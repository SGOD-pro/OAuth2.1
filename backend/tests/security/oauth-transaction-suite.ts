import dotenv from "dotenv";
dotenv.config();

import assert from "node:assert/strict";
import crypto from "crypto";

// Configure test environment
process.env.NODE_ENV = "test";
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/test_security";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "a".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "https://auth.example.com";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "https://app.example.com";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32";
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { createOAuthTransaction, getOAuthTransaction } = await import("../../src/db/state");

console.log("================================================================");
console.log("  SWYRA AUTH -- OAUTH TRANSACTION & CODE SECURITY SUITE");
console.log("================================================================");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}:`, err.message || err);
    failed++;
  }
}

let reqCounter = 1;
function getTestHeaders(overrides: Record<string, string> = {}): Headers {
  const h = new Headers();
  h.set("host", "auth.example.com");
  h.set("content-type", "application/json");
  const randSub = Math.floor(reqCounter / 5);
  reqCounter++;
  h.set("x-forwarded-for", `10.88.${randSub}.${reqCounter % 200}`);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

// --------------------------------------------------------------------------
// TEST 1: Server-Side Transaction Persistence at /oauth2/authorize
// --------------------------------------------------------------------------
await runTest("TX-1: /oauth2/authorize creates authoritative server-side transaction record", async () => {
  const db = await getDb();
  const clientId = "tx_client_" + crypto.randomBytes(4).toString("hex");
  const redirectUri = "https://app.example.com/callback";
  const state = "state_" + crypto.randomBytes(8).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "client-secret-hash",
    name: "TX Test App",
    redirectUris: [redirectUri],
    allowedOrigins: ["https://app.example.com"],
    isPublic: true,
    disabled: false,
    createdAt: new Date(),
  });

  const res = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}`,
    {
      method: "GET",
      headers: getTestHeaders(),
    }
  );

  assert.equal(res.status, 302, "Authorize must return 302 redirect");
  const cookieHeader = res.headers.get("set-cookie") || "";
  assert.ok(cookieHeader.includes("oauth_transaction_id="), "Response must set oauth_transaction_id cookie");

  // Query MongoDB oauth_transactions collection
  const txRecord = await getOAuthTransaction({ state });
  assert.ok(txRecord, "Authoritative server-side transaction record must exist in MongoDB");
  assert.equal(txRecord?.clientId, clientId);
  assert.equal(txRecord?.redirectUri, redirectUri);
  assert.equal(txRecord?.state, state);
  assert.equal(txRecord?.status, "pending");
  assert.ok(txRecord?.expiresAt instanceof Date);
});

// --------------------------------------------------------------------------
// TEST 2: Multi-Tab Shared Cookie Jar Isolation
// --------------------------------------------------------------------------
await runTest("TX-2: Multi-tab parallel OAuth flows maintain state-bound tenant isolation", async () => {
  const db = await getDb();
  const clientA = "tab_app_a_" + crypto.randomBytes(4).toString("hex");
  const clientB = "tab_app_b_" + crypto.randomBytes(4).toString("hex");

  for (const cid of [clientA, clientB]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: "secret-hash",
      name: `Tab App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: true,
      disabled: false,
      createdAt: new Date(),
    });
  }

  const stateA = "tab_a_state_" + crypto.randomBytes(6).toString("hex");
  const stateB = "tab_b_state_" + crypto.randomBytes(6).toString("hex");

  // Tab A initiates OAuth
  const tabARes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientA}&redirect_uri=https://${clientA}.example.com/cb&response_type=code&state=${stateA}`,
    { method: "GET", headers: getTestHeaders() }
  );
  assert.equal(tabARes.status, 302);

  // Tab B initiates OAuth (overwriting any shared cookie jar current_client_id)
  const tabBRes = await app.request(
    `/api/auth/oauth2/authorize?client_id=${clientB}&redirect_uri=https://${clientB}.example.com/cb&response_type=code&state=${stateB}`,
    { method: "GET", headers: getTestHeaders() }
  );
  assert.equal(tabBRes.status, 302);

  // Tab A continues flow with stateA
  const txA = await getOAuthTransaction({ state: stateA });
  assert.ok(txA, "Transaction A must exist");
  assert.equal(txA?.clientId, clientA, "State A must resolve Client A");

  // Tab B continues flow with stateB
  const txB = await getOAuthTransaction({ state: stateB });
  assert.ok(txB, "Transaction B must exist");
  assert.equal(txB?.clientId, clientB, "State B must resolve Client B");
});

// --------------------------------------------------------------------------
// TEST 3: Client ID Tampering Detection in Transaction Continuation
// --------------------------------------------------------------------------
await runTest("TX-3: Client ID tampering in consent/continue strictly rejected (400)", async () => {
  const db = await getDb();
  const clientA = "tamper_a_" + crypto.randomBytes(4).toString("hex");
  const clientB = "tamper_b_" + crypto.randomBytes(4).toString("hex");

  for (const cid of [clientA, clientB]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: "secret-hash",
      name: `Tamper App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: true,
      disabled: false,
      createdAt: new Date(),
    });
  }

  // Authenticate user to test consent endpoint
  const email = `consent_user_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = "Password@1234!";
  await authProvider.api.signUpEmail({ body: { email, password, name: "Consent User" } });
  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders({ Origin: "https://app.example.com" }),
    body: JSON.stringify({ email, password }),
  });
  const cookie = loginRes.headers.get("set-cookie") || "";

  // Create transaction bound to clientA
  const stateA = "tamper_state_" + crypto.randomBytes(6).toString("hex");
  await createOAuthTransaction({
    transactionId: crypto.randomUUID(),
    clientId: clientA,
    redirectUri: `https://${clientA}.example.com/cb`,
    state: stateA,
  });

  // Attacker submits consent with stateA but forged client_id=clientB
  const tamperRes = await app.request("/api/auth/oauth2/consent", {
    method: "POST",
    headers: getTestHeaders({ Cookie: cookie, Origin: "https://app.example.com" }),
    body: JSON.stringify({
      oauth_query: `client_id=${clientB}&state=${stateA}&redirect_uri=https://${clientA}.example.com/cb`,
    }),
  });

  assert.equal(tamperRes.status, 400, "Client ID mismatch with transaction must return 400");
  const data = await tamperRes.json();
  assert.equal(data.error, "invalid_request");
});

// --------------------------------------------------------------------------
// TEST 4: Expired Transaction Invalidation
// --------------------------------------------------------------------------
await runTest("TX-4: Expired transactions are strictly rejected", async () => {
  const db = await getDb();
  const expiredState = "expired_state_" + crypto.randomBytes(6).toString("hex");

  // Create an already-expired transaction in MongoDB
  await db.collection("oauth_transactions").insertOne({
    transactionId: crypto.randomUUID(),
    clientId: "some-client",
    redirectUri: "https://example.com/cb",
    state: expiredState,
    status: "pending",
    createdAt: new Date(Date.now() - 3600 * 1000),
    expiresAt: new Date(Date.now() - 60 * 1000), // Expired 1 min ago
  });

  const tx = await getOAuthTransaction({ state: expiredState });
  assert.equal(tx, null, "Expired transaction must evaluate to null");
});

// --------------------------------------------------------------------------
// TEST 5: PKCE Code Challenge and Verifier Protection
// --------------------------------------------------------------------------
await runTest("TX-5: PKCE verifier mismatch rejects token exchange (400)", async () => {
  const db = await getDb();
  const clientId = "pkce_client_" + crypto.randomBytes(4).toString("hex");
  const clientSecret = "pkce-secret-12345";
  const hashedSecret = crypto.createHash("sha256").update(clientSecret).digest("base64url");
  const redirectUri = "https://pkce.example.com/cb";

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: hashedSecret,
    name: "PKCE Test Client",
    redirectUris: [redirectUri],
    allowedOrigins: ["https://pkce.example.com"],
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
  });

  // Seed an authorization code in MongoDB
  const code = "auth_code_" + crypto.randomBytes(16).toString("hex");
  const codeVerifier = "legitimate-code-verifier-string-length-43-chars-min";
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  await db.collection("oauthAuthorizationCode").insertOne({
    code,
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod: "S256",
    expiresAt: new Date(Date.now() + 300 * 1000),
    userId: "test-user-id",
    createdAt: new Date(),
  });

  // Exchange with WRONG code verifier
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}&code_verifier=wrong-verifier-attack`,
  });

  assert.equal(tokenRes.status, 400, "Wrong PKCE code_verifier must fail with 400");
  const data = await tokenRes.json();
  assert.ok(data.error === "invalid_grant" || data.error === "invalid_request");
});

// --------------------------------------------------------------------------
// TEST 6: Authorization Code Cross-Client Substitution Protection
// --------------------------------------------------------------------------
await runTest("TX-6: Authorization code cannot be exchanged by a different client", async () => {
  const db = await getDb();
  const clientA = "app_a_code_" + crypto.randomBytes(4).toString("hex");
  const clientB = "app_b_code_" + crypto.randomBytes(4).toString("hex");
  const secretA = "secretA-12345";
  const secretB = "secretB-12345";

  for (const [cid, sec] of [[clientA, secretA], [clientB, secretB]]) {
    await db.collection("oauthClient").insertOne({
      clientId: cid,
      clientSecret: crypto.createHash("sha256").update(sec).digest("base64url"),
      name: `App ${cid}`,
      redirectUris: [`https://${cid}.example.com/cb`],
      allowedOrigins: [`https://${cid}.example.com`],
      isPublic: false,
      disabled: false,
      createdAt: new Date(),
    });
  }

  // Seed code issued to App A
  const code = "code_for_app_a_" + crypto.randomBytes(16).toString("hex");
  await db.collection("oauthAuthorizationCode").insertOne({
    code,
    clientId: clientA,
    redirectUri: `https://${clientA}.example.com/cb`,
    expiresAt: new Date(Date.now() + 300 * 1000),
    userId: "test-user-id",
    createdAt: new Date(),
  });

  // Client B attempts to exchange Client A's code
  const tokenRes = await app.request("/api/auth/oauth2/token", {
    method: "POST",
    headers: getTestHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(`${clientB}:${secretB}`).toString("base64"),
    }),
    body: `grant_type=authorization_code&code=${code}&redirect_uri=https://${clientA}.example.com/cb`,
  });

  assert.equal(tokenRes.status, 400, "Exchanging Client A's code with Client B credentials must fail (400)");
  const data = await tokenRes.json();
  assert.ok(data.error === "invalid_grant" || data.error === "invalid_request");
});

console.log("================================================================");
console.log(`  OAUTH TRANSACTION SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

process.exit(failed > 0 ? 1 : 0);
