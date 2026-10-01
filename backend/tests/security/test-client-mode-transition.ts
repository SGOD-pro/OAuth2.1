import dotenv from "dotenv";
dotenv.config();

// Ensure test verifies production IdP security invariants (even when CI runner specifies NODE_ENV=test)
process.env.NODE_ENV = "production";
process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION = "false";
process.env.BETTER_AUTH_URL = "https://auth.example.com";
process.env.FRONTEND_URL = "https://app.example.com";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
process.env.APP_ADMIN_JWT_SECRET = process.env.APP_ADMIN_JWT_SECRET || "b".repeat(32);
process.env.APP_ADMIN_TOTP_KEY = process.env.APP_ADMIN_TOTP_KEY || "c".repeat(32);
process.env.TRUSTED_PROXY_CIDRS = process.env.TRUSTED_PROXY_CIDRS || "127.0.0.1/32,10.0.0.0/8";

import assert from "node:assert/strict";
import crypto from "node:crypto";

const { default: app } = await import("../../src/app");
const { getDb } = await import("../../src/db/mongo");
const { authProvider } = await import("../../src/utils/auth");
const { config } = await import("../../src/config");
const { isRegisteredRedirectUri, validateOAuthClientConfiguration } = await import("../../src/utils/security");

console.log("================================================================");
console.log("  SWYRA AUTH -- OAUTH CLIENT MODE TRANSITION & SECURITY MATRIX");
console.log("  Verifying Atomic Prod <-> Dev Transition & Per-Client Boundaries");
console.log("================================================================");

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err: any) {
    console.error(`[FAIL] ${name}`);
    console.error(err);
    failed++;
  }
}

let ipCounter = 300;
function getTestHeaders(custom: Record<string, string> = {}) {
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  return {
    "Content-Type": "application/json",
    "x-forwarded-for": `${ip}, 10.0.0.1`,
    "x-gateway-secret": process.env.INTERNAL_GATEWAY_SECRET || config.internalGatewaySecret || "g".repeat(32),
    Origin: process.env.FRONTEND_URL || "https://oauth21.vercel.app",
    "x-csrf-token": "any",
    ...custom,
  };
}

const db = await getDb();

// Setup Super-Admin credentials
const superAdminEmail = `super_${crypto.randomBytes(4).toString("hex")}@example.com`;
const superAdminPass = "SuperAdmin@1234!";
await authProvider.api.signUpEmail({
  body: { email: superAdminEmail, password: superAdminPass, name: "Super Admin" },
});
await db.collection("user").updateOne(
  { email: superAdminEmail },
  { $set: { role: "admin", scopedClientId: null, emailVerified: true } }
);

const saLoginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: superAdminEmail, password: superAdminPass }),
});
assert.equal(saLoginRes.status, 200, "Super admin login must succeed");
const superAdminCookie = (saLoginRes.headers.get("set-cookie") || "").split(";")[0];

// --------------------------------------------------------------------------
// TEST 1: Production Client Rejects Localhost Redirect Without Dev Mode
// --------------------------------------------------------------------------
await runTest("TRANS-1: Production client cannot register loopback URI without isDev=true", async () => {
  const clientId = "client-prod-" + crypto.randomBytes(4).toString("hex");

  // Create initial production client
  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-1",
    name: "Production Client 1",
    redirectUris: ["https://app1.example.com/callback"],
    allowedOrigins: ["https://app1.example.com"],
    isDev: false,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Attempt to add localhost redirect without setting isDev: true
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      redirect_uris: ["http://localhost:3000/callback"],
    }),
  });

  assert.equal(patchRes.status, 400, "PATCH with localhost on production client must return 400");
  const data = await patchRes.json();
  assert.ok(
    data.error?.includes("Loopback redirect URIs are permitted only for development-mode OAuth clients"),
    `Error message should clearly explain dev-mode requirement, got: ${data.error}`
  );

  // Verify DB state is unmodified
  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.isDev, false);
  assert.deepEqual(doc?.redirectUris, ["https://app1.example.com/callback"]);
});

// --------------------------------------------------------------------------
// TEST 2: Super-Admin Transitions Production Client to Development Mode
// --------------------------------------------------------------------------
await runTest("TRANS-2: Super-Admin securely transitions prod client to dev mode with loopback URI", async () => {
  const clientId = "client-transition-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-2",
    name: "Transition Client",
    redirectUris: ["https://legacy.example.com/callback"],
    allowedOrigins: ["https://legacy.example.com"],
    isDev: false,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Perform atomic transition: isDev=true + localhost redirect URI + localhost origin
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
    }),
  });

  assert.equal(patchRes.status, 200, `PATCH must succeed with 200, got: ${patchRes.status}`);

  // Database Verification
  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.isDev, true, "isDev must be transitioned to true");
  assert.equal(doc?.isPublic, false, "isPublic must remain unchanged (confidential)");
  assert.equal(doc?.clientSecret, "secret-hash-2", "clientSecret must NOT be altered or rotated");
  assert.equal(doc?.applicationType, "native", "applicationType must be resolved to native for loopback per RFC 8252");
  assert.ok(doc?.redirectUris.includes("http://localhost:3000/callback"), "redirectUris must contain localhost");

  // Verify OAuth redirect URI matching works for the transitioned client
  const isMatch = isRegisteredRedirectUri(
    {
      _id: doc?._id,
      id: clientId,
      clientId,
      name: doc?.name,
      redirectUris: doc?.redirectUris,
      allowedOrigins: doc?.allowedOrigins,
      disabled: false,
      isDev: true,
      isPublic: false,
      skipConsent: false,
    },
    "http://localhost:3000/callback"
  );
  assert.equal(isMatch, true, "isRegisteredRedirectUri must validate localhost callback for dev client");
});

// --------------------------------------------------------------------------
// TEST 3: Strict Boundaries for Development Clients (No SSRF / Evil Domains)
// --------------------------------------------------------------------------
await runTest("TRANS-3: Development mode rejects lookalike hosts, intranet IPs, and malformed URIs", async () => {
  const clientId = "client-dev-strict-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-3",
    name: "Dev Strict Client",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    isDev: true,
    isPublic: true,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const testCases = [
    { uri: "http://localhost.evil.com/callback", desc: "Lookalike hostname" },
    { uri: "http://127.0.0.1.attacker.com/callback", desc: "Lookalike IP hostname" },
    { uri: "http://192.168.1.100:3000/callback", desc: "RFC1918 Private Class C IP (SSRF)" },
    { uri: "http://10.0.0.1:3000/callback", desc: "RFC1918 Private Class A IP (SSRF)" },
    { uri: "http://169.254.169.254/latest/meta-data", desc: "AWS Metadata IP (SSRF)" },
    { uri: "http://localhost:3000/callback#token", desc: "Fragment in URI (RFC 6749 Section 3.1.2)" },
    { uri: "http://user:pass@localhost:3000/callback", desc: "Userinfo in URI (RFC 6749 Section 3.1.2)" },
    { uri: "http://localhost:3000/*", desc: "Wildcard in URI" },
  ];

  for (const { uri, desc } of testCases) {
    const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
      method: "PATCH",
      headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
      body: JSON.stringify({
        redirect_uris: [uri],
      }),
    });
    assert.equal(patchRes.status, 400, `Must reject ${desc}: ${uri}`);
  }
});

// --------------------------------------------------------------------------
// TEST 4: Transition from Development to Production Mode (dev -> prod)
// --------------------------------------------------------------------------
await runTest("TRANS-4: dev -> prod transition requires removing localhost; cannot leave localhost in prod", async () => {
  const clientId = "client-dev-to-prod-" + crypto.randomBytes(4).toString("hex");

  // Client currently in development mode
  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-4",
    name: "Dev to Prod Client",
    redirectUris: ["http://localhost:3000/callback"],
    allowedOrigins: ["http://localhost:3000"],
    isDev: true,
    isPublic: true,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Attempt 4A: Flip isDev=false without replacing localhost redirect URI -> MUST FAIL
  const failRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: false,
    }),
  });
  assert.equal(failRes.status, 400, "Must reject dev -> prod transition when localhost URIs remain");
  const failData = await failRes.json();
  assert.ok(
    failData.error?.includes("Loopback redirect URIs are permitted only for development-mode OAuth clients"),
    `Error should indicate loopback not permitted for prod, got: ${failData.error}`
  );

  // Attempt 4B: Flip isDev=false WITH replacing redirect URIs with valid HTTPS -> MUST SUCCEED
  const successRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: false,
      redirect_uris: ["https://production.example.com/callback"],
      allowed_origins: ["https://production.example.com"],
    }),
  });
  assert.equal(successRes.status, 200, "dev -> prod transition with HTTPS must succeed");

  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.isDev, false, "Client must now be in production mode");
  assert.equal(doc?.applicationType, "web", "Application type should be web for HTTPS");
  assert.deepEqual(doc?.redirectUris, ["https://production.example.com/callback"]);
});

// --------------------------------------------------------------------------
// TEST 5: Scoped Admin Cannot Escalate Privileges to Flip isDev Flag
// --------------------------------------------------------------------------
await runTest("TRANS-5: Scoped Admin cannot flip isDev or register localhost", async () => {
  const clientId = "client-scoped-guard-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-5",
    name: "Scoped Guard Client",
    redirectUris: ["https://scoped.example.com/callback"],
    allowedOrigins: ["https://scoped.example.com"],
    isDev: false,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const scopedEmail = `scoped_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const scopedPass = "ScopedAdmin@1234!";
  await authProvider.api.signUpEmail({
    body: { email: scopedEmail, password: scopedPass, name: "Scoped Admin" },
  });
  await db.collection("user").updateOne(
    { email: scopedEmail },
    { $set: { role: "admin", scopedClientId: clientId, emailVerified: true } }
  );

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: scopedEmail, password: scopedPass }),
  });
  assert.equal(loginRes.status, 200);
  const scopedCookie = loginRes.headers.get("set-cookie") || "";

  // Scoped admin tries to send isDev: true with localhost
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: scopedCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
    }),
  });

  // Since scoped admin's isDev is stripped, client remains isDev: false, so localhost is rejected
  assert.equal(patchRes.status, 400, "Scoped admin cannot bypass production localhost check");

  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.isDev, false, "isDev must remain false in DB");
  assert.deepEqual(doc?.redirectUris, ["https://scoped.example.com/callback"], "redirect URIs must remain HTTPS");
});

// --------------------------------------------------------------------------
// TEST 6: Scoped Admin Cross-Client Protection (Client A -> Client B)
// --------------------------------------------------------------------------
await runTest("TRANS-6: Scoped Admin of Client A cannot modify Client B", async () => {
  const clientA = "client-tenant-a-" + crypto.randomBytes(4).toString("hex");
  const clientB = "client-tenant-b-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertMany([
    {
      clientId: clientA,
      clientSecret: "secret-a",
      name: "Tenant A",
      redirectUris: ["https://a.example.com/callback"],
      allowedOrigins: ["https://a.example.com"],
      isDev: false,
      isPublic: true,
      disabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      clientId: clientB,
      clientSecret: "secret-b",
      name: "Tenant B",
      redirectUris: ["https://b.example.com/callback"],
      allowedOrigins: ["https://b.example.com"],
      isDev: false,
      isPublic: true,
      disabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ]);

  const adminEmailA = `admin_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const adminPassA = "AdminA@1234!";
  await authProvider.api.signUpEmail({
    body: { email: adminEmailA, password: adminPassA, name: "Admin Tenant A" },
  });
  await db.collection("user").updateOne(
    { email: adminEmailA },
    { $set: { role: "admin", scopedClientId: clientA, emailVerified: true } }
  );

  const loginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: adminEmailA, password: adminPassA }),
  });
  const cookieA = loginRes.headers.get("set-cookie") || "";

  // Admin A tries to modify Client B
  const attackRes = await app.request(`/api/admin/clients/${clientB}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: cookieA, "x-csrf-token": "any" }),
    body: JSON.stringify({
      client_name: "Compromised Tenant B",
    }),
  });

  assert.equal(attackRes.status, 403, "Cross-tenant access must return 403");

  const docB = await db.collection("oauthClient").findOne({ clientId: clientB });
  assert.equal(docB?.name, "Tenant B", "Tenant B configuration must remain untouched");
});

// --------------------------------------------------------------------------
// TEST 7: Unauthenticated Caller Protection
// --------------------------------------------------------------------------
await runTest("TRANS-7: Unauthenticated caller cannot modify client configuration", async () => {
  const clientId = "client-unauth-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-7",
    name: "Unauth Target Client",
    redirectUris: ["https://unauth.example.com/callback"],
    allowedOrigins: ["https://unauth.example.com"],
    isDev: false,
    isPublic: true,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const res = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders(),
    body: JSON.stringify({
      isDev: true,
    }),
  });

  assert.equal(res.status, 401, "Unauthenticated request must return 401");
});

// --------------------------------------------------------------------------
// TEST 8: Central Policy Unit Tests (validateOAuthClientConfiguration)
// --------------------------------------------------------------------------
await runTest("TRANS-8: validateOAuthClientConfiguration direct policy matrix", () => {
  // Production server + production client + localhost -> rejected
  const res1 = validateOAuthClientConfiguration(
    { isDev: false, redirectUris: ["http://localhost:3000/callback"], allowedOrigins: ["https://app.com"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res1.valid, false);
  assert.ok(res1.error?.includes("Loopback redirect URIs are permitted only for development-mode OAuth clients"));

  // Production server + dev client + localhost -> allowed
  const res2 = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://localhost:3000/callback"], allowedOrigins: ["http://localhost:3000"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res2.valid, true);
  assert.equal(res2.effectiveApplicationType, "native");

  // Production server + dev client + lookalike evil host -> rejected
  const res3 = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://localhost.evil.com/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res3.valid, false);

  // Production server + dev client + private IP (SSRF) -> rejected
  const res4 = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://192.168.1.1:3000/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res4.valid, false);

  // New client creation in production with allowDevClientsInProduction=false -> rejected
  const res5 = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://localhost:3000/callback"], allowedOrigins: ["http://localhost:3000"] },
    { serverEnvironment: "production", isNewClient: true, allowDevClientsInProduction: false }
  );
  assert.equal(res5.valid, false);
  assert.ok(res5.error?.includes("Development clients with loopback URIs are disabled in production environment"));

  // Existing client update in production with allowDevClientsInProduction=false -> permitted
  const res6 = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://localhost:3000/callback"], allowedOrigins: ["http://localhost:3000"] },
    { serverEnvironment: "production", isNewClient: false, allowDevClientsInProduction: false }
  );
  assert.equal(res6.valid, true);
});

// --------------------------------------------------------------------------
// TEST 9: Application Type Override Rejection (Native App Safety)
// --------------------------------------------------------------------------
await runTest("TRANS-9: Caller cannot force application_type='web' on dev/loopback client", async () => {
  const clientId = "client-apptype-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-9",
    name: "AppType Client",
    redirectUris: ["https://initial.example.com/callback"],
    allowedOrigins: ["https://initial.example.com"],
    isDev: false,
    isPublic: true,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Attempt to transition to dev mode with loopback URI but forcing application_type="web"
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      isDev: true,
      redirect_uris: ["http://localhost:3000/callback"],
      allowed_origins: ["http://localhost:3000"],
      application_type: "web",
    }),
  });

  assert.equal(patchRes.status, 200, "PATCH must succeed with 200");

  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.applicationType, "native", "applicationType must be forced to native despite caller asking for web");
  assert.equal(doc?.application_type, "native", "application_type must be forced to native");
});

// --------------------------------------------------------------------------
// TEST 10: Parameter Tampering & Privilege Escalation Stripping
// --------------------------------------------------------------------------
await runTest("TRANS-10: Critical privilege and identity fields are stripped on client PATCH", async () => {
  const clientId = "client-tamper-" + crypto.randomBytes(4).toString("hex");

  await db.collection("oauthClient").insertOne({
    clientId,
    clientSecret: "secret-hash-10",
    name: "Tamper Target Client",
    redirectUris: ["https://tamper.example.com/callback"],
    allowedOrigins: ["https://tamper.example.com"],
    isDev: false,
    isPublic: false,
    disabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Caller attempts to inject arbitrary clientId, userId, role, or change clientSecret
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getTestHeaders({ Cookie: superAdminCookie, "x-csrf-token": "any" }),
    body: JSON.stringify({
      client_name: "Tamper Target Client Renamed",
      client_id: "forged-client-id",
      id: "forged-id",
      userId: "forged-user-id",
      role: "superadmin_backdoor",
    }),
  });

  assert.equal(patchRes.status, 200);

  const doc = await db.collection("oauthClient").findOne({ clientId });
  assert.equal(doc?.clientId, clientId, "clientId must NOT be modified");
  assert.equal(doc?.name, "Tamper Target Client Renamed", "Allowed field name must be updated");
  assert.equal((doc as any)?.role, undefined, "Injected role field must not exist");
  assert.equal(doc?.clientSecret, "secret-hash-10", "clientSecret must not be changed");
});

console.log("================================================================");
console.log(`  TRANSITION SUITE RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
