import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ObjectId } from "mongodb";

// 1. Guaranteed disposable in-memory database
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb, closeDb } = await import("../../src/db/mongo");
const { default: app } = await import("../../src/app");
const { authProvider } = await import("../../src/utils/auth");
const { isOriginAllowed } = await import("../../src/middleware/cors");
const {
  getCachedOrigin,
  setCachedOrigin,
  invalidateOrigins,
  invalidateClientOrigins,
  extractClientOrigins,
  clearOriginCache,
} = await import("../../src/cache/origin-cache");

console.log("================================================================");
console.log("  SWYRA AUTH -- CORS CACHE & INVALIDATION CORRECTNESS SUITE");
console.log("================================================================\n");

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

const db = await getDb();

// Seed Super-Admin for management operations
const superEmail = "super_cors@swyra.com";
const superPass = "SuperCorsPass123!Aa";
const superSignUp = await authProvider.api.signUpEmail({
  body: { email: superEmail, password: superPass, name: "Super Admin CORS" },
});
const superId = String(superSignUp.user.id);
await db.collection("user").updateOne(
  { email: superEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

let ipCounter = 200;
function getTestHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers();
  const ip = `198.51.100.${++ipCounter % 240 + 1}`;
  h.set("content-type", "application/json");
  h.set("host", "localhost:3000");
  h.set("origin", process.env.FRONTEND_URL || "http://localhost:5174");
  h.set("referer", (process.env.FRONTEND_URL || "http://localhost:5174") + "/");
  h.set("x-forwarded-for", `${ip}, 10.0.0.1`);
  h.set("x-gateway-secret", GATEWAY_SECRET);
  for (const [k, v] of Object.entries(extra)) {
    if (v === "") h.delete(k);
    else h.set(k, v);
  }
  return h;
}

const superLoginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: getTestHeaders(),
  body: JSON.stringify({ email: superEmail, password: superPass }),
});
const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

function getAdminHeaders(extra: Record<string, string> = {}): Headers {
  return getTestHeaders({
    Cookie: superCookie,
    ...extra,
  });
}

// =============================================================================
// TEST 1: Positive and negative cache behavior in origin cache
// =============================================================================
await runTest("CORS-1: Positive and negative results are cached and retrieved correctly", async () => {
  await clearOriginCache();

  const testOriginA = "https://positive-test-app.example.com";
  const testOriginB = "https://negative-test-app.example.com";

  // Initially uncached
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), null);

  // Store positive result
  await setCachedOrigin(testOriginA, true);
  assert.equal(await getCachedOrigin(testOriginA), true);

  // Store negative result
  await setCachedOrigin(testOriginB, false);
  assert.equal(await getCachedOrigin(testOriginB), false);

  // Invalidate specific origin
  await invalidateOrigins([testOriginA]);
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), false); // B remains cached

  // Invalidate with empty array should clear all entries per documentation
  await setCachedOrigin(testOriginA, true);
  assert.equal(await getCachedOrigin(testOriginA), true);
  await invalidateOrigins([]);
  assert.equal(await getCachedOrigin(testOriginA), null);
  assert.equal(await getCachedOrigin(testOriginB), null);

  await clearOriginCache();
  assert.equal(await getCachedOrigin(testOriginB), null);
});

// =============================================================================
// TEST 2: extractClientOrigins extracts both allowedOrigins and redirect URI origins
// =============================================================================
await runTest("CORS-2: extractClientOrigins extracts all explicit and derived origins", async () => {
  const clientObj = {
    allowedOrigins: [
      "https://app1.example.com",
      "https://app2.example.com/",
      "https://app6.example.com/deep/resource/path",
      "https://app7.example.com/portal?foo=bar",
    ],
    allowed_origins: ["https://app3.example.com"],
    redirectUris: ["https://app4.example.com/oauth/callback", "https://app1.example.com/callback"],
    redirect_uris: ["https://app5.example.com:8443/cb"],
  };

  const extracted = extractClientOrigins(clientObj);
  assert.ok(extracted.includes("https://app1.example.com"));
  assert.ok(extracted.includes("https://app2.example.com"));
  assert.ok(extracted.includes("https://app3.example.com"));
  assert.ok(extracted.includes("https://app4.example.com"));
  assert.ok(extracted.includes("https://app5.example.com:8443"));
  assert.ok(extracted.includes("https://app6.example.com"), "Full URL in allowedOrigins must be extracted to its web origin");
  assert.ok(extracted.includes("https://app7.example.com"), "URL with query params must be extracted to its web origin");
  assert.equal(extracted.length, 7); // app1 deduplicated
});

// =============================================================================
// TEST 3: Client creation invalidates origins and allows CORS request
// =============================================================================
await runTest("CORS-3: Client creation invalidates origins across cache layers", async () => {
  const origin = "https://newly-created-app.example.com";
  // Pre-seed negative cache to test invalidation on creation
  await setCachedOrigin(origin, false);
  assert.equal(await getCachedOrigin(origin), false);

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Created App",
      redirect_uris: [`${origin}/callback`],
      allowed_origins: [origin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);

  // Cache entry should be invalidated on creation
  const cachedAfter = await getCachedOrigin(origin);
  assert.equal(cachedAfter, null, "Origin cache entry must be invalidated upon client creation");

  // Dynamic CORS preflight must now succeed
  const corsRes = await app.request("/api/auth/oauth2/authorize", {
    method: "OPTIONS",
    headers: new Headers({
      Origin: origin,
      "Access-Control-Request-Method": "GET",
    }),
  });
  assert.equal(corsRes.status, 204);
  assert.equal(corsRes.headers.get("access-control-allow-origin"), origin);
});

// =============================================================================
// TEST 4: Client update invalidates both old and new origins
// =============================================================================
await runTest("CORS-4: Client update invalidates old and new origins", async () => {
  const oldOrigin = "https://old-client-origin.example.com";
  const newOrigin = "https://new-client-origin.example.com";

  // Create client with oldOrigin
  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Update Test App",
      redirect_uris: [`${oldOrigin}/callback`],
      allowed_origins: [oldOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Populate cache for old origin
  assert.equal(await isOriginAllowed(oldOrigin), true);
  await setCachedOrigin(oldOrigin, true);
  await setCachedOrigin(newOrigin, false);

  // Patch client to use newOrigin instead
  const patchRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      redirect_uris: [`${newOrigin}/callback`],
      allowed_origins: [newOrigin],
    }),
  });
  assert.equal(patchRes.status, 200);

  // Both old and new origins must be invalidated in cache
  assert.equal(await getCachedOrigin(oldOrigin), null, "Old origin must be invalidated");
  assert.equal(await getCachedOrigin(newOrigin), null, "New origin must be invalidated");

  // Old origin is no longer allowed, new origin is allowed
  assert.equal(await isOriginAllowed(oldOrigin), false);
  assert.equal(await isOriginAllowed(newOrigin), true);
});

// =============================================================================
// TEST 5: Disabled client cannot keep origin allowed; active client preserves it
// =============================================================================
await runTest("CORS-5: Disabled client cannot keep origin allowed; multi-client overlap preserved", async () => {
  const sharedOrigin = "https://shared-origin.example.com";

  // Create Client A with sharedOrigin
  const createARes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Shared App A",
      redirect_uris: [`${sharedOrigin}/callback-a`],
      allowed_origins: [sharedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createARes.status, 201);
  const createdA = await createARes.json();
  const clientAId = createdA.client_id || createdA.clientId || createdA.id;

  // Create Client B with sharedOrigin
  const createBRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Shared App B",
      redirect_uris: [`${sharedOrigin}/callback-b`],
      allowed_origins: [sharedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createBRes.status, 201);
  const createdB = await createBRes.json();
  const clientBId = createdB.client_id || createdB.clientId || createdB.id;

  assert.equal(await isOriginAllowed(sharedOrigin), true);

  // Disable Client A
  const disableARes = await app.request(`/api/admin/clients/${clientAId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({ disabled: true }),
  });
  assert.equal(disableARes.status, 200);

  // Shared origin MUST STILL BE ALLOWED because Client B is active
  assert.equal(
    await isOriginAllowed(sharedOrigin),
    true,
    "Active Client B must preserve origin access even when Client A is disabled"
  );

  // Now disable Client B
  const disableBRes = await app.request(`/api/admin/clients/${clientBId}`, {
    method: "PATCH",
    headers: getAdminHeaders(),
    body: JSON.stringify({ disabled: true }),
  });
  assert.equal(disableBRes.status, 200);

  // Shared origin MUST NOW BE DENIED because no active client uses it
  assert.equal(
    await isOriginAllowed(sharedOrigin),
    false,
    "Origin must be denied when all clients using it are disabled"
  );
});

// =============================================================================
// TEST 6: Client deletion invalidates all explicit and redirect-derived origins
// =============================================================================
await runTest("CORS-6: Client deletion invalidates explicit and derived origins", async () => {
  const deleteOrigin = "https://delete-me-origin.example.com";
  const deleteRedirectOrigin = "https://delete-redirect-origin.example.com";

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Delete Me App",
      redirect_uris: [`${deleteRedirectOrigin}/auth/callback`],
      allowed_origins: [deleteOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Pre-seed positive cache
  await setCachedOrigin(deleteOrigin, true);
  await setCachedOrigin(deleteRedirectOrigin, true);

  // Delete client
  const delRes = await app.request(`/api/admin/clients/${clientId}`, {
    method: "DELETE",
    headers: getAdminHeaders(),
  });
  assert.equal(delRes.status, 200);

  // Both origins must be invalidated in cache
  assert.equal(await getCachedOrigin(deleteOrigin), null);
  assert.equal(await getCachedOrigin(deleteRedirectOrigin), null);

  // Both origins are no longer allowed
  assert.equal(await isOriginAllowed(deleteOrigin), false);
  assert.equal(await isOriginAllowed(deleteRedirectOrigin), false);
});

// =============================================================================
// TEST 7: Scoped app config patch invalidates origins
// =============================================================================
await runTest("CORS-7: Scoped app config patch invalidates origins", async () => {
  const scopedOrigin = "https://scoped-app.example.com";
  const patchedOrigin = "https://scoped-app-patched.example.com";

  const createRes = await app.request("/api/admin/clients", {
    method: "POST",
    headers: getAdminHeaders(),
    body: JSON.stringify({
      client_name: "Scoped App",
      redirect_uris: [`${scopedOrigin}/callback`],
      allowed_origins: [scopedOrigin],
      is_public: false,
    }),
  });
  assert.equal(createRes.status, 201);
  const created = await createRes.json();
  const clientId = created.client_id || created.clientId || created.id;

  // Seed App Admin for this specific client
  const appAdminEmail = `app_admin_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const appAdminPass = "AppAdminPass123!Aa";
  const signUpRes = await authProvider.api.signUpEmail({
    body: { email: appAdminEmail, password: appAdminPass, name: "App Admin Scoped" },
  });
  const appAdminUserId = String(signUpRes.user.id);
  await db.collection("user").updateOne(
    { email: appAdminEmail },
    { $set: { role: "admin", scopedClientId: clientId, emailVerified: true } }
  );
  await db.collection("app_admins").insertOne({
    userId: appAdminUserId,
    clientId: clientId,
    role: "admin",
    createdAt: new Date(),
  });

  const appAdminLoginRes = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: getTestHeaders(),
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPass }),
  });
  assert.equal(appAdminLoginRes.status, 200);
  const appAdminCookie = (appAdminLoginRes.headers.get("set-cookie") || "").split(";")[0];

  await setCachedOrigin(scopedOrigin, true);
  await setCachedOrigin(patchedOrigin, false);

  const patchRes = await app.request(`/api/admin/app/${clientId}/config`, {
    method: "PATCH",
    headers: getTestHeaders({
      Cookie: appAdminCookie,
    }),
    body: JSON.stringify({
      redirect_uris: [`${patchedOrigin}/callback`],
      allowed_origins: [patchedOrigin],
    }),
  });
  assert.equal(patchRes.status, 200);

  assert.equal(await getCachedOrigin(scopedOrigin), null);
  assert.equal(await getCachedOrigin(patchedOrigin), null);
  assert.equal(await isOriginAllowed(patchedOrigin), true);
  assert.equal(await isOriginAllowed(scopedOrigin), false);
});

// =============================================================================
// TEST 8: Cache functions operate safely when Redis is unavailable
// =============================================================================
await runTest("CORS-8: Cache functions fall back safely when Redis is unavailable", async () => {
  // In our test environment, Upstash Redis env vars were deleted, so Redis is null / unavailable.
  // Verify that getCachedOrigin, setCachedOrigin, and invalidateOrigins execute without throwing.
  const fallbackOrigin = "https://fallback-test.example.com";

  await setCachedOrigin(fallbackOrigin, true);
  const cachedVal = await getCachedOrigin(fallbackOrigin);
  assert.equal(cachedVal, true, "MongoDB cache fallback must return stored value when Redis is unavailable");

  await invalidateOrigins([fallbackOrigin]);
  const invalidatedVal = await getCachedOrigin(fallbackOrigin);
  assert.equal(invalidatedVal, null, "MongoDB invalidation must succeed when Redis is unavailable");
});

await closeDb();
await mongod.stop();

console.log("\n================================================================");
console.log(`  CORS CACHE CORRECTNESS RESULTS: ${passed} PASSED, ${failed} FAILED`);
console.log("================================================================\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
