// Guaranteed clean environment: never inherit external Redis credentials
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

import crypto from "node:crypto";
import { MongoMemoryServer } from "mongodb-memory-server";
import { performance } from "node:perf_hooks";
import * as jose from "jose";

// Guaranteed disposable in-memory database
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "p".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb, closeDb } = await import("../src/db/mongo");
const { default: app } = await import("../src/app");
const { authProvider } = await import("../src/utils/auth");
const { isOriginAllowed } = await import("../src/middleware/cors");
const { getCachedOrigin, setCachedOrigin, clearOriginCache } = await import("../src/cache/origin-cache");

const db = await getDb();

function computePercentiles(samples: number[]) {
  if (samples.length === 0) return { p50: 0, p95: 0, p99: 0, min: 0, max: 0, avg: 0, count: 0 };
  const sorted = [...samples].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.50)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const avg = sorted.reduce((sum, v) => sum + v, 0) / sorted.length;
  return {
    p50: Number(p50.toFixed(2)),
    p95: Number(p95.toFixed(2)),
    p99: Number(p99.toFixed(2)),
    min: Number(min.toFixed(2)),
    max: Number(max.toFixed(2)),
    avg: Number(avg.toFixed(2)),
    count: samples.length,
  };
}

console.log("================================================================");
console.log("  SWYRA AUTH -- PERFORMANCE ASSESSMENT BENCHMARK HARNESS");
console.log("================================================================\n");

// -----------------------------------------------------------------------------
// BENCHMARK 1: Login (POST /api/auth/sign-in/email)
// -----------------------------------------------------------------------------
const LOGIN_ITERATIONS = 30;
console.log(`[1/4] Benchmarking Login (${LOGIN_ITERATIONS} iterations with fresh credentials)...`);
const loginLatencies: number[] = [];

for (let i = 0; i < LOGIN_ITERATIONS; i++) {
  const email = `bench_login_${i}_${crypto.randomBytes(3).toString("hex")}@example.com`;
  const password = "BenchPassword123!Aa";
  await authProvider.api.signUpEmail({
    body: { email, password, name: `Bench User ${i}` },
  });

  const ip = `198.51.100.${(i % 240) + 1}`;
  const t0 = performance.now();
  const res = await app.request("/api/auth/sign-in/email", {
    method: "POST",
    headers: new Headers({
      "content-type": "application/json",
      host: "localhost:3000",
      origin: "http://localhost:5174",
      referer: "http://localhost:5174/",
      "x-forwarded-for": `${ip}, 10.0.0.1`,
      "x-gateway-secret": GATEWAY_SECRET,
    }),
    body: JSON.stringify({ email, password }),
  });
  const t1 = performance.now();
  if (res.status === 200) {
    loginLatencies.push(t1 - t0);
  }
}

// -----------------------------------------------------------------------------
// BENCHMARK 2: Session Validation (GET /api/auth/get-session)
// -----------------------------------------------------------------------------
const SESSION_ITERATIONS = 100;
console.log(`[2/4] Benchmarking Session Validation (${SESSION_ITERATIONS} iterations)...`);

// Create a stable session
const sessionEmail = `session_bench_${crypto.randomBytes(4).toString("hex")}@example.com`;
const sessionPass = "SessionPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: sessionEmail, password: sessionPass, name: "Session Bench User" },
});
const loginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: new Headers({
    "content-type": "application/json",
    host: "localhost:3000",
    origin: "http://localhost:5174",
    referer: "http://localhost:5174/",
    "x-gateway-secret": GATEWAY_SECRET,
    "x-forwarded-for": "198.51.100.250, 10.0.0.1",
  }),
  body: JSON.stringify({ email: sessionEmail, password: sessionPass }),
});
const sessionCookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];

const sessionLatencies: number[] = [];
for (let i = 0; i < SESSION_ITERATIONS; i++) {
  const ip = `198.51.101.${(i % 240) + 1}`;
  const t0 = performance.now();
  const res = await app.request("/api/auth/get-session", {
    method: "GET",
    headers: new Headers({
      host: "localhost:3000",
      Cookie: sessionCookie,
      "x-gateway-secret": GATEWAY_SECRET,
      "x-forwarded-for": `${ip}, 10.0.0.1`,
    }),
  });
  const t1 = performance.now();
  if (res.status === 200) {
    sessionLatencies.push(t1 - t0);
  }
}

// -----------------------------------------------------------------------------
// BENCHMARK 3: Token Verification (Offline RS256 JWT verify via JWKS)
// -----------------------------------------------------------------------------
const TOKEN_ITERATIONS = 100;
console.log(`[3/4] Benchmarking Token Verification (${TOKEN_ITERATIONS} iterations)...`);

// Create OAuth client and issue real access token via authorization code flow
const perfRedirectUri = "https://bench-app.example.com/callback";

// Seed super-admin to create client via official admin endpoint
const superEmail = `super_perf_${crypto.randomBytes(3).toString("hex")}@swyra.com`;
const superPass = "SuperPerfPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: superEmail, password: superPass, name: "Super Admin Perf" },
});
await db.collection("user").updateOne(
  { email: superEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

const superLoginRes = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: new Headers({
    "content-type": "application/json",
    host: "localhost:3000",
    origin: "http://localhost:5174",
    referer: "http://localhost:5174/",
    "x-gateway-secret": GATEWAY_SECRET,
    "x-forwarded-for": "198.51.100.252, 10.0.0.1",
  }),
  body: JSON.stringify({ email: superEmail, password: superPass }),
});
const superCookie = (superLoginRes.headers.get("set-cookie") || "").split(";")[0];

const createClientRes = await app.request("/api/admin/clients", {
  method: "POST",
  headers: new Headers({
    "content-type": "application/json",
    host: "localhost:3000",
    origin: "http://localhost:5174",
    referer: "http://localhost:5174/",
    "x-gateway-secret": GATEWAY_SECRET,
    Cookie: superCookie,
    "x-forwarded-for": "198.51.100.253, 10.0.0.1",
  }),
  body: JSON.stringify({
    client_name: "Bench Client",
    redirect_uris: [perfRedirectUri],
    allowed_origins: ["https://bench-app.example.com"],
    is_public: true,
    skip_consent: true,
  }),
});
const createdClient = await createClientRes.json();
const perfClientId = createdClient.client_id || createdClient.clientId || createdClient.id;
const perfClientSecret = createdClient.client_secret || createdClient.clientSecret;

// Authorize to get code
const codeVerifier = crypto.randomBytes(32).toString("base64url");
const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
const authUrl = `/api/auth/oauth2/authorize?client_id=${perfClientId}&response_type=code&redirect_uri=${encodeURIComponent(perfRedirectUri)}&scope=openid%20profile%20email&state=state123&code_challenge=${codeChallenge}&code_challenge_method=S256`;
const authRes = await app.request(authUrl, {
  method: "GET",
  headers: new Headers({
    host: "localhost:3000",
    Cookie: sessionCookie,
    "x-gateway-secret": GATEWAY_SECRET,
  }),
});
const redirectLoc = authRes.headers.get("location") || "";
const authCode = new URL(redirectLoc).searchParams.get("code");
if (!authCode) {
  throw new Error(`Authorize failed: redirect location was ${redirectLoc}`);
}

const basicAuth = Buffer.from(`${perfClientId}:${perfClientSecret}`).toString("base64");
const tokenExchangeRes = await app.request("/api/auth/oauth2/token", {
  method: "POST",
  headers: new Headers({
    host: "localhost:3000",
    Authorization: `Basic ${basicAuth}`,
    "Content-Type": "application/x-www-form-urlencoded",
    "x-gateway-secret": GATEWAY_SECRET,
  }),
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: perfRedirectUri,
    code_verifier: codeVerifier,
  }).toString(),
});
const tokenPayload = await tokenExchangeRes.json();
const testJwt = tokenPayload.id_token || tokenPayload.access_token;
if (!testJwt) {
  throw new Error(`Token exchange failed: ${JSON.stringify(tokenPayload)}`);
}

// Fetch JWKS
const jwksRes = await app.request("/.well-known/jwks.json", {
  method: "GET",
  headers: new Headers({ host: "localhost:3000" }),
});
const jwksData = await jwksRes.json();
const localJwks = jose.createLocalJWKSet(jwksData);

const tokenLatencies: number[] = [];
for (let i = 0; i < TOKEN_ITERATIONS; i++) {
  const t0 = performance.now();
  const verifyResult = await jose.jwtVerify(testJwt, localJwks, {
    issuer: "http://localhost:3000",
  });
  const t1 = performance.now();
  if (verifyResult.payload.sub) {
    tokenLatencies.push(t1 - t0);
  }
}

// -----------------------------------------------------------------------------
// BENCHMARK 4: CORS Origin Lookup (Uncached DB query vs Origin-Cache hit)
// -----------------------------------------------------------------------------
console.log(`[4/4] Benchmarking CORS Lookup (50 uncached novel lookups + 100 cache hits)...`);
await clearOriginCache();

const corsUncachedLatencies: number[] = [];
for (let i = 0; i < 50; i++) {
  const novelOrigin = `https://novel-origin-${i}.example.com`;
  await clearOriginCache(); // force uncached database evaluation
  const t0 = performance.now();
  await isOriginAllowed(novelOrigin);
  const t1 = performance.now();
  corsUncachedLatencies.push(t1 - t0);
}

// Populate cache for benchmark
const cachedOrigin = "https://bench-app.example.com";
await setCachedOrigin(cachedOrigin, true);
const corsCachedLatencies: number[] = [];
for (let i = 0; i < 100; i++) {
  const t0 = performance.now();
  const allowed = await getCachedOrigin(cachedOrigin);
  const t1 = performance.now();
  if (allowed === true) {
    corsCachedLatencies.push(t1 - t0);
  }
}

// -----------------------------------------------------------------------------
// REPORT SUMMARY
// -----------------------------------------------------------------------------
const loginStats = computePercentiles(loginLatencies);
const sessionStats = computePercentiles(sessionLatencies);
const tokenStats = computePercentiles(tokenLatencies);
const corsUncachedStats = computePercentiles(corsUncachedLatencies);
const corsCachedStats = computePercentiles(corsCachedLatencies);

console.log("\n================================================================");
console.log("  BENCHMARK MEASUREMENT RESULTS (in milliseconds)");
console.log("================================================================");
console.log(`Environment: Node ${process.version}, Linux ${process.platform} ${process.arch}, Disposable MongoMemoryServer`);
console.log("----------------------------------------------------------------");
console.log("Operation                    | p50 (ms) | p95 (ms) | p99 (ms) | Avg (ms) | Min (ms) | Max (ms)");
console.log("-----------------------------|----------|----------|----------|----------|----------|----------");
console.log(`Login (/sign-in/email)       | ${String(loginStats.p50).padEnd(8)} | ${String(loginStats.p95).padEnd(8)} | ${String(loginStats.p99).padEnd(8)} | ${String(loginStats.avg).padEnd(8)} | ${String(loginStats.min).padEnd(8)} | ${String(loginStats.max)}`);
console.log(`Session (/get-session)       | ${String(sessionStats.p50).padEnd(8)} | ${String(sessionStats.p95).padEnd(8)} | ${String(sessionStats.p99).padEnd(8)} | ${String(sessionStats.avg).padEnd(8)} | ${String(sessionStats.min).padEnd(8)} | ${String(sessionStats.max)}`);
console.log(`Token Verify (RS256 JWKS)    | ${String(tokenStats.p50).padEnd(8)} | ${String(tokenStats.p95).padEnd(8)} | ${String(tokenStats.p99).padEnd(8)} | ${String(tokenStats.avg).padEnd(8)} | ${String(tokenStats.min).padEnd(8)} | ${String(tokenStats.max)}`);
console.log(`CORS Lookup (Uncached DB)    | ${String(corsUncachedStats.p50).padEnd(8)} | ${String(corsUncachedStats.p95).padEnd(8)} | ${String(corsUncachedStats.p99).padEnd(8)} | ${String(corsUncachedStats.avg).padEnd(8)} | ${String(corsUncachedStats.min).padEnd(8)} | ${String(corsUncachedStats.max)}`);
console.log(`CORS Lookup (Cached Hit)     | ${String(corsCachedStats.p50).padEnd(8)} | ${String(corsCachedStats.p95).padEnd(8)} | ${String(corsCachedStats.p99).padEnd(8)} | ${String(corsCachedStats.avg).padEnd(8)} | ${String(corsCachedStats.min).padEnd(8)} | ${String(corsCachedStats.max)}`);
console.log("================================================================\n");

console.log("Database Indexes Verified on Critical Paths:");
const collections = ["oauthClient", "user_app_registrations", "session", "user", "account"];
for (const col of collections) {
  try {
    const indexes = await db.collection(col).indexes();
    console.log(`\nCollection: ${col}`);
    for (const idx of indexes) {
      console.log(`  - ${idx.name}: ${JSON.stringify(idx.key)}`);
    }
  } catch (err: any) {
    console.log(`  (collection ${col} not found or no indexes)`);
  }
}

await closeDb();
await mongod.stop();
