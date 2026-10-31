import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { MongoMemoryServer } from "mongodb-memory-server";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const scratchDir = "/home/swyra/.gemini/antigravity/brain/0245a90d-85b5-4a36-85e2-ded87f7ddbe3/scratch";
if (!fs.existsSync(scratchDir)) {
  fs.mkdirSync(scratchDir, { recursive: true });
}

console.log("=== Starting Disposable MongoDB ===");
const mongod = await MongoMemoryServer.create();
const mongoUri = mongod.getUri();
console.log("Mongo URI:", mongoUri);

process.env.NODE_ENV = "test";
process.env.MONGO_URI = mongoUri;
process.env.BETTER_AUTH_SECRET = "b".repeat(32);
process.env.BETTER_AUTH_URL = "http://127.0.0.1:3300";
process.env.FRONTEND_URL = "http://127.0.0.1:5174";
const GATEWAY_SECRET = "g".repeat(32);
process.env.INTERNAL_GATEWAY_SECRET = GATEWAY_SECRET;
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8";

const { getDb } = await import("../src/db/mongo");
const { authProvider } = await import("../src/utils/auth");
const db = await getDb();

// -----------------------------------------------------------------------------
// Seed Clients
// -----------------------------------------------------------------------------
const clientA = "client-private-app-a";
const clientASecret = "secret-app-a-1234567890";
const clientAHash = crypto.createHash("sha256").update(clientASecret).digest("base64url");
const clientACallback = "http://127.0.0.1:4400/auth/callback";

const clientB = "client-private-app-b";
const clientBSecret = "secret-app-b-1234567890";
const clientBHash = crypto.createHash("sha256").update(clientBSecret).digest("base64url");
const clientBCallback = "http://127.0.0.1:4400/auth/callback-b";

await db.collection("oauthClient").insertMany([
  {
    id: clientA,
    clientId: clientA,
    clientSecret: clientAHash,
    name: "Private App A",
    redirectUris: [clientACallback],
    allowedOrigins: ["http://127.0.0.1:4400", "http://127.0.0.1:5174"],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
  {
    id: clientB,
    clientId: clientB,
    clientSecret: clientBHash,
    name: "Private App B",
    redirectUris: [clientBCallback],
    allowedOrigins: ["http://127.0.0.1:4400", "http://127.0.0.1:5174"],
    isPublic: false,
    isDev: true,
    skipConsent: true,
    skip_consent: true,
    disabled: false,
    createdAt: new Date(),
  },
]);

// -----------------------------------------------------------------------------
// Seed Users
// -----------------------------------------------------------------------------

// 1. Super Admin with MFA
const superMfaEmail = "super_mfa@swyra.com";
const superMfaPass = "SuperMfaPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: superMfaEmail, password: superMfaPass, name: "Super Admin MFA" },
});
await db.collection("user").updateOne(
  { email: superMfaEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);
const superPreSignIn = await authProvider.api.signInEmail({
  body: { email: superMfaEmail, password: superMfaPass },
  asResponse: true,
});
const superPreCookie = (superPreSignIn.headers.get("set-cookie") || "").split(";")[0];
const super2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: superMfaPass, method: "totp" },
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

// 2. Super Admin without MFA
const superNonMfaEmail = "super_nonmfa@swyra.com";
const superNonMfaPass = "SuperNonMfaPass123!Aa";
await authProvider.api.signUpEmail({
  body: { email: superNonMfaEmail, password: superNonMfaPass, name: "Super Admin Non-MFA" },
});
await db.collection("user").updateOne(
  { email: superNonMfaEmail },
  { $set: { role: "super-admin", scopedClientId: null, emailVerified: true } }
);

// 3. App Admin A with MFA
const appAdminMfaEmail = "admin_mfa_a@example.com";
const appAdminMfaPass = "AppAdminMfaPass123!Aa";
const appAdminMfaSignUp = await authProvider.api.signUpEmail({
  body: { email: appAdminMfaEmail, password: appAdminMfaPass, name: "App Admin A MFA" },
});
const appAdminMfaId = String(appAdminMfaSignUp.user.id);
await db.collection("user").updateOne(
  { email: appAdminMfaEmail },
  { $set: { role: "app-admin", scopedClientId: clientA, emailVerified: true } }
);
await db.collection("user_app_registrations").insertOne({
  userId: appAdminMfaId,
  clientId: clientA,
  appRole: "admin",
  status: "active",
  registeredAt: new Date(),
});
const adminPreSignIn = await authProvider.api.signInEmail({
  body: { email: appAdminMfaEmail, password: appAdminMfaPass },
  asResponse: true,
});
const adminPreCookie = (adminPreSignIn.headers.get("set-cookie") || "").split(";")[0];
const admin2faSetup = await authProvider.api.enableTwoFactor({
  body: { password: appAdminMfaPass, method: "totp" },
  headers: new Headers({ cookie: adminPreCookie }),
});
const adminB32Secret = new URL(admin2faSetup.totpURI).searchParams.get("secret")!;
const adminRawSecret = new TextDecoder().decode(base32.decode(adminB32Secret));
const adminBackupCodes = admin2faSetup.backupCodes;
const adminInitCode = await createOTP(adminRawSecret, { digits: 6, period: 30 }).totp();
await authProvider.api.verifyTOTP({
  body: { code: adminInitCode },
  headers: new Headers({ cookie: adminPreCookie }),
  asResponse: true,
});

// 4. App Admin A without MFA
const appAdminNonMfaEmail = "admin_nonmfa_a@example.com";
const appAdminNonMfaPass = "AppAdminNonMfaPass123!Aa";
const appAdminNonMfaSignUp = await authProvider.api.signUpEmail({
  body: { email: appAdminNonMfaEmail, password: appAdminNonMfaPass, name: "App Admin A Non-MFA" },
});
const appAdminNonMfaId = String(appAdminNonMfaSignUp.user.id);
await db.collection("user").updateOne(
  { email: appAdminNonMfaEmail },
  { $set: { role: "app-admin", scopedClientId: clientA, emailVerified: true } }
);
await db.collection("user_app_registrations").insertOne({
  userId: appAdminNonMfaId,
  clientId: clientA,
  appRole: "admin",
  status: "active",
  registeredAt: new Date(),
});

// Save credentials
const creds = {
  superMfa: { email: superMfaEmail, password: superMfaPass, secret: superRawSecret, b32Secret: superB32Secret },
  superNonMfa: { email: superNonMfaEmail, password: superNonMfaPass },
  appAdminMfa: { email: appAdminMfaEmail, password: appAdminMfaPass, secret: adminRawSecret, b32Secret: adminB32Secret, backupCodes: adminBackupCodes },
  appAdminNonMfa: { email: appAdminNonMfaEmail, password: appAdminNonMfaPass },
  clientA: { id: clientA, secret: clientASecret, callback: clientACallback },
  clientB: { id: clientB, secret: clientBSecret, callback: clientBCallback },
};
fs.writeFileSync(path.join(scratchDir, "test-creds.json"), JSON.stringify(creds, null, 2));
console.log("Credentials written to", path.join(scratchDir, "test-creds.json"));

// -----------------------------------------------------------------------------
// Launch Services
// -----------------------------------------------------------------------------

// 1. Backend Node Server
console.log("Spawning IdP Backend on port 3300...");
const idpProc = spawn(
  process.execPath,
  [path.join(repoRoot, "backend/node_modules/tsx/dist/cli.mjs"), path.join(repoRoot, "backend/src/node-server.ts")],
  {
    cwd: path.join(repoRoot, "backend"),
    env: {
      ...process.env,
      PORT: "3300",
      MONGO_URI: mongoUri,
      BETTER_AUTH_SECRET: "b".repeat(32),
      BETTER_AUTH_URL: "http://127.0.0.1:3300",
      FRONTEND_URL: "http://127.0.0.1:5174",
      AUTH_PUBLIC_SIGNUP_ENABLED: "true",
      INTERNAL_GATEWAY_SECRET: GATEWAY_SECRET,
      TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.0.0.0/8",
    },
    stdio: "inherit",
  }
);

// 2. Custom Frontend SPA Gateway Server (serves dist + proxies /api)
console.log("Starting Frontend SPA Gateway on port 5174...");
const distDir = path.join(repoRoot, "frontend/dist");
const MIME_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

const feServer = http.createServer(async (req, res) => {
  const url = req.url || "/";

  // Test API helpers for browser verification
  if (url === "/test-api/creds") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(creds));
    return;
  }
  if (url === "/test-api/reset-ratelimit") {
    await db.collection("rate_limits").deleteMany({});
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (url.startsWith("/test-api/totp")) {
    const parsed = new URL(url, "http://127.0.0.1:5174");
    const account = parsed.searchParams.get("account");
    const secret = account === "superMfa" ? creds.superMfa.secret : creds.appAdminMfa.secret;
    const code = await createOTP(secret, { digits: 6, period: 30 }).totp();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ code }));
    return;
  }

  // Proxy /api requests to backend on port 3300
  if (url.startsWith("/api/")) {
    const proxyReq = http.request(
      `http://127.0.0.1:3300${url}`,
      {
        method: req.method,
        headers: {
          ...req.headers,
          host: "127.0.0.1:3300",
          "x-gateway-secret": GATEWAY_SECRET,
          "x-forwarded-for": "127.0.0.1",
        },
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode!, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );
    proxyReq.on("error", (err) => {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "gateway_proxy_error", message: err.message }));
    });
    req.pipe(proxyReq);
    return;
  }

  // Static files or SPA fallback
  const cleanPath = url.split("?")[0];
  const filePath = path.join(distDir, cleanPath === "/" ? "index.html" : cleanPath);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);
    res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(200, { "Content-Type": "text/html" });
    fs.createReadStream(path.join(distDir, "index.html")).pipe(res);
  }
});

await new Promise<void>((resolve) => {
  feServer.listen(5174, "127.0.0.1", () => {
    console.log("[PASS] Frontend SPA Gateway ready at http://127.0.0.1:5174");
    resolve();
  });
});

// 3. Express Consumer on port 4400
console.log("Spawning Express Consumer on port 4400...");
const expressProc = spawn(
  process.execPath,
  [path.join(repoRoot, "test/react-express-app/backend/dist/index.js")],
  {
    cwd: path.join(repoRoot, "test/react-express-app/backend"),
    env: {
      ...process.env,
      PORT: "4400",
      NODE_ENV: "development",
      AUTH_ISSUER: "http://127.0.0.1:3300",
      CLIENT_ID: clientA,
      CLIENT_SECRET: clientASecret,
      AUTH_CALLBACK_URL: clientACallback,
      CLIENT_ORIGIN: "http://127.0.0.1:4400/auth/me",
    },
    stdio: "inherit",
  }
);

function cleanup() {
  console.log("Shutting down all services...");
  idpProc.kill("SIGTERM");
  feServer.close();
  expressProc.kill("SIGTERM");
  mongod.stop();
  process.exit(0);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
process.on("exit", cleanup);

console.log("\n================================================================");
console.log("  ALL VERIFICATION SERVERS READY & RUNNING");
console.log("================================================================\n");
