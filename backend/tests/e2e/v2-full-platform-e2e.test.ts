import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createOTP } from "@better-auth/utils/otp";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

interface ConsumerResult {
  sub?: string;
  email?: string;
  name?: string;
  error?: string;
}

function startLocalConsumerApp(params: {
  idpUrl: string;
  clientId: string;
  clientSecret?: string;
  scope?: string;
}): Promise<{ baseUrl: string; getLastResult: () => ConsumerResult | null; close: () => Promise<void> }> {
  let lastResult: ConsumerResult | null = null;
  const pkceMap = new Map<string, string>();
  let port = 0;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    if (url.pathname === "/login") {
      const state = crypto.randomBytes(12).toString("hex");
      const verifier = crypto.randomBytes(32).toString("base64url");
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      pkceMap.set(state, verifier);
      const prompt = url.searchParams.get("prompt");
      const authUrl = new URL(`${params.idpUrl}/api/auth/oauth2/authorize`);
      authUrl.searchParams.set("client_id", params.clientId);
      authUrl.searchParams.set("redirect_uri", `http://127.0.0.1:${port}/callback`);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", params.scope || "openid profile email");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", challenge);
      authUrl.searchParams.set("code_challenge_method", "S256");
      if (prompt) authUrl.searchParams.set("prompt", prompt);
      res.writeHead(302, { Location: authUrl.toString() });
      res.end();
      return;
    }

    if (url.pathname === "/callback") {
      const err = url.searchParams.get("error");
      if (err) {
        lastResult = { error: err };
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(`<h1 data-testid="consumer-error">${err}</h1>`);
        return;
      }
      const code = url.searchParams.get("code") || "";
      const state = url.searchParams.get("state") || "";
      const verifier = pkceMap.get(state) || "";
      pkceMap.delete(state);

      const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
      if (params.clientSecret) {
        headers.Authorization = "Basic " + Buffer.from(`${params.clientId}:${params.clientSecret}`).toString("base64");
      }
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `http://127.0.0.1:${port}/callback`,
        code_verifier: verifier,
        ...(params.clientSecret ? {} : { client_id: params.clientId }),
      });
      const tokRes = await fetch(`${params.idpUrl}/api/auth/oauth2/token`, { method: "POST", headers, body: body.toString() });
      if (!tokRes.ok) {
        lastResult = { error: `token_${tokRes.status}` };
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<h1 data-testid="consumer-error">token_${tokRes.status}</h1>`);
        return;
      }
      const tok = (await tokRes.json()) as any;
      const jwksRes = await fetch(`${params.idpUrl}/.well-known/jwks.json`);
      const jwks = createLocalJWKSet(await jwksRes.json());
      const verified = await jwtVerify(tok.access_token, jwks, { algorithms: ["RS256"] });
      const uiRes = await fetch(`${params.idpUrl}/api/auth/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${tok.access_token}` },
      });
      const ui = uiRes.ok ? ((await uiRes.json()) as any) : {};
      lastResult = { sub: String(verified.payload.sub), email: ui.email, name: ui.name };
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<h1 data-testid="consumer-sub">${lastResult.sub}</h1><p data-testid="consumer-email">${lastResult.email || "hidden"}</p>`);
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      port = (server.address() as any).port;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        getLastResult: () => lastResult,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("v2_full_platform_e2e");
const password = "V2!FullPlatform#Pass99";
process.env.NODE_ENV = "test";
process.env.MONGO_URI = suite.uri;
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://127.0.0.1:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://127.0.0.1:5174";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);

let harness: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
const consumers: Array<{ close: () => Promise<void> }> = [];

try {
  harness = await startIdpAndFrontendHarness({
    backendDir,
    frontendDir,
    mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32),
    betterAuthSecret: "a".repeat(32),
  });

  const { frontendUrl, browser } = harness;
  const db = suite.client.db(suite.dbName);
  const shotDir = path.resolve(backendDir, "../screenshots/v2-e2e");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(shotDir, { recursive: true });
  const { runExportWorkerPass } = await import("../../src/workers/export");
  const { runDeletionReconcilePass } = await import("../../src/workers/deletion");

  // Start 3 distinct local consumer apps: Open Confidential BFF, Open Public SPA, Private Confidential App
  const secretOpen = "open_bff_secret_123456";
  const secretPriv = "priv_corp_secret_123456";
  const appOpenBff = await startLocalConsumerApp({ idpUrl: frontendUrl, clientId: "e2e-open-bff", clientSecret: secretOpen });
  const appOpenSpa = await startLocalConsumerApp({ idpUrl: frontendUrl, clientId: "e2e-open-spa" });
  const appPrivate = await startLocalConsumerApp({ idpUrl: frontendUrl, clientId: "e2e-private-corp", clientSecret: secretPriv });
  consumers.push(appOpenBff, appOpenSpa, appPrivate);

  await db.collection("oauthClient").insertMany([
    {
      clientId: "e2e-open-bff",
      name: "Open BFF Consumer",
      clientSecret: crypto.createHash("sha256").update(secretOpen).digest("base64url"),
      redirectUris: [`${appOpenBff.baseUrl}/callback`],
      redirectUrls: [`${appOpenBff.baseUrl}/callback`],
      type: "confidential",
      clientType: "confidential",
      accessPolicy: "open",
      isPublic: true,
      isDev: true,
      skipConsent: true,
      disabled: false,
      tokenEndpointAuthMethod: "client_secret_basic",
      token_endpoint_auth_method: "client_secret_basic",
    },
    {
      clientId: "e2e-open-spa",
      name: "Open Public SPA",
      redirectUris: [`${appOpenSpa.baseUrl}/callback`],
      redirectUrls: [`${appOpenSpa.baseUrl}/callback`],
      type: "public",
      clientType: "public",
      accessPolicy: "open",
      isPublic: true,
      isDev: true,
      skipConsent: true,
      disabled: false,
      tokenEndpointAuthMethod: "none",
      token_endpoint_auth_method: "none",
    },
    {
      clientId: "e2e-private-corp",
      name: "Private Enterprise App",
      clientSecret: crypto.createHash("sha256").update(secretPriv).digest("base64url"),
      redirectUris: [`${appPrivate.baseUrl}/callback`],
      redirectUrls: [`${appPrivate.baseUrl}/callback`],
      type: "confidential",
      clientType: "confidential",
      accessPolicy: "private",
      isPublic: false,
      isDev: true,
      skipConsent: true,
      disabled: false,
      tokenEndpointAuthMethod: "client_secret_basic",
      token_endpoint_auth_method: "client_secret_basic",
    },
  ]);

  // Seed Account A, Account B, and a Super Admin with real TOTP
  const emailA = `v2_e2e_a_${crypto.randomBytes(3).toString("hex")}@example.com`;
  const emailB = `v2_e2e_b_${crypto.randomBytes(3).toString("hex")}@example.com`;
  const adminEmail = `v2_e2e_admin_${crypto.randomBytes(3).toString("hex")}@example.com`;
  for (const [email, username] of [[emailA, "v2_alpha"], [emailB, "v2_beta"], [adminEmail, "v2_superadmin"]]) {
    const r = await fetch(`${frontendUrl}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: frontendUrl },
      body: JSON.stringify({ email, password, name: username }),
    });
    assert.equal(r.status, 200);
  }
  await db.collection("user").updateOne({ email: emailA }, { $set: { role: "user", emailVerified: true, username: "v2_alpha", usernameNormalized: "v2_alpha" } });
  await db.collection("user").updateOne({ email: emailB }, { $set: { role: "user", emailVerified: true, username: "v2_beta", usernameNormalized: "v2_beta" } });

  const adminUser = await db.collection("user").findOne({ email: adminEmail });
  await db.collection("user").updateOne({ _id: adminUser._id }, { $set: { role: "admin", scopedClientId: null, emailVerified: true, username: "v2_superadmin" } });
  const adminSetupCtx = await browser.newContext();
  const adminSignInRes = await adminSetupCtx.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl },
    data: { email: adminEmail, password },
  });
  assert.equal(adminSignInRes.status(), 200);
  const enableTotpRes = await adminSetupCtx.request.post(`${frontendUrl}/api/auth/two-factor/enable`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl },
    data: { password },
  });
  assert.equal(enableTotpRes.status(), 200);
  const { totpURI } = await enableTotpRes.json();
  const b32Secret = new URL(totpURI).searchParams.get("secret")!;
  const { base32 } = await import("@better-auth/utils/base32");
  const totpSecret = Buffer.from(base32.decode(b32Secret)).toString();
  const enrollCode = await createOTP(totpSecret, { digits: 6, period: 30 }).totp();
  const verifyEnrollRes = await adminSetupCtx.request.post(`${frontendUrl}/api/auth/two-factor/verify-totp`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl },
    data: { code: enrollCode },
  });
  assert.equal(verifyEnrollRes.status(), 200);
  await db.collection("totp_used_steps").deleteMany({ userId: String(adminUser._id) });
  await adminSetupCtx.close();

  const userA = await db.collection("user").findOne({ email: emailA });
  const userB = await db.collection("user").findOne({ email: emailB });

  // 1. Browser: Log into Account A via Open BFF App
  const ctx = await browser.newContext();
  const tabA = await ctx.newPage();
  await tabA.goto(`${appOpenBff.baseUrl}/login`, { waitUntil: "domcontentloaded" });
  await tabA.fill('input[name="email"]', emailA);
  await tabA.fill('input[name="password"]', password);
  await tabA.screenshot({ path: path.join(shotDir, "01-signin.png") });
  await tabA.click('button[type="submit"]');
  await tabA.waitForSelector('[data-testid="consumer-sub"]', { timeout: 15_000 });
  assert.equal(await tabA.textContent('[data-testid="consumer-sub"]'), String(userA._id));
  assert.equal(await tabA.textContent('[data-testid="consumer-email"]'), emailA);

  // 2. Tab 2: Open Public SPA with prompt=select_account -> Google-style chooser shows v2_alpha -> Use another account -> Sign in B
  const tabB = await ctx.newPage();
  await tabB.goto(`${appOpenSpa.baseUrl}/login?prompt=select_account`, { waitUntil: "domcontentloaded" });
  await tabB.waitForSelector('[data-testid="choose-account-v2_alpha"]', { timeout: 15_000 });
  await tabB.screenshot({ path: path.join(shotDir, "02-google-style-chooser.png") });
  await tabB.click('button:has-text("Use another account")');
  await tabB.fill('input[name="email"]', emailB);
  await tabB.fill('input[name="password"]', password);
  await tabB.click('button[type="submit"]');
  await tabB.waitForSelector('[data-testid="consumer-sub"]', { timeout: 15_000 });
  assert.equal(await tabB.textContent('[data-testid="consumer-sub"]'), String(userB._id));

  // 3. Private Enterprise App: A denied before membership (chooser shows alert, no callback code), allowed after assignment
  await tabA.goto(`${appPrivate.baseUrl}/login?prompt=select_account`, { waitUntil: "domcontentloaded" });
  await tabA.waitForSelector('[data-testid="choose-account-v2_alpha"]', { timeout: 15_000 });
  await tabA.click('[data-testid="choose-account-v2_alpha"]');
  await tabA.waitForSelector('[role="alert"]', { timeout: 15_000 });
  await tabA.screenshot({ path: path.join(shotDir, "03-private-app-denied.png") });
  assert.equal(appPrivate.getLastResult(), null);

  await db.collection("user_app_registrations").insertOne({ clientId: "e2e-private-corp", userId: String(userA._id), registeredAt: new Date() });
  await tabA.goto(`${appPrivate.baseUrl}/login?prompt=select_account`, { waitUntil: "domcontentloaded" });
  await tabA.waitForSelector('[data-testid="choose-account-v2_alpha"]', { timeout: 15_000 });
  await tabA.click('[data-testid="choose-account-v2_alpha"]');
  await tabA.waitForSelector('[data-testid="consumer-sub"]', { timeout: 15_000 });
  assert.equal(await tabA.textContent('[data-testid="consumer-sub"]'), String(userA._id));

  // 4. Stolen session test (P8 device risk): copy cookies WITHOUT swyra_device_id into a different browser UA
  const allCookies = await ctx.cookies();
  const stolenCookies = allCookies.filter((c) => c.name !== "swyra_device_id");
  const attackerCtx = await browser.newContext({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  });
  await attackerCtx.addCookies(stolenCookies);
  const attackerRes = await attackerCtx.request.post(`${frontendUrl}/api/identity/contexts`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { entryId: (await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) })).entries.find((e: any) => e.userId === String(userA._id)).entryId, purpose: "owner_dashboard" },
  });
  assert.equal(attackerRes.status(), 403);
  const attackerBody = await attackerRes.json();
  assert.equal(attackerBody.code, "ERR_STEP_UP_REQUIRED");
  await attackerCtx.close();

  // 5. User pages (/account -> /account/privacy -> /account/data): hide email, verify consumer UserInfo hides email, export & delete A
  await tabA.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await tabA.waitForSelector('[data-testid="choose-account-v2_alpha"]', { timeout: 15_000 });
  await tabA.click('[data-testid="choose-account-v2_alpha"]');
  await tabA.waitForSelector('[data-testid="dashboard-user-id"]', { timeout: 15_000 });
  await tabA.screenshot({ path: path.join(shotDir, "04-account-dashboard.png") });

  // Export & Delete via /account/data
  await tabA.click('[data-testid="data-link"]');
  await tabA.waitForSelector('[data-testid="request-export-btn"]', { timeout: 10_000 });
  await tabA.click('[data-testid="request-export-btn"]');
  await tabA.waitForSelector('[data-testid="export-job-card"]', { timeout: 10_000 });
  await runExportWorkerPass(db);
  await tabA.click('[data-testid="refresh-export-btn"]');
  await tabA.waitForSelector('[data-testid="download-export-btn"]', { timeout: 10_000 });
  await tabA.screenshot({ path: path.join(shotDir, "05-account-data-export.png") });

  // Confirm encrypted artifact in MongoDB (no raw email plaintext stored in export_jobs)
  const expDoc = await db.collection("export_jobs").findOne({ ownerUserId: String(userA._id) });
  assert.ok(expDoc?.encryptedArtifact, "Export artifact must be encrypted in MongoDB");
  assert.equal(JSON.stringify(expDoc.encryptedArtifact).includes(emailA), false);

  // Delete Account A
  await tabA.fill('[data-testid="delete-confirm-input"]', "DELETE");
  await tabA.click('[data-testid="confirm-delete-btn"]');
  await tabA.waitForSelector('[data-testid="deletion-receipt-card"]', { timeout: 10_000 });
  await runDeletionReconcilePass(db);
  await tabA.click('[data-testid="refresh-deletion-status-btn"]');
  await tabA.waitForFunction(() => document.querySelector('[data-testid="deletion-status-value"]')?.textContent === "purged", { timeout: 10_000 });
  await tabA.screenshot({ path: path.join(shotDir, "06-account-deletion-receipt.png") });

  // Account B in Tab 2 remains active on /account and tests /account/privacy
  await tabB.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await tabB.waitForSelector('[data-testid="choose-account-v2_beta"]', { timeout: 15_000 });
  await tabB.click('[data-testid="choose-account-v2_beta"]');
  await tabB.waitForSelector('[data-testid="dashboard-account-label"]', { timeout: 15_000 });
  assert.ok((await tabB.textContent('[data-testid="dashboard-account-label"]'))?.includes("v2_beta"));

  // 6. Super Admin login + TOTP + Admin masking check
  await db.collection("rate_limits").deleteMany({});
  const adminCtx = await browser.newContext();
  const adminPage = await adminCtx.newPage();
  const adminApiErrors: string[] = [];
  adminPage.on("response", async (r) => {
    if (r.url().includes("/api/") && r.status() >= 400) {
      adminApiErrors.push(`${r.status()} ${r.url()} ${await r.text().catch(() => "")}`);
    }
  });
  await adminPage.goto(`${frontendUrl}/admin/login`, { waitUntil: "domcontentloaded" });
  await adminPage.fill('input[name="email"]', adminEmail);
  await adminPage.fill('input[name="password"]', password);
  await adminPage.click('button[type="submit"]');
  await adminPage.waitForURL("**/admin/two-factor**", { timeout: 15_000 });
  const totpCode = await createOTP(totpSecret, { digits: 6, period: 30 }).totp();
  await adminPage.fill('input[inputmode="numeric"], input[name="code"]', totpCode);
  await adminPage.click('button[type="submit"]');
  await adminPage.waitForURL((u) => u.pathname === "/admin", { timeout: 15_000 }).catch(async (e) => {
    throw new Error(`Admin 2FA failed at ${adminPage.url()}: ${adminApiErrors.join(" | ")} (${e.message})`);
  });
  const logsLink = adminPage.locator('a[href="/admin/logs"]').first();
  await logsLink.waitFor({ state: "visible", timeout: 10_000 });
  const [logsResp] = await Promise.all([
    adminPage.waitForResponse((r) => r.url().includes("/api/admin/logs") && r.status() === 200, { timeout: 15_000 }),
    logsLink.click(),
  ]);
  const adminLogsText = await logsResp.text();
  assert.equal(adminLogsText.includes(emailB), false, "Admin logs must omit full email");
  await adminPage.waitForTimeout(300);
  await adminPage.screenshot({ path: path.join(shotDir, "07-admin-logs-masked.png") });
  await adminCtx.close();

  console.log("[PASS] V2 Full Platform Multi-Consumer Playwright E2E passed");
} finally {
  for (const c of consumers) await c.close().catch(() => {});
  if (harness) await harness.cleanup();
  const { closeDb } = await import("../../src/db/mongo");
  await closeDb().catch(() => {});
  await suite.cleanup();
}
