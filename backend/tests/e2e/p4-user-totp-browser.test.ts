import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { Buffer } from "node:buffer";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p4_user_totp_browser");
const password = "P4!Totp#Password99";

let harness: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
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
  const email = `totp_browser_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const clientId = `p4_totp_client_${crypto.randomBytes(4).toString("hex")}`;
  const redirectUri = `${frontendUrl}/oauth-callback-dummy`;

  await db.collection("oauthClient").insertOne({
    clientId,
    name: "P4 TOTP Browser Test App",
    redirectUris: [redirectUri],
    type: "public",
    tokenEndpointAuthMethod: "none",
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
    isPublic: true,
    isDev: true,
    clientType: "public",
    accessPolicy: "open",
    disabled: false,
    skipConsent: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const context = await browser.newContext();
  const page = await context.newPage();

  // 1. Sign up and sign in
  const signUpRes = await context.request.post(`${frontendUrl}/api/auth/sign-up/email`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { email, password, name: "P4 TOTP User" },
  });
  assert.equal(signUpRes.status(), 200);
  await db.collection("user").updateOne({ email }, { $set: { emailVerified: true } });

  const signInInitRes = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { email, password },
  });
  assert.equal(signInInitRes.status(), 200);

  await page.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await page.getByText("P4 TOTP User").click();
  await page.waitForSelector('[data-testid="dashboard-user-id"]', { timeout: 10_000 });

  // 2. Enroll TOTP from /account
  await page.fill('input[placeholder*="password" i], input[type="password"]', password);
  await page.click('[data-testid="totp-enable-btn"], button:has-text("Enable TOTP")');

  const secretEl = page.locator('[data-testid="totp-manual-secret"], code').first();
  await secretEl.waitFor({ state: "visible", timeout: 10_000 });
  const b32Secret = (await secretEl.innerText()).trim().replace(/\s+/g, "");
  assert.ok(b32Secret.length >= 16, `Expected base32 secret, got ${b32Secret}`);
  const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();

  const enrollCode = await createOTP(rawSecret, { digits: 6, period: 30 }).totp();
  await page.fill('[data-testid="totp-code-input"], input[placeholder*="6-digit"]', enrollCode);
  await page.click('[data-testid="totp-verify-btn"], button:has-text("Verify & Enable")');
  const doneBtn = page.locator('button:has-text("Done")');
  await doneBtn.waitFor({ state: "visible", timeout: 10_000 });
  await doneBtn.click();
  await page.reload({ waitUntil: "networkidle" });
  await page.getByText("P4 TOTP User").click();
  await page.locator('[data-testid="totp-start-disable-btn"], button:has-text("Disable TOTP")').waitFor({ state: "visible", timeout: 15_000 });

  // 3. Sign out and start OAuth sign-in with TOTP challenge
  await context.clearCookies();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const state = crypto.randomBytes(16).toString("hex");
  const authUrl = `${frontendUrl}/api/auth/oauth2/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20profile&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;
  await page.goto(authUrl, { waitUntil: "domcontentloaded" });

  // 4. Sign in with TOTP challenge
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/two-factor**", { timeout: 15_000 });

  const loginCode = await createOTP(rawSecret, { digits: 6, period: 30 }).hotp(Math.floor(Date.now() / 30000) + 1);
  await page.fill('input[inputmode="numeric"], input[name="code"]', loginCode);
  await page.click('button[type="submit"]');

  // 5. Consumer OAuth callback & token exchange
  await page.waitForURL((u) => u.toString().startsWith(redirectUri), { timeout: 15_000 });
  const cbUrl = new URL(page.url());
  const code = cbUrl.searchParams.get("code");
  assert.ok(code, "OAuth authorize must return authorization code");
  assert.equal(cbUrl.searchParams.get("state"), state);

  const tokenRes = await context.request.post(`${frontendUrl}/api/auth/oauth2/token`, {
    headers: { Origin: frontendUrl },
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    },
  });
  assert.equal(tokenRes.status(), 200, `OAuth token exchange must succeed: ${await tokenRes.text()}`);
  const tokenJson = await tokenRes.json();
  assert.ok(tokenJson.access_token, "Token response must include access_token");

  // 6. Authorized disable from /account
  await page.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await page.getByText("P4 TOTP User").click();
  await page.waitForSelector('[data-testid="dashboard-user-id"]', { timeout: 10_000 });
  await page.click('button:has-text("Disable TOTP")');
  await page.fill('input[type="password"]', password);
  const disableCode = await createOTP(rawSecret, { digits: 6, period: 30 }).hotp(Math.floor(Date.now() / 30000) - 1);
  await page.fill('[data-testid="totp-code-input"], input[placeholder*="6-digit"]', disableCode);
  await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/identity/totp/disable") && r.status() === 200),
    page.click('button:has-text("Confirm Disable")'),
  ]);
  await page.reload({ waitUntil: "networkidle" });
  await page.getByText("P4 TOTP User").click();
  await page.locator('[data-testid="totp-enable-btn"], button:has-text("Enable TOTP")').waitFor({ state: "visible", timeout: 10_000 });

  console.log("[PASS] P4 Ordinary-User TOTP Browser E2E (enroll, sign-out, TOTP sign-in, OAuth, disable)");
} finally {
  if (harness) await harness.cleanup();
  await suite.cleanup();
}
