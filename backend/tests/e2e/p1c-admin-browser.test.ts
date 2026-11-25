import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

console.log("================================================================");
console.log("  SWYRA AUTH -- P1C ADMIN BROWSER ACCEPTANCE SUITE (BAC-P1C-01..06)");
console.log("================================================================\n");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, "../../");
const frontendDir = path.resolve(backendDir, "../frontend");
const gatewaySecret = "g".repeat(32);
const betterAuthSecret = "a".repeat(32);

const suite = await setupSuiteDatabase("p1c_admin_browser");
const db = suite.client.db();
let harness: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;

async function signInAdminBrowser(page: any, frontendUrl: string, email: string, password: string, totpRawSecret: string) {
  const { createOTP } = await import("@better-auth/utils/otp");
  await page.goto(`${frontendUrl}/admin/login`, { waitUntil: "networkidle" });
  await page.fill('input[name="email"]', email);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/two-factor**", { timeout: 15000 });
  const code = await createOTP(totpRawSecret, { digits: 6, period: 30 }).totp();
  await page.fill('input[name="code"], input[inputmode="numeric"]', code);
  await page.click('button[type="submit"]');
}

async function enrollTotpApi(idpUrl: string, email: string, password: string): Promise<string> {
  const { createOTP } = await import("@better-auth/utils/otp");
  const { base32 } = await import("@better-auth/utils/base32");
  const loginRes = await fetch(`${idpUrl}/api/auth/sign-in/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: idpUrl, "x-gateway-secret": gatewaySecret },
    body: JSON.stringify({ email, password }),
  });
  const cookie = (loginRes.headers.get("set-cookie") || "").split(";")[0];
  const enableRes = await fetch(`${idpUrl}/api/auth/two-factor/enable`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie, Origin: idpUrl, "x-gateway-secret": gatewaySecret },
    body: JSON.stringify({ password }),
  });
  const { totpURI } = await enableRes.json();
  const b32Secret = new URL(totpURI).searchParams.get("secret")!;
  const rawSecret = Buffer.from(base32.decode(b32Secret)).toString();
  const code = await createOTP(rawSecret, { digits: 6, period: 30 }).hotp(Math.floor(Date.now() / 30000) - 1);
  await fetch(`${idpUrl}/api/auth/two-factor/verify-totp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie, Origin: idpUrl, "x-gateway-secret": gatewaySecret },
    body: JSON.stringify({ code }),
  });
  return rawSecret;
}

try {
  harness = await startIdpAndFrontendHarness({
    backendDir,
    frontendDir,
    mongoUri: suite.uri,
    gatewaySecret,
    betterAuthSecret,
  });

  const password = "AdminPassword@1234!";
  const superEmail = `super_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const appAdminEmail = `scoped_${crypto.randomBytes(4).toString("hex")}@example.com`;

  for (const [email, name] of [[superEmail, "Super Admin"], [appAdminEmail, "Scoped Admin"]] as const) {
    const res = await fetch(`${harness.idpUrl}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: harness.idpUrl },
      body: JSON.stringify({ email, password, name }),
    });
    assert.equal(res.status, 200);
  }
  await db.collection("user").updateOne({ email: superEmail }, { $set: { role: "super-admin", scopedClientId: null } });

  const scopedClientId = `scoped-client-${crypto.randomBytes(4).toString("hex")}`;
  const scopedSecretHash = crypto.createHash("sha256").update("scoped-secret-123").digest("base64url");
  await db.collection("oauthClient").insertOne({
    id: scopedClientId,
    clientId: scopedClientId,
    clientSecret: scopedSecretHash,
    name: "Scoped Tenant App",
    redirectUris: ["https://scoped-app.example.com/cb"],
    allowedOrigins: ["https://scoped-app.example.com"],
    clientType: "confidential",
    accessPolicy: "private",
    isPublic: false,
    isDev: false,
    tokenEndpointAuthMethod: "client_secret_basic",
    createdAt: new Date(),
  });
  const appAdminDoc = await db.collection("user").findOne({ email: appAdminEmail });
  await db.collection("user").updateOne({ email: appAdminEmail }, { $set: { role: "app-admin", scopedClientId } });
  await db.collection("app_admins").insertOne({ userId: appAdminDoc!.id || String(appAdminDoc!._id), clientId: scopedClientId, email: appAdminEmail, isActive: true, createdAt: new Date() });

  const ambigClientId = `ambig-client-${crypto.randomBytes(4).toString("hex")}`;
  await db.collection("oauthClient").insertOne({
    id: ambigClientId,
    clientId: ambigClientId,
    name: "Legacy Ambiguous App",
    redirectUris: ["https://ambig.example.com/cb#badfrag"],
    createdAt: new Date(Date.now() - 10000),
  });

  const superTotp = await enrollTotpApi(harness.idpUrl, superEmail, password);
  const appAdminTotp = await enrollTotpApi(harness.idpUrl, appAdminEmail, password);

  const superCtx = await harness.browser.newContext();
  const page = await superCtx.newPage();
  await signInAdminBrowser(page, harness.frontendUrl, superEmail, password, superTotp);
  await page.waitForURL("**/admin", { timeout: 15000 });
  await page.goto(`${harness.frontendUrl}/admin/clients`, { waitUntil: "networkidle" });

  // BAC-P1C-01: Register clean Open Public client
  await page.click('button:has-text("Create application")');
  await page.waitForSelector('input[name="clientType"][value="confidential"]:checked');
  await page.waitForSelector('input[name="accessPolicy"][value="private"]:checked');
  await page.click('input[name="clientType"][value="public"]');
  await page.click('input[name="accessPolicy"][value="open"]');
  await page.fill('input[placeholder="e.g. Customer Portal"]', "BAC Open Public App");
  await page.fill('input[placeholder*="callback"]', "https://open-pub.example.com/cb");
  await page.click('button:has-text("Add") >> nth=0');
  await page.click('button[type="submit"]:has-text("Register application")');
  await page.waitForSelector('button:has-text("Done")', { timeout: 10000 });
  assert.equal(await page.getByText('Client Secret', { exact: true }).count(), 0, "Public client must not display secret field");
  assert.equal(await page.locator('button:has-text("Copy secret")').count(), 0, "Public client must not render Copy secret button");
  await page.click('button:has-text("Done")');
  await page.locator("tr", { hasText: "BAC Open Public App" }).waitFor({ state: "visible", timeout: 10000 });
  const openPubDoc = await db.collection("oauthClient").findOne({ name: "BAC Open Public App" });
  assert.equal(openPubDoc?.clientType, "public");
  assert.equal(openPubDoc?.accessPolicy, "open");
  assert.equal(openPubDoc?.clientSecret, undefined);
  console.log("[PASS] BAC-P1C-01: Registered clean Open Public client via browser UI");

  // BAC-P1C-02: Register clean Private Confidential client
  await page.click('button:has-text("Create application")');
  await page.fill('input[placeholder="e.g. Customer Portal"]', "BAC Priv Conf App");
  await page.fill('input[placeholder*="callback"]', "https://priv-conf.example.com/cb");
  await page.click('button:has-text("Add") >> nth=0');
  await page.click('button[type="submit"]:has-text("Register application")');
  await page.waitForSelector('text=Client Secret', { timeout: 10000 });
  await page.click('button:has-text("Copy secret")');
  await page.click('button:has-text("Done")');
  const privConfDoc = await db.collection("oauthClient").findOne({ name: "BAC Priv Conf App" });
  assert.equal(privConfDoc?.clientType, "confidential");
  assert.equal(privConfDoc?.accessPolicy, "private");
  assert.ok(privConfDoc?.clientSecret);
  console.log("[PASS] BAC-P1C-02: Registered clean Private Confidential client with one-time secret");

  // BAC-P1C-03: Register clean Open Confidential client
  await page.click('button:has-text("Create application")');
  await page.click('input[name="accessPolicy"][value="open"]');
  await page.fill('input[placeholder="e.g. Customer Portal"]', "BAC Open Conf App");
  await page.fill('input[placeholder*="callback"]', "https://open-conf.example.com/cb");
  await page.click('button:has-text("Add") >> nth=0');
  await page.click('button[type="submit"]:has-text("Register application")');
  await page.waitForSelector('button:has-text("Copy secret")', { timeout: 10000 });
  await page.click('button:has-text("Copy secret")');
  await page.click('button:has-text("Done")');
  const openConfDoc = await db.collection("oauthClient").findOne({ name: "BAC Open Conf App" });
  assert.equal(openConfDoc?.clientType, "confidential");
  assert.equal(openConfDoc?.accessPolicy, "open");
  console.log("[PASS] BAC-P1C-03: Registered clean Open Confidential client");

  // BAC-P1C-04: Register clean Private Public client
  await page.click('button:has-text("Create application")');
  await page.click('input[name="clientType"][value="public"]');
  await page.fill('input[placeholder="e.g. Customer Portal"]', "BAC Priv Pub App");
  await page.fill('input[placeholder*="callback"]', "https://priv-pub.example.com/cb");
  await page.click('button:has-text("Add") >> nth=0');
  await page.click('button[type="submit"]:has-text("Register application")');
  await page.waitForSelector('button:has-text("Done")', { timeout: 10000 });
  assert.equal(await page.getByText('Client Secret', { exact: true }).count(), 0);
  assert.equal(await page.locator('button:has-text("Copy secret")').count(), 0);
  await page.click('button:has-text("Done")');
  const privPubDoc = await db.collection("oauthClient").findOne({ name: "BAC Priv Pub App" });
  assert.equal(privPubDoc?.clientType, "public");
  assert.equal(privPubDoc?.accessPolicy, "private");
  console.log("[PASS] BAC-P1C-04: Registered clean Private Public client");

  // BAC-P1C-05: Remediate Ambiguous legacy client
  const ambigRow = page.locator("tr", { hasText: "Legacy Ambiguous App" });
  await ambigRow.getByText("Ambiguous", { exact: true }).waitFor({ state: "visible" });
  await ambigRow.locator('button:has-text("Edit")').click();
  await page.waitForSelector('text=Ambiguous configuration requiring administrative review');
  await page.waitForSelector('text=MISSING_ACCESS_METADATA');
  await page.click('input[name="clientType"][value="public"]');
  await page.click('input[name="accessPolicy"][value="open"]');
  await page.click('button[aria-label*="ambig.example.com/cb#badfrag"]');
  await page.fill('input[placeholder*="callback"]', "https://ambig.example.com/cb");
  await page.click('button:has-text("Add") >> nth=0');
  const confirmOpenCheckbox = page.locator('input[type="checkbox"][data-confirm="widening-access"], button[role="checkbox"][data-confirm="widening-access"]');
  if (await confirmOpenCheckbox.count()) await confirmOpenCheckbox.click();
  await page.click('button[type="submit"]:has-text("Save changes")');
  await page.waitForTimeout(1500);
  await ambigRow.getByText("Migrated", { exact: true }).waitFor({ state: "visible", timeout: 10000 });
  assert.equal(await ambigRow.getByText("Ambiguous", { exact: true }).count(), 0);
  const fixedDoc = await db.collection("oauthClient").findOne({ clientId: ambigClientId });
  assert.equal(fixedDoc?.clientType, "public");
  assert.equal(fixedDoc?.accessPolicy, "open");
  console.log("[PASS] BAC-P1C-05: Remediated ambiguous client to Migrated");
  // Also verify credential transitions (Confidential -> Public with confirmation & Public -> Confidential one-time secret) + widening confirm + blur validation
  const privConfRow = page.locator("tr", { hasText: "BAC Priv Conf App" });
  await privConfRow.locator('button:has-text("Edit")').click();
  await page.fill('#edit-redirect-uri', 'https://priv-conf.example.com/bad#frag');
  await page.locator('#edit-redirect-uri').blur();
  await page.waitForSelector('[role="alert"]:has-text("fragments")');
  await page.fill('#edit-redirect-uri', 'https://priv-conf.example.com/cb2');
  assert.equal(await page.locator('#edit-redirect-uri').getAttribute('aria-invalid'), 'false');
  await page.click('button:has-text("Add") >> nth=0');
  await page.click('input[name="clientType"][value="public"]');
  await page.click('input[name="accessPolicy"][value="open"]');
  await page.click('[data-confirm="revoke-secret"]');
  await page.click('[data-confirm="widening-access"]');
  await page.click('button[type="submit"]:has-text("Save changes")');
  await page.waitForSelector('button[type="submit"]:has-text("Save changes")', { state: 'detached', timeout: 10000 });
  await privConfRow.getByText("Public", { exact: true }).waitFor({ state: "visible", timeout: 10000 });
  await privConfRow.getByText("Open", { exact: true }).waitFor({ state: "visible", timeout: 10000 });
  const downgradedDoc = await db.collection("oauthClient").findOne({ name: "BAC Priv Conf App" });
  assert.equal(downgradedDoc?.clientType, "public");
  assert.equal(downgradedDoc?.accessPolicy, "open");
  assert.equal(downgradedDoc?.clientSecret, undefined);

  const openPubRow = page.locator("tr", { hasText: "BAC Open Public App" });
  await openPubRow.locator('button:has-text("Edit")').click();
  await page.click('input[name="clientType"][value="confidential"]');
  await page.click('button[type="submit"]:has-text("Save changes")');
  await page.waitForSelector('button:has-text("Copy secret")', { timeout: 10000 });
  await page.click('button:has-text("Copy secret")');
  await page.click('button:has-text("Done")');
  const upgradedDoc = await db.collection("oauthClient").findOne({ name: "BAC Open Public App" });
  assert.equal(upgradedDoc?.clientType, "confidential");
  assert.ok(upgradedDoc?.clientSecret);
  await superCtx.close();

  // BAC-P1C-06: Scoped App Admin UI block + direct PATCH 403 denial
  const scopedCtx = await harness.browser.newContext();
  const scopedPage = await scopedCtx.newPage();
  await scopedPage.goto(`${harness.frontendUrl}/admin/login`, { waitUntil: "networkidle" });
  await scopedPage.fill('input[name="email"]', appAdminEmail);
  await scopedPage.fill('input[name="password"]', password);
  await scopedPage.click('button[type="submit"]');
  await scopedPage.waitForURL("**/admin/two-factor**", { timeout: 15000 });
  const { createOTP } = await import("@better-auth/utils/otp");
  await scopedPage.fill('input[name="code"], input[inputmode="numeric"]', await createOTP(appAdminTotp, { digits: 6, period: 30 }).totp());
  await scopedPage.click('button[type="submit"]');
  await scopedPage.waitForURL("**/admin/login?error=access_denied_scoped**", { timeout: 15000 });
  const patchStatus = await scopedPage.evaluate(async (cid: string) => {
    const csrfMatch = document.cookie.split("; ").find((r) => r.startsWith("csrf_token="));
    const csrf = csrfMatch ? decodeURIComponent(csrfMatch.split("=")[1]) : "";
    const r = await fetch(`/api/admin/clients/${cid}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ clientType: "public", accessPolicy: "open", isDev: true }),
    });
    return r.status;
  }, scopedClientId);
  assert.equal(patchStatus, 403, "Direct PATCH of policy fields by scoped App Admin must return 403");
  const untouched = await db.collection("oauthClient").findOne({ clientId: scopedClientId });
  assert.equal(untouched?.clientType, "confidential");
  assert.equal(untouched?.accessPolicy, "private");
  assert.equal(untouched?.isDev, false);
  console.log("[PASS] BAC-P1C-06: Scoped App Admin blocked from console and HTTP PATCH rejected 403");
  await scopedCtx.close();

  console.log("\n================================================================");
  console.log("  ALL BAC-P1C-01..06 BROWSER ACCEPTANCE CHECKS PASSED");
  console.log("================================================================");
} finally {
  if (harness) await harness.cleanup();
  await suite.cleanup();
}
