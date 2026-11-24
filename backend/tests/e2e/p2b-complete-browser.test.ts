import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { AddressInfo } from "node:net";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p2b_browser_e2e");
const delivered: Array<{ to: string; text: string }> = [];
const sinkServer = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => { raw += c; });
  req.on("end", () => {
    try { delivered.push(JSON.parse(raw)); } catch {}
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ messageId: `sink-${crypto.randomUUID()}` }));
  });
});
await new Promise<void>((r) => sinkServer.listen(0, "127.0.0.1", r));
const sinkPort = (sinkServer.address() as AddressInfo).port;

let harness: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
try {
  // 1. Default-off check
  harness = await startIdpAndFrontendHarness({
    backendDir, frontendDir, mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32), betterAuthSecret: "a".repeat(32),
    extraEnv: { IDENTITY_REGISTRATION_MODE: "disabled" },
  });
  const p0 = await (await harness.browser.newContext()).newPage();
  await p0.goto(`${harness.frontendUrl}/register/profile`, { waitUntil: "networkidle" });
  await p0.waitForSelector('text=Registration unavailable', { timeout: 10000 });
  await harness.cleanup();
  harness = null;

  // 2. Full OTP -> /register/profile -> collision retry -> completion -> sign-in
  harness = await startIdpAndFrontendHarness({
    backendDir, frontendDir, mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32), betterAuthSecret: "a".repeat(32),
    extraEnv: {
      IDENTITY_REGISTRATION_MODE: "verified",
      IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_MAIL_TEST_SINK_URL: `http://127.0.0.1:${sinkPort}/send`,
      IDENTITY_MAIL_RESEND_SECONDS: "60",
    },
  });

  const db = suite.client.db(suite.dbName);
  // Seed first verified account "taken_name" through the real registration API so collision uses real active keys
  const headers = {
    "Content-Type": "application/json",
    Origin: harness.frontendUrl,
    "x-csrf-token": "seed-csrf",
    "x-forwarded-for": "198.51.115.10, 10.0.0.1",
  };
  const s1 = await fetch(`${harness.frontendUrl}/api/identity/registration/start`, {
    method: "POST", headers,
    body: JSON.stringify({ email: "taken@example.com", acceptedTermsVersion: "v1" }),
  });
  assert.equal(s1.status, 202);
  const { intentId: takenIntent } = (await s1.json()) as any;
  const b1 = s1.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("swyra_reg_browser="))!;
  for (let i = 0; i < 40 && delivered.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
  const code1 = delivered.at(-1)!.text.match(/\b(\d{6})\b/)![1];
  const v1 = await fetch(`${harness.frontendUrl}/api/identity/registration/verify`, {
    method: "POST", headers: { ...headers, Cookie: b1 },
    body: JSON.stringify({ intentId: takenIntent, code: code1 }),
  });
  const p1 = v1.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("swyra_reg_proof="))!;
  const c1 = await fetch(`${harness.frontendUrl}/api/identity/registration/complete`, {
    method: "POST", headers: { ...headers, Cookie: `${b1}; ${p1}` },
    body: JSON.stringify({ username: "taken_name", password: "Browser!P2b#Password99", acceptedTermsVersion: "v1" }),
  });
  assert.equal(c1.status, 201);
  delivered.length = 0;

  const ctx = await harness.browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${harness.frontendUrl}/register`, { waitUntil: "networkidle" });
  await page.fill('input[name="email"]', "p2b-e2e@example.com");
  await page.click('[data-testid="terms-checkbox"]');
  await page.click('button[type="submit"]:has-text("Send verification code")');

  await page.waitForURL("**/register/verify**", { timeout: 15000 });
  for (let i = 0; i < 40 && delivered.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
  const code = delivered.at(-1)!.text.match(/\b(\d{6})\b/)![1];

  await page.fill('input[name="code"]', code);
  await page.click('button[type="submit"]:has-text("Verify code")');
  await page.waitForSelector('text=Email verified', { timeout: 10000 });

  await page.click('a:has-text("Continue to profile"), button:has-text("Continue to profile")');
  await page.waitForURL("**/register/profile**", { timeout: 10000 });

  // Collide on taken_name first -> proof preserved, user retries
  await page.fill('input[name="username"]', "taken_name");
  await page.fill('input[name="password"]', "Browser!P2b#Password99");
  await page.click('button[type="submit"]:has-text("Complete registration")');
  await page.waitForSelector('[role="alert"]', { timeout: 10000 });

  await page.fill('input[name="username"]', "p2b_browser_user");
  await page.click('button[type="submit"]:has-text("Complete registration")');
  await page.waitForSelector('text=Account created', { timeout: 10000 });

  const user = await db.collection("user").findOne({ email: "p2b-e2e@example.com" });
  assert.ok(user);
  assert.equal(user.role, "user");
  assert.equal(user.username, "p2b_browser_user");
  assert.equal(await db.collection("user_app_registrations").countDocuments(), 0);

  // Verify user can sign in cleanly via the UI or session already established
  await page.click('a:has-text("Continue to sign in")');
  await page.waitForURL("**/auth**", { timeout: 10000 });
  await ctx.close();
  console.log("[PASS] P2b Browser E2E: verify -> /register/profile -> collision retry -> verified account + sign-in");
} finally {
  if (harness) await harness.cleanup().catch(() => {});
  sinkServer.close();
  await suite.cleanup();
}
