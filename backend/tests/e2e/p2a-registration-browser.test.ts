import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { AddressInfo } from "node:net";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p2a_browser_e2e");
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
    backendDir,
    frontendDir,
    mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32),
    betterAuthSecret: "a".repeat(32),
    extraEnv: { IDENTITY_REGISTRATION_MODE: "disabled" },
  });
  const p1 = await (await harness.browser.newContext()).newPage();
  await p1.goto(`${harness.frontendUrl}/register`, { waitUntil: "networkidle" });
  await p1.waitForSelector('text=Registration unavailable', { timeout: 10000 });
  console.log("[PASS] P2a Browser: default-off mode blocks /register UI cleanly");
  await harness.cleanup();
  harness = null;

  // 2. Verified registration flow using real loopback mail sink
  harness = await startIdpAndFrontendHarness({
    backendDir,
    frontendDir,
    mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32),
    betterAuthSecret: "a".repeat(32),
    extraEnv: {
      IDENTITY_REGISTRATION_MODE: "verified",
      IDENTITY_MAIL_TRANSPORT: "test_sink",
      IDENTITY_MAIL_TEST_SINK_URL: `http://127.0.0.1:${sinkPort}/send`,
      IDENTITY_MAIL_RESEND_SECONDS: "60",
    },
  });

  const db = suite.client.db(suite.dbName);
  const ctx = await harness.browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${harness.frontendUrl}/register`, { waitUntil: "networkidle" });

  await page.fill('input[name="email"]', "p2a-e2e@example.com");
  await page.click('[data-testid="terms-checkbox"]');
  await page.click('button[type="submit"]:has-text("Send verification code")');

  await page.waitForURL("**/register/verify**", { timeout: 15000 });
  await page.waitForSelector('text=Verification code sent', { timeout: 10000 });
  await page.waitForSelector('text=Resend available in', { timeout: 10000 });

  // Wait for sink message
  for (let i = 0; i < 40 && delivered.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(delivered.length >= 1, "Loopback test sink must receive verification email");
  const code = delivered[0].text.match(/\b(\d{6})\b/)![1];

  // Wrong code first
  await page.fill('input[name="code"]', code === "000000" ? "000001" : "000000");
  await page.click('button[type="submit"]:has-text("Verify code")');
  await page.waitForSelector('[role="alert"]', { timeout: 10000 });
  for (const col of ["user", "account", "session", "oauthAccessToken", "user_app_registrations"]) {
    assert.equal(await db.collection(col).countDocuments(), 0, `Wrong OTP must create 0 ${col}`);
  }

  // Correct code succeeds & stops at email verification
  await page.fill('input[name="code"]', code);
  await page.click('button[type="submit"]:has-text("Verify code")');
  await page.waitForSelector('text=Email verified', { timeout: 10000 });
  for (const col of ["user", "account", "session", "oauthAccessToken", "user_app_registrations"]) {
    assert.equal(await db.collection(col).countDocuments(), 0, `Successful P2a OTP must still create 0 ${col}`);
  }
  await ctx.close();
  console.log("[PASS] P2a Browser: /register and /register/verify complete with zero accounts/sessions created");
} finally {
  if (harness) await harness.cleanup();
  await new Promise<void>((r) => sinkServer.close(() => r()));
  await suite.cleanup();
}
