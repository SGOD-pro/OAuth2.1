import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p5_owner_portal_browser");
const password = "P5!Browser#Password99";

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
  const emailA = `p5_br_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const emailB = `p5_br_b_${crypto.randomBytes(4).toString("hex")}@example.com`;

  const context = await browser.newContext();
  for (const [email, name] of [[emailA, "p5_user_a"], [emailB, "p5_user_b"]]) {
    const r = await context.request.post(`${frontendUrl}/api/auth/sign-up/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password, name },
    });
    assert.equal(r.status(), 200);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true, username: name } });
    const s = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password },
    });
    assert.equal(s.status(), 200);
  }

  // Create a second session for A
  const sA2 = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { email: emailA, password },
  });
  assert.equal(sA2.status(), 200);

  const userA = await db.collection("user").findOne({ email: emailA });
  const userAId = String(userA._id);
  await db.collection("oauthClient").insertMany([
    { clientId: "p5_br_app1", name: "Browser App 1", redirectUris: [`${frontendUrl}/cb1`], createdAt: new Date(), updatedAt: new Date() },
    { clientId: "p5_br_app2", name: "Browser App 2", redirectUris: [`${frontendUrl}/cb2`], createdAt: new Date(), updatedAt: new Date() },
  ]);
  await db.collection("oauthConsent").insertMany([
    { userId: userAId, clientId: "p5_br_app1", scopes: ["openid"], createdAt: new Date() },
    { userId: userAId, clientId: "p5_br_app2", scopes: ["openid"], createdAt: new Date() },
  ]);

  const pageA = await context.newPage();
  await pageA.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await pageA.getByText("p5_user_a").click();
  await pageA.waitForSelector('[data-testid="owner-sessions-section"]', { timeout: 10_000 });
  await pageA.waitForSelector('[data-testid="app-row-p5_br_app1"]', { timeout: 10_000 });

  // B in Tab B
  const pageB = await context.newPage();
  await pageB.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await pageB.getByText("p5_user_b").click();
  await pageB.waitForSelector('[data-testid="dashboard-user-id"]', { timeout: 10_000 });

  // Disconnect p5_br_app1 from Tab A
  await pageA.click('[data-testid="disconnect-app-p5_br_app1"]');
  await pageA.locator('[data-testid="app-row-p5_br_app1"]').waitFor({ state: "detached", timeout: 10_000 });
  await pageA.locator('[data-testid="app-row-p5_br_app2"]').waitFor({ state: "visible", timeout: 10_000 });

  // Verify B is still active in Tab B
  assert.ok((await pageB.locator('[data-testid="dashboard-account-label"]').textContent())?.includes("p5_user_b"));
  console.log("[PASS] P5 Owner Sessions & Connected Apps Two-Tab Browser E2E passed");
} finally {
  if (harness) await harness.cleanup();
  await suite.cleanup();
}
