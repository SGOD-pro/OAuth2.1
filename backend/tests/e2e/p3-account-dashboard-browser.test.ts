import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p3_account_dashboard_browser");
const password = "P3!Dash#Password99";

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
  const emailA = `dash_pw_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const emailB = `dash_pw_b_${crypto.randomBytes(4).toString("hex")}@example.com`;

  const context = await browser.newContext();
  const pageA = await context.newPage();

  for (const [email, name] of [[emailA, "dash_user_a"], [emailB, "dash_user_b"]]) {
    const r = await context.request.post(`${frontendUrl}/api/auth/sign-up/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password, name },
    });
    assert.equal(r.status(), 200);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true, username: name } });
  }
  const userADoc = await db.collection("user").findOne({ email: emailA });
  const userBDoc = await db.collection("user").findOne({ email: emailB });

  for (const email of [emailA, emailB]) {
    const r = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password },
    });
    assert.equal(r.status(), 200);
  }

  // Open /account in Tab A and select A
  await pageA.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await pageA.getByText("dash_user_a").click();
  await pageA.waitForSelector('[data-testid="dashboard-user-id"]');
  assert.ok((await pageA.locator('[data-testid="dashboard-user-id"]').textContent())?.includes(String(userADoc?._id || userADoc?.id)));

  // Open /account in Tab B and select B
  const pageB = await context.newPage();
  await pageB.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await pageB.getByText("dash_user_b").click();
  await pageB.waitForSelector('[data-testid="dashboard-user-id"]');
  assert.ok((await pageB.locator('[data-testid="dashboard-user-id"]').textContent())?.includes(String(userBDoc?._id || userBDoc?.id)));

  // Verify Tab A still shows A and no persistent storage holds the context handle
  assert.ok((await pageA.locator('[data-testid="dashboard-account-label"]').textContent())?.includes("dash_user_a"));
  const storageDump = await pageA.evaluate(() => JSON.stringify({ ls: { ...localStorage }, ss: { ...sessionStorage } }));
  assert.ok(!storageDump.includes("owner_dashboard") && !storageDump.includes("contextHandle"));

  // Reload Tab A -> documented tab-memory behavior clears in-memory handle and returns to chooser
  await pageA.reload({ waitUntil: "networkidle" });
  await pageA.getByText("dash_user_a").waitFor({ state: "visible" });

  // Sign out A from Tab A's chooser; Tab B remains usable on B
  const signOutBtn = pageA.locator("button", { hasText: /sign out/i }).first();
  await signOutBtn.click();
  await pageA.waitForTimeout(300);
  assert.ok((await pageB.locator('[data-testid="dashboard-account-label"]').textContent())?.includes("dash_user_b"));

  console.log("[PASS] P3 Account Dashboard Two-Tab Browser E2E passed");
} finally {
  await harness?.cleanup().catch(() => {});
  await suite.cleanup().catch(() => {});
}
