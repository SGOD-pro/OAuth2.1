import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p5_owner_profile_browser");
const password = "P52!Browser#Password99";

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
  const emailA = `p52_br_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const emailB = `p52_br_b_${crypto.randomBytes(4).toString("hex")}@example.com`;

  const context = await browser.newContext();
  for (const [email, name, uname] of [[emailA, "Profile User A", "prof_user_a"], [emailB, "Profile User B", "prof_user_b"]]) {
    const r = await context.request.post(`${frontendUrl}/api/auth/sign-up/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password, name },
    });
    assert.equal(r.status(), 200);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true, username: uname, usernameNormalized: uname } });
    const s = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password },
    });
    assert.equal(s.status(), 200);
  }

  const pageA = await context.newPage();
  await pageA.goto(`${frontendUrl}/account/profile`, { waitUntil: "networkidle" });
  await pageA.getByText("prof_user_a").click();
  await pageA.waitForSelector('[data-testid="profile-name-input"]', { timeout: 10_000 });

  const pageB = await context.newPage();
  await pageB.goto(`${frontendUrl}/account`, { waitUntil: "networkidle" });
  await pageB.getByText("prof_user_b").click();
  await pageB.waitForSelector('[data-testid="dashboard-user-id"]', { timeout: 10_000 });

  // Duplicate username fails with error
  await pageA.fill('[data-testid="profile-username-input"]', "prof_user_b");
  await pageA.click('[data-testid="profile-save-btn"]');
  await pageA.locator('[data-testid="profile-error"]').waitFor({ state: "visible", timeout: 10_000 });

  // Valid update persists across reload and leaves B unchanged
  await pageA.fill('[data-testid="profile-name-input"]', "Profile User A Edited");
  await pageA.fill('[data-testid="profile-username-input"]', "prof_user_a_edited");
  await pageA.click('[data-testid="profile-save-btn"]');
  await pageA.locator('[data-testid="profile-saved"]').waitFor({ state: "visible", timeout: 10_000 });

  await pageA.reload({ waitUntil: "networkidle" });
  await pageA.getByText("prof_user_a").click();
  await pageA.waitForSelector('[data-testid="profile-name-input"]', { timeout: 10_000 });
  assert.equal(await pageA.inputValue('[data-testid="profile-name-input"]'), "Profile User A Edited");
  assert.equal(await pageA.inputValue('[data-testid="profile-username-input"]'), "prof_user_a_edited");

  assert.ok((await pageB.locator('[data-testid="dashboard-account-label"]').textContent())?.includes("prof_user_b"));
  console.log("[PASS] P5.2 Owner Profile Two-Tab Browser E2E passed");
} finally {
  if (harness) await harness.cleanup();
  await suite.cleanup();
}
