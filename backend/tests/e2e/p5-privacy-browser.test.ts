import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p5_privacy_browser");
const password = "P54!Browser#Password99";

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
  const emailA = `p54_br_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
  const emailB = `p54_br_b_${crypto.randomBytes(4).toString("hex")}@example.com`;

  const context = await browser.newContext();
  for (const [email, name] of [
    [emailA, "Privacy User A"],
    [emailB, "Privacy User B"],
  ]) {
    const r = await context.request.post(`${frontendUrl}/api/auth/sign-up/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password, name },
    });
    assert.equal(r.status(), 200);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true } });
    const s = await context.request.post(`${frontendUrl}/api/auth/sign-in/email`, {
      headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
      data: { email, password },
    });
    assert.equal(s.status(), 200);
  }

  const userA = await db.collection("user").findOne({ email: emailA });
  const userB = await db.collection("user").findOne({ email: emailB });
  const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
  const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));
  const entryB = regSet.entries.find((e: any) => e.userId === String(userB._id));

  const ctxARes = await context.request.post(`${frontendUrl}/api/identity/contexts`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { entryId: entryA.entryId, purpose: "owner_dashboard" },
  });
  assert.equal(ctxARes.status(), 201);
  const ctxA = (await ctxARes.json()).contextHandle;

  const ctxBRes = await context.request.post(`${frontendUrl}/api/identity/contexts`, {
    headers: { "Content-Type": "application/json", Origin: frontendUrl, "x-csrf-token": "t" },
    data: { entryId: entryB.entryId, purpose: "owner_dashboard" },
  });
  assert.equal(ctxBRes.status(), 201);
  const ctxB = (await ctxBRes.json()).contextHandle;

  // Tab A: A unchecks both privacy toggles, saves, and reloads
  const pageA = await context.newPage();
  await pageA.addInitScript((handle: string) => {
    sessionStorage.setItem("owner_context_id", handle);
  }, ctxA);
  await pageA.goto(`${frontendUrl}/account/privacy`, { waitUntil: "networkidle" });

  const emailToggleA = pageA.getByLabel("Share email address with connected apps");
  const profileToggleA = pageA.getByLabel("Share profile details with connected apps");
  assert.equal(await emailToggleA.isChecked(), true);
  assert.equal(await profileToggleA.isChecked(), true);

  await emailToggleA.uncheck();
  await profileToggleA.uncheck();
  await pageA.getByRole("button", { name: "Save privacy settings" }).click();
  await pageA.getByText("Privacy preferences saved.").waitFor({ state: "visible" });

  await pageA.reload({ waitUntil: "networkidle" });
  assert.equal(await emailToggleA.isChecked(), false);
  assert.equal(await profileToggleA.isChecked(), false);

  // Tab B: B remains unchanged (both checked)
  const pageB = await context.newPage();
  await pageB.addInitScript((handle: string) => {
    sessionStorage.setItem("owner_context_id", handle);
  }, ctxB);
  await pageB.goto(`${frontendUrl}/account/privacy`, { waitUntil: "networkidle" });
  assert.equal(await pageB.getByLabel("Share email address with connected apps").isChecked(), true);
  assert.equal(await pageB.getByLabel("Share profile details with connected apps").isChecked(), true);

  console.log("P5.4 Privacy Browser E2E Passed");
} finally {
  await harness?.browser?.close().catch(() => {});
  await suite.cleanup().catch(() => {});
  process.exit(process.exitCode ?? 0);
}
