import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { createLocalJWKSet, jwtVerify } from "jose";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { startIdpAndFrontendHarness } from "../fixtures/browser-harness";

const backendDir = path.resolve(import.meta.dirname, "../..");
const frontendDir = path.resolve(backendDir, "../frontend");
const suite = await setupSuiteDatabase("p3_two_tab_chooser");
const strongPassword = "P3b!Browser#Password99";

let harness: Awaited<ReturnType<typeof startIdpAndFrontendHarness>> | null = null;
try {
  harness = await startIdpAndFrontendHarness({
    backendDir, frontendDir, mongoUri: suite.uri,
    gatewaySecret: "g".repeat(32), betterAuthSecret: "a".repeat(32),
  });

  const db = suite.client.db(suite.dbName);
  const seedUser = async (email: string, username: string) => {
    const r = await fetch(`${harness!.frontendUrl}/api/auth/sign-up/email`, {
      method: "POST", headers: { "Content-Type": "application/json", Origin: harness!.frontendUrl },
      body: JSON.stringify({ email, password: strongPassword, name: username }),
    });
    assert.equal(r.status, 200);
    await db.collection("user").updateOne({ email }, { $set: { role: "user", emailVerified: true, username } });
    return db.collection("user").findOne({ email });
  };
  const uA = await seedUser("two-tab-a@example.com", "twotab_a");
  const uB = await seedUser("two-tab-b@example.com", "twotab_b");

  await db.collection("oauthClient").insertOne({
    clientId: "p3-two-tab-client", name: "Two Tab Consumer",
    redirectUris: [`${harness.frontendUrl}/callback`],
    tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"], scopes: ["openid", "profile", "email"],
    skipConsent: false, requirePKCE: true, disabled: false,
    isPublic: true, accessPolicy: "open", clientType: "public", isDev: true,
  });

  const startAuthUrl = (state: string, nonce: string, challenge: string) =>
    `${harness!.frontendUrl}/api/auth/oauth2/authorize?client_id=p3-two-tab-client&redirect_uri=${encodeURIComponent(`${harness!.frontendUrl}/callback`)}&response_type=code&scope=${encodeURIComponent("openid profile")}&state=${state}&nonce=${nonce}&code_challenge_method=S256&code_challenge=${challenge}`;

  const ctx = await harness.browser.newContext();
  const tabA = await ctx.newPage();
  const tabB = await ctx.newPage();

  // 1. Tab A signs in as Account A
  const verA1 = crypto.randomBytes(32).toString("base64url");
  const chA1 = crypto.createHash("sha256").update(verA1).digest("base64url");
  await tabA.goto(startAuthUrl("sA1", "nA1", chA1), { waitUntil: "domcontentloaded" });
  await tabA.waitForSelector('input[name="email"]', { timeout: 15000 });
  await tabA.fill('input[name="email"]', "two-tab-a@example.com");
  await tabA.fill('input[name="password"]', strongPassword);
  await tabA.click('button[type="submit"]');
  await tabA.waitForURL("**/consent**", { timeout: 15000 });
  await tabA.click('button:has-text("Authorize")');
  await tabA.waitForURL("**/callback**", { timeout: 15000 });

  // 2. Tab B opens chooser -> sees Account A -> clicks "Use another account" -> signs in as Account B (preserving A)
  const verB1 = crypto.randomBytes(32).toString("base64url");
  const chB1 = crypto.createHash("sha256").update(verB1).digest("base64url");
  await tabB.goto(`${startAuthUrl("sB1", "nB1", chB1)}&prompt=select_account`, { waitUntil: "domcontentloaded" });
  await tabB.waitForSelector('button:has-text("Use another account")', { timeout: 10000 });
  await tabB.click('button:has-text("Use another account")');
  await tabB.fill('input[name="email"]', "two-tab-b@example.com");
  await tabB.fill('input[name="password"]', strongPassword);
  await tabB.click('button[type="submit"]');
  await tabB.waitForURL("**/consent**", { timeout: 15000 });
  await tabB.click('button:has-text("Authorize")');
  await tabB.waitForURL("**/callback**", { timeout: 15000 });

  // 3. Interleave Tab A and Tab B chooser -> consent -> code exchange -> exact subjects
  const verA2 = crypto.randomBytes(32).toString("base64url");
  const chA2 = crypto.createHash("sha256").update(verA2).digest("base64url");
  const verB2 = crypto.randomBytes(32).toString("base64url");
  const chB2 = crypto.createHash("sha256").update(verB2).digest("base64url");

  await tabA.goto(`${startAuthUrl("sA2", "nA2", chA2)}&prompt=consent`, { waitUntil: "domcontentloaded" });
  await tabA.waitForSelector('[data-testid="chooser-list"]', { timeout: 10000 });

  await tabB.goto(`${startAuthUrl("sB2", "nB2", chB2)}&prompt=consent`, { waitUntil: "domcontentloaded" });
  await tabB.waitForSelector('[data-testid="chooser-list"]', { timeout: 10000 });

  await tabB.click('[data-testid="choose-account-twotab_b"]');
  await tabB.waitForURL("**/consent**", { timeout: 15000 });

  await tabA.click('[data-testid="choose-account-twotab_a"]');
  await tabA.waitForURL("**/consent**", { timeout: 15000 });

  await tabB.click('button:has-text("Authorize")');
  await tabB.waitForURL("**/callback**", { timeout: 15000 });
  const codeB = new URL(tabB.url()).searchParams.get("code")!;

  await tabA.click('button:has-text("Authorize")');
  await tabA.waitForURL("**/callback**", { timeout: 15000 });
  const codeA = new URL(tabA.url()).searchParams.get("code")!;

  const jwks = await (await fetch(`${harness.frontendUrl}/api/auth/jwks.json`)).json();
  const exchange = async (code: string, verifier: string) => {
    const res = await fetch(`${harness!.frontendUrl}/api/auth/oauth2/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: "p3-two-tab-client", redirect_uri: `${harness!.frontendUrl}/callback`, code, code_verifier: verifier }),
    });
    assert.equal(res.status, 200);
    return (await res.json()) as any;
  };
  const tokA = await exchange(codeA, verA2);
  const tokB = await exchange(codeB, verB2);
  const claimsA = (await jwtVerify(tokA.id_token, createLocalJWKSet(jwks), { algorithms: ["RS256"] })).payload;
  const claimsB = (await jwtVerify(tokB.id_token, createLocalJWKSet(jwks), { algorithms: ["RS256"] })).payload;
  assert.equal(claimsA.sub, String(uA!._id));
  assert.equal(claimsA.nonce, "nA2");
  assert.equal(claimsB.sub, String(uB!._id));
  assert.equal(claimsB.nonce, "nB2");

  // 4. Signing out A from chooser leaves B active and usable
  const verB3 = crypto.randomBytes(32).toString("base64url");
  const chB3 = crypto.createHash("sha256").update(verB3).digest("base64url");
  await tabB.goto(`${startAuthUrl("sB3", "nB3", chB3)}&prompt=${encodeURIComponent("select_account consent")}`, { waitUntil: "domcontentloaded" });
  await tabB.waitForSelector('[data-testid="chooser-list"]', { timeout: 10000 });
  await tabB.click('[data-testid="signout-account-twotab_a"]');
  await tabB.waitForSelector('[data-testid="signedout-account-twotab_a"]', { timeout: 10000 });
  await tabB.click('[data-testid="choose-account-twotab_b"]');
  await tabB.waitForURL("**/consent**", { timeout: 15000 });
  await tabB.click('button:has-text("Authorize")');
  await tabB.waitForURL("**/callback**", { timeout: 15000 });
  assert.ok(new URL(tabB.url()).searchParams.get("code"));

  await ctx.close();
  console.log("[PASS] P3 Two-Tab Browser Chooser E2E passed");
} finally {
  if (harness) await harness.cleanup().catch(() => {});
  await suite.cleanup();
}
