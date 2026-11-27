import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, before, describe, it } from "node:test";
import { Hono } from "hono";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P7.2 Ledger-First Denial Window and Reconciler Recovery", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let origin: string;
  let gatewaySecret: string;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.ALLOW_PUBLIC_SIGNUP = "true";
    process.env.REQUIRE_EMAIL_VERIFICATION = "false";
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;
    origin = process.env.FRONTEND_URL;

    suiteCtx = await setupSuiteDatabase("p7_ledger_only_denial");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
    const { default: appInstance } = await import("../../src/app");
    app = appInstance;
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  function headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      Origin: origin,
      "x-gateway-secret": gatewaySecret,
      "x-csrf-token": "any",
      "x-forwarded-for": "198.51.100.99, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookie(res: Response, name: string): string {
    const raw = (res.headers as any).getSetCookie
      ? (res.headers as any).getSetCookie()
      : [res.headers.get("set-cookie") || ""];
    for (const item of raw) {
      for (const part of String(item).split(/,(?=\s*[^;]+=[^;]+)/)) {
        const kv = part.trim().split(";")[0].trim();
        if (kv.startsWith(`${name}=`)) return kv;
      }
    }
    return "";
  }

  async function issueCodeViaAuthorize(clientId: string, redirectUri: string, cookie: string, pkceChallenge: string) {
    const state = crypto.randomBytes(8).toString("hex");
    const authUrl = `/api/auth/oauth2/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent("openid profile email offline_access")}&state=${state}&code_challenge=${pkceChallenge}&code_challenge_method=S256`;
    const res = await app.request(authUrl, { method: "GET", headers: headers({ Cookie: cookie }) });
    assert.equal(res.status, 302);
    const loc = res.headers.get("location") || "";
    const u = new URL(loc, "http://localhost");
    const code = u.searchParams.get("code");
    assert.ok(code, `Expected code in redirect, got ${loc}`);
    return code;
  }

  it("denies all online/issuance/export boundaries during ledger-only failure window and recovers via reconciler without owner session", async () => {
    const emailA = `p72_led_a_${Date.now()}@example.com`;
    const emailB = `p72_led_b_${Date.now()}@example.com`;
    const pass = "P72!Ledger#Pass123";
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const { runExportWorkerPass } = await import("../../src/workers/export");
    const { createDeletionHandlers } = await import("../../src/routes/identity-deletion");
    const { reconcilePendingLedgerDeletions } = await import("../../src/identity/deletion");
    const { commitUserIssuanceLinearization } = await import("../../src/routes/auth-client-fence");
    const { enqueueOwnerExportJob, processNextExportJob } = await import("../../src/identity/export-jobs");
    const cookieName = getBrowserSessionCookieName();

    // Create A and B in same browser
    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass, name: "Ledger Alpha" }),
    });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true, username: "led_alpha" } });
    const inA = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    const proof = extractCookie(inA, cookieName);
    const sessionCookieA = extractCookie(inA, "better-auth.session_token");

    await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailB, password: pass, name: "Ledger Beta" }),
    });
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true, username: "led_beta" } });
    const inB = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers({ Cookie: proof }),
      body: JSON.stringify({ email: emailB, password: pass }),
    });
    const proofAB = extractCookie(inB, cookieName) || proof;

    const userA = await db.collection("user").findOne({ email: emailA });
    const userB = await db.collection("user").findOne({ email: emailB });
    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
    const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));
    const entryB = regSet.entries.find((e: any) => e.userId === String(userB._id));

    const ctxARes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    const ctxA = (await ctxARes.json()).contextHandle;

    const ctxBRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryB.entryId, purpose: "owner_dashboard" }),
    });
    const ctxB = (await ctxBRes.json()).contextHandle;

    // Register confidential open client and issue token + refresh + pending code for A
    const clientId = `p7_led_client_${Date.now()}`;
    const clientSecret = `p7_led_secret_${Date.now()}`;
    const clientSecretHash = crypto.createHash("sha256").update(clientSecret).digest("base64url");
    const redirectUri = "https://consumer.example.com/callback";
    await db.collection("oauthClient").insertOne({
      clientId,
      clientSecret: clientSecretHash,
      name: "P7 Ledger Test App",
      redirectUris: [redirectUri],
      redirectUrls: [redirectUri],
      allowedOrigins: ["https://consumer.example.com"],
      type: "confidential",
      clientType: "confidential",
      accessPolicy: "open",
      isPublic: true,
      isDev: false,
      disabled: false,
      skipConsent: true,
      tokenEndpointAuthMethod: "client_secret_basic",
      token_endpoint_auth_method: "client_secret_basic",
      createdAt: new Date(),
    });
    await db.collection("oauthConsent").insertOne({
      clientId,
      userId: String(userA._id),
      scopes: ["openid", "profile", "email", "offline_access"],
      createdAt: new Date(),
    });

    const verifier1 = crypto.randomBytes(32).toString("base64url");
    const challenge1 = crypto.createHash("sha256").update(verifier1).digest("base64url");
    const code1 = await issueCodeViaAuthorize(clientId, redirectUri, sessionCookieA, challenge1);
    const basicAuth = "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

    const tokRes = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basicAuth },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code1,
        redirect_uri: redirectUri,
        code_verifier: verifier1,
      }).toString(),
    });
    assert.equal(tokRes.status, 200, `Token exchange failed: ${await tokRes.clone().text()}`);
    const tokBody = await tokRes.json();
    assert.ok(tokBody.access_token);
    assert.ok(tokBody.refresh_token);

    // Issue a second pending code BEFORE Step A
    const verifier2 = crypto.randomBytes(32).toString("base64url");
    const challenge2 = crypto.createHash("sha256").update(verifier2).digest("base64url");
    const pendingCode = await issueCodeViaAuthorize(clientId, redirectUri, sessionCookieA, challenge2);

    // Create and complete an export for A BEFORE Step A
    const expRes = await app.request("/api/identity/me/export", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA, "Idempotency-Key": "pre-ledger-exp" }),
      body: JSON.stringify({}),
    });
    assert.equal(expRes.status, 202);
    const { jobId: oldExportId } = await expRes.json();
    assert.equal(await runExportWorkerPass(db), 1);

    // Persist Step A and force Step B to fail
    const failingApp = new Hono();
    const handlers = createDeletionHandlers({
      getDb: async () => db,
      startSession: () => ({
        async withTransaction() {
          throw new Error("Forced Step B DB failure");
        },
        async endSession() {},
      }),
    });
    failingApp.post("/api/identity/me/deletion", handlers.requestDeletion);

    const stepBFAIL = await failingApp.request("/api/identity/me/deletion", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ confirm: true }),
    });
    assert.equal(stepBFAIL.status, 503);
    assert.equal(extractCookie(stepBFAIL, "swyra_deletion_receipt"), "");

    const ledgerEntry = await db.collection("deletion_ledger").findOne({ userId: String(userA._id) });
    assert.ok(ledgerEntry, "Step A ledger entry must exist");
    assert.equal(await db.collection("deletion_jobs").countDocuments({ userId: String(userA._id) }), 0);

    const userDuringWindow = await db.collection("user").findOne({ _id: userA._id });
    assert.notEqual(userDuringWindow.status, "deleting");
    assert.notEqual(userDuringWindow.disabled, true);
    assert.equal(userDuringWindow.tokenVersion ?? 1, userA.tokenVersion ?? 1);

    // Ledger-only failure window: every online/issuance/export boundary must reject A
    const meDuring = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(meDuring.status, 401);

    const ctxDuring = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxDuring.status, 401);

    const signInDuring = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ email: emailA, password: pass }),
    });
    assert.equal(signInDuring.status, 401);

    const codeExchangeDuring = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basicAuth },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: pendingCode,
        redirect_uri: redirectUri,
        code_verifier: verifier2,
      }).toString(),
    });
    assert.notEqual(codeExchangeDuring.status, 200);

    const refreshDuring = await app.request("/api/auth/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basicAuth },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokBody.refresh_token,
      }).toString(),
    });
    assert.notEqual(refreshDuring.status, 200);

    const userinfoDuring = await app.request("/api/auth/oauth2/userinfo", {
      method: "GET",
      headers: { Authorization: `Bearer ${tokBody.access_token}` },
    });
    assert.notEqual(userinfoDuring.status, 200);

    const introspectDuring = await app.request("/api/auth/oauth2/introspect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basicAuth },
      body: new URLSearchParams({ token: tokBody.access_token }).toString(),
    });
    assert.equal(introspectDuring.status, 200);
    assert.equal((await introspectDuring.json()).active, false);

    const expDlDuring = await app.request(`/api/identity/me/export/${oldExportId}/download`, {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(expDlDuring.status, 401);

    assert.equal(await commitUserIssuanceLinearization(db, String(userA._id), 1), false);

    const racingExp = await enqueueOwnerExportJob(db, String(userA._id), { idempotencyKey: `led-race-${Date.now()}` });
    await processNextExportJob(db);
    const racingExpDoc = await db.collection("export_jobs").findOne({ jobId: racingExp.jobId });
    assert.equal(racingExpDoc.status, "suppressed");
    assert.equal(racingExpDoc.encryptedArtifact, undefined);

    // Account B in same browser remains usable
    const bMeDuring = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bMeDuring.status, 200);
    assert.equal((await bMeDuring.json()).email, emailB);

    // Remove fault and run reconciler (no owner session, no in-memory receipt)
    const rec1 = await reconcilePendingLedgerDeletions(db);
    assert.equal(rec1.reconciledCount, 1);

    const rec2 = await reconcilePendingLedgerDeletions(db);
    assert.equal(rec2.reconciledCount, 0);

    const userAfter = await db.collection("user").findOne({ _id: userA._id });
    assert.equal(userAfter.status, "deleting");
    assert.equal(userAfter.disabled, true);
    assert.equal(userAfter.tokenVersion, (userA.tokenVersion ?? 1) + 1);

    const delJobs = await db.collection("deletion_jobs").find({ userId: String(userA._id) }).toArray();
    assert.equal(delJobs.length, 1);
    assert.equal(delJobs[0].operationId, ledgerEntry.operationId);

    // B still active after reconciliation
    const bMeAfter = await app.request("/api/identity/me", {
      method: "GET",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
    });
    assert.equal(bMeAfter.status, 200);
  });
});
