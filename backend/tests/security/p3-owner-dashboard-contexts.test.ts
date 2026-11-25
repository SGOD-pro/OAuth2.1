import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P3 Owner Dashboard Contexts", () => {
  let suite: any;
  let db: any;
  let closeDb: any;
  let setTestDbOverride: any;
  let app: any;
  let authProvider: any;
  let findActiveBrowserSet: any;
  const gatewaySecret = "g".repeat(32);
  const password = "Password123!@#Secure";

  function hdrs(extra: Record<string, string> = {}) {
    return { "X-Gateway-Secret": gatewaySecret, "x-csrf-token": "test-csrf", Origin: "http://localhost:5174", ...extra };
  }

  function extractCookie(res: Response, name: string): string {
    for (const part of (res.headers.get("set-cookie") || "").split(/,(?=[^;]+=)/)) {
      const kv = part.trim().split(";")[0];
      if (kv.startsWith(`${name}=`)) return kv;
    }
    return "";
  }

  async function registerUser(email: string) {
    const res = await authProvider.api.signUpEmail({ body: { email, password, name: "User" } });
    assert.ok(res.user?.id);
    await db.collection("user").updateOne({ email }, { $set: { emailVerified: true } });
    return res.user.id as string;
  }

  async function loginAndGetEntry(email: string, rawBrowserProof?: string) {
    const cookieHeader = rawBrowserProof ? `swyra-browser=${rawBrowserProof}` : "";
    const res = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", ...(cookieHeader ? { Cookie: cookieHeader } : {}) }),
      body: JSON.stringify({ email, password }),
    });
    assert.equal(res.status, 200);
    const entryId = res.headers.get("x-browser-entry-id")!;
    const bc = extractCookie(res, "swyra-browser");
    const rawProof = bc ? bc.split("=")[1] : rawBrowserProof!;
    const setDoc = await findActiveBrowserSet(db, rawProof);
    const entry = setDoc?.entries.find((e: any) => e.entryId === entryId);
    return { entryId, rawProof, sessionId: entry?.sessionId as string, setId: setDoc?.setId as string };
  }

  before(async () => {
    isolateTestEnvironment();
    suite = await setupSuiteDatabase("p3_owner_contexts");
    Object.assign(process.env, {
      NODE_ENV: "test", MONGO_URI: suite.uri, DB_NAME: suite.dbName, BETTER_AUTH_SECRET: "a".repeat(32),
      BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174", GOOGLE_CLIENT_ID: "test-google-id",
      GOOGLE_CLIENT_SECRET: "test-google-secret", INTERNAL_GATEWAY_SECRET: gatewaySecret,
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,172.16.0.0/12,127.0.0.1/32",
    });
    const mongoMod = await import("../../src/db/mongo");
    closeDb = mongoMod.closeDb;
    setTestDbOverride = mongoMod.setTestDbOverride;
    authProvider = (await import("../../src/utils/auth")).authProvider;
    app = (await import("../../src/app")).default;
    findActiveBrowserSet = (await import("../../src/identity/browser-session-registry")).findActiveBrowserSet;
    db = suite.client.db(suite.dbName);
    setTestDbOverride(db);
  });

  after(async () => {
    if (closeDb) await closeDb().catch(() => {});
    if (suite?.cleanup) await suite.cleanup().catch(() => {});
  });

  it("pins two dashboard tabs to A and B, rejects admin routes, and isolates sign-out", async () => {
    const emailA = `dash_a_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const emailB = `dash_b_${crypto.randomBytes(4).toString("hex")}@example.com`;
    const userA = await registerUser(emailA);
    const userB = await registerUser(emailB);

    const sA = await loginAndGetEntry(emailA);
    const sB = await loginAndGetEntry(emailB, sA.rawProof);
    const proof = sB.rawProof;

    const ctxARes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId: sA.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxARes.status, 201);
    const ctxA = await ctxARes.json();

    const ctxBRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId: sB.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxBRes.status, 201);
    const ctxB = await ctxBRes.json();

    const meA = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxA.contextHandle }),
    });
    assert.equal(meA.status, 200);
    assert.equal((await meA.json()).userId, userA);

    const meB = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxB.contextHandle }),
    });
    assert.equal(meB.status, 200);
    assert.equal((await meB.json()).userId, userB);

    // Admin routes must reject ordinary owner dashboard contexts
    const adminRes = await app.request("/api/admin/stats", {
      headers: hdrs({ Cookie: `swyra-browser=${proof}`, "X-Identity-Context": ctxA.contextHandle }),
    });
    assert.ok(adminRes.status === 401 || adminRes.status === 403);

    // Sign out A; A's context becomes invalid while B's context remains usable
    const soRes = await app.request("/api/identity/accounts/sign-out", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${proof}` }),
      body: JSON.stringify({ entryId: sA.entryId }),
    });
    assert.equal(soRes.status, 200);
    const nextProofCookie = extractCookie(soRes, "swyra-browser");

    const meAAfter = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: nextProofCookie, "X-Identity-Context": ctxA.contextHandle }),
    });
    assert.equal(meAAfter.status, 401);

    const meBAfter = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: nextProofCookie, "X-Identity-Context": ctxB.contextHandle }),
    });
    assert.equal(meBAfter.status, 200);
    assert.equal((await meBAfter.json()).userId, userB);
  });

  it("enforces expiry, parent-session-bounded renewal, wrong-purpose rejection, and browser mismatch", async () => {
    const email = `dash_exp_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await registerUser(email);
    const s = await loginAndGetEntry(email);

    // Wrong purpose rejected on issuance
    const badPurpose = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${s.rawProof}` }),
      body: JSON.stringify({ entryId: s.entryId, purpose: "admin_panel" }),
    });
    assert.equal(badPurpose.status, 400);

    // Set parent session expiry to 5 minutes from now; renewal must not exceed parent session expiry
    const parentExp = new Date(Date.now() + 5 * 60 * 1000);
    const sessFilter = [{ id: s.sessionId }, ...(ObjectId.isValid(s.sessionId) ? [{ _id: new ObjectId(s.sessionId) }] : [])];
    await db.collection("session").updateOne({ $or: sessFilter }, { $set: { expiresAt: parentExp } });

    const ctxRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: hdrs({ "Content-Type": "application/json", Cookie: `swyra-browser=${s.rawProof}` }),
      body: JSON.stringify({ entryId: s.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxRes.status, 201);
    const ctx = await ctxRes.json();
    assert.ok(new Date(ctx.expiresAt).getTime() <= parentExp.getTime() + 1000);

    const renewRes = await app.request("/api/identity/contexts/renew", {
      method: "POST",
      headers: hdrs({ Cookie: `swyra-browser=${s.rawProof}`, "X-Identity-Context": ctx.contextHandle }),
    });
    assert.equal(renewRes.status, 200);
    const renewed = await renewRes.json();
    assert.ok(new Date(renewed.expiresAt).getTime() <= parentExp.getTime() + 1000);

    // Conflicting browser proof rejected
    const otherEmail = `other_${crypto.randomBytes(4).toString("hex")}@example.com`;
    await registerUser(otherEmail);
    const other = await loginAndGetEntry(otherEmail);
    const mismatch = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${other.rawProof}`, "X-Identity-Context": ctx.contextHandle }),
    });
    assert.equal(mismatch.status, 401);

    // Expired context rejected
    await db.collection("identity_contexts").updateOne({ entryId: s.entryId }, { $set: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await app.request("/api/identity/contexts/me", {
      headers: hdrs({ Cookie: `swyra-browser=${s.rawProof}`, "X-Identity-Context": ctx.contextHandle }),
    });
    assert.equal(expired.status, 401);
  });
});
