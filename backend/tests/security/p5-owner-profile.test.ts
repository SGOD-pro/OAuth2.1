import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P5.2 Owner Profile API (GET/PATCH /api/identity/me)", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let origin: string;
  let gatewaySecret: string;

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

    await setupSuiteDatabase("p5_owner_profile");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
    const { default: appInstance } = await import("../../src/app");
    app = appInstance;
  });

  after(async () => {
    process.exit(0);
  });

  function headers(extra: Record<string, string> = {}) {
    return {
      "Content-Type": "application/json",
      Origin: origin,
      "x-gateway-secret": gatewaySecret,
      "x-csrf-token": "any",
      "x-forwarded-for": "198.51.100.92, 10.0.0.1",
      ...extra,
    };
  }

  function extractCookie(res: Response, name: string): string {
    const raw = (res.headers as any).getSetCookie ? (res.headers as any).getSetCookie() : [res.headers.get("set-cookie") || ""];
    for (const item of raw) {
      for (const part of String(item).split(/,(?=\s*[^;]+=[^;]+)/)) {
        const kv = part.trim().split(";")[0].trim();
        if (kv.includes(`${name}=`)) return kv;
      }
    }
    return "";
  }

  it("reads/updates only selected account, enforces field allowlist & username uniqueness, and leaves B unchanged", async () => {
    const emailA = `p52_a_${Date.now()}@example.com`;
    const emailB = `p52_b_${Date.now()}@example.com`;
    const pass = "P52!Profile#Pass123";
    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const cookieName = getBrowserSessionCookieName();

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass, name: "Alpha User" }) });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true, username: "alpha_user" } });
    const inA = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass }) });
    const proof = extractCookie(inA, cookieName);

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailB, password: pass, name: "Beta User" }) });
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true, username: "beta_user", usernameNormalized: "beta_user" } });
    const inB = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers({ Cookie: proof }), body: JSON.stringify({ email: emailB, password: pass }) });
    const proofAB = extractCookie(inB, cookieName) || proof;

    const userA = await db.collection("user").findOne({ email: emailA });
    const userB = await db.collection("user").findOne({ email: emailB });
    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userA._id) });
    const entryA = regSet.entries.find((e: any) => e.userId === String(userA._id));

    const ctxRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    const ctxA = (await ctxRes.json()).contextHandle;

    // GET /api/identity/me
    const getRes = await app.request("/api/identity/me", { method: "GET", headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }) });
    assert.equal(getRes.status, 200);
    const getBody = await getRes.json();
    assert.equal(getBody.userId, String(userA._id));
    assert.equal(getBody.email, emailA);

    // Disallowed field rejected (400)
    const badField = await app.request("/api/identity/me", {
      method: "PATCH",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ email: "hijack@example.com" }),
    });
    assert.equal(badField.status, 400);

    // Duplicate username returns 409 and preserves existing profile
    const dupRes = await app.request("/api/identity/me", {
      method: "PATCH",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ name: "Should Not Save", username: "beta_user" }),
    });
    assert.equal(dupRes.status, 409);
    const afterDup = await db.collection("user").findOne({ _id: userA._id });
    assert.equal(afterDup.name, "Alpha User");
    assert.equal(afterDup.username, "alpha_user");

    // Valid PATCH updates A and leaves B unchanged
    const okRes = await app.request("/api/identity/me", {
      method: "PATCH",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
      body: JSON.stringify({ name: "Alpha Updated", username: "alpha_updated" }),
    });
    assert.equal(okRes.status, 200);
    const okBody = await okRes.json();
    assert.equal(okBody.name, "Alpha Updated");
    assert.equal(okBody.username, "alpha_updated");
    assert.equal(okBody.userId, String(userA._id));

    const userBAfter = await db.collection("user").findOne({ _id: userB._id });
    assert.equal(userBAfter.name, "Beta User");
    assert.equal(userBAfter.username, "beta_user");

    // Concurrent profile saves claiming the same username: 1 wins (200), 1 loses (409)
    const contested = `contested_${Date.now()}`;
    const regSetB = await db.collection("browser_session_sets").findOne({ "entries.userId": String(userB._id) });
    const entryB = regSetB.entries.find((e: any) => e.userId === String(userB._id));
    const ctxBRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryB.entryId, purpose: "owner_dashboard" }),
    });
    const ctxB = (await ctxBRes.json()).contextHandle;

    const [rA, rB] = await Promise.all([
      app.request("/api/identity/me", {
        method: "PATCH",
        headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
        body: JSON.stringify({ username: contested }),
      }),
      app.request("/api/identity/me", {
        method: "PATCH",
        headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxB }),
        body: JSON.stringify({ username: contested }),
      }),
    ]);
    const statuses = [rA.status, rB.status].sort((a, b) => a - b);
    assert.deepEqual(statuses, [200, 409], `Concurrent username claim must yield [200, 409], got ${statuses}`);
  });
});
