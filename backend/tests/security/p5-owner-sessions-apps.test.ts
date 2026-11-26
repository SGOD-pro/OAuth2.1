import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";

describe("P5 Owner Sessions & Connected Apps API", { timeout: 60_000 }, () => {
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

    await setupSuiteDatabase("p5_owner_sessions_apps");
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
      "x-forwarded-for": "198.51.100.91, 10.0.0.1",
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

  it("lists only selected account sessions/apps, enforces ownership & recent auth, and revokes/disconnects safely", async () => {
    const emailA = `p5_a_${Date.now()}@example.com`;
    const emailB = `p5_b_${Date.now()}@example.com`;
    const pass = "P5!Portal#Pass123";

    const { getBrowserSessionCookieName } = await import("../../src/identity/browser-session-registry");
    const cookieName = getBrowserSessionCookieName();

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass, name: "User A" }) });
    await db.collection("user").updateOne({ email: emailA }, { $set: { emailVerified: true } });
    const inA1 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass }) });
    const proof = extractCookie(inA1, cookieName);
    // Second session for A
    const inA2 = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailA, password: pass }) });
    assert.equal(inA2.status, 200);

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: emailB, password: pass, name: "User B" }) });
    await db.collection("user").updateOne({ email: emailB }, { $set: { emailVerified: true } });
    const inB = await app.request("/api/auth/sign-in/email", { method: "POST", headers: headers({ Cookie: proof }), body: JSON.stringify({ email: emailB, password: pass }) });
    const proofAB = extractCookie(inB, cookieName) || proof;

    const userA = await db.collection("user").findOne({ email: emailA });
    const userB = await db.collection("user").findOne({ email: emailB });
    const userAId = String(userA._id);
    const userBId = String(userB._id);

    const regSet = await db.collection("browser_session_sets").findOne({ "entries.userId": userAId });
    const entryA = regSet.entries.find((e: any) => e.userId === userAId);
    const ctxRes = await app.request("/api/identity/contexts", {
      method: "POST",
      headers: headers({ Cookie: proofAB }),
      body: JSON.stringify({ entryId: entryA.entryId, purpose: "owner_dashboard" }),
    });
    assert.equal(ctxRes.status, 201);
    const ctxA = (await ctxRes.json()).contextHandle;

    // Seed apps for A (app1, app2) and B (appB)
    await db.collection("oauthClient").insertMany([
      { clientId: "p5_app1", name: "App One", redirectUris: [`${origin}/cb1`], createdAt: new Date(), updatedAt: new Date() },
      { clientId: "p5_app2", name: "App Two", redirectUris: [`${origin}/cb2`], createdAt: new Date(), updatedAt: new Date() },
      { clientId: "p5_appB", name: "App B", redirectUris: [`${origin}/cbB`], createdAt: new Date(), updatedAt: new Date() },
    ]);
    await db.collection("oauthConsent").insertMany([
      { userId: userAId, clientId: "p5_app1", scopes: ["openid", "profile"], createdAt: new Date() },
      { userId: userAId, clientId: "p5_app2", scopes: ["openid"], createdAt: new Date() },
      { userId: userBId, clientId: "p5_appB", scopes: ["openid"], createdAt: new Date() },
    ]);
    await db.collection("user_app_registrations").insertOne({
      userId: userAId,
      clientId: "p5_app1",
      status: "active",
      createdAt: new Date(),
    });

    // List sessions & apps for A
    const listS = await app.request("/api/identity/sessions", { method: "GET", headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }) });
    assert.equal(listS.status, 200);
    const sBody = await listS.json();
    assert.ok(sBody.sessions.length >= 2, "A must see A's sessions");
    assert.equal(JSON.stringify(sBody).includes("token"), false, "Must not expose raw session token");

    const listA = await app.request("/api/identity/apps", { method: "GET", headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }) });
    assert.equal(listA.status, 200);
    const aBody = await listA.json();
    assert.deepEqual(aBody.apps.map((a: any) => a.clientId).sort(), ["p5_app1", "p5_app2"]);

    // Cross-account session revocation denied (404)
    const sessB = await db.collection("session").findOne({ userId: userB._id });
    const crossRev = await app.request(`/api/identity/sessions/${String(sessB._id)}/revoke`, {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(crossRev.status, 404);

    // Revoke A's non-current session -> preserves A's current session and B
    const nonCurrentA = sBody.sessions.find((s: any) => !s.current);
    const revOk = await app.request(`/api/identity/sessions/${nonCurrentA.sessionId}/revoke`, {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(revOk.status, 200);
    // Repeated revoke is idempotent
    const revRepeat = await app.request(`/api/identity/sessions/${nonCurrentA.sessionId}/revoke`, {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(revRepeat.status, 200);

    const listSAfter = await (await app.request("/api/identity/sessions", { method: "GET", headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }) })).json();
    assert.equal(listSAfter.sessions.length, sBody.sessions.length - 1);
    assert.ok(await db.collection("session").findOne({ _id: sessB._id }), "B's session must remain");

    // Stale createdAt (>5 min) with recent updatedAt must still be denied (403)
    const currentA = sBody.sessions.find((s: any) => s.current);
    const { ObjectId } = await import("mongodb");
    await db.collection("session").updateOne(
      { _id: new ObjectId(currentA.sessionId) },
      { $set: { createdAt: new Date(Date.now() - 10 * 60 * 1000), updatedAt: new Date() }, $unset: { mfaVerifiedAt: "" } }
    );
    const staleRev = await app.request(`/api/identity/sessions/${nonCurrentA.sessionId}/revoke`, {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(staleRev.status, 403, "Stale auth with recent updatedAt must be denied on revoke");
    const staleDisc = await app.request("/api/identity/apps/p5_app1/disconnect", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(staleDisc.status, 403, "Stale auth with recent updatedAt must be denied on disconnect");

    // Restore fresh reauthentication -> actions succeed
    await db.collection("session").updateOne(
      { _id: new ObjectId(currentA.sessionId) },
      { $set: { mfaVerifiedAt: new Date() } }
    );

    // Disconnect p5_app1 -> preserves p5_app2, B's app, and administrator-managed user_app_registrations
    const discOk = await app.request("/api/identity/apps/p5_app1/disconnect", {
      method: "POST",
      headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }),
    });
    assert.equal(discOk.status, 200);
    const listAAfter = await (await app.request("/api/identity/apps", { method: "GET", headers: headers({ Cookie: proofAB, "X-Identity-Context": ctxA }) })).json();
    assert.deepEqual(listAAfter.apps.map((a: any) => a.clientId), ["p5_app2"]);
    assert.ok(await db.collection("oauthConsent").findOne({ userId: userBId, clientId: "p5_appB" }));
    assert.ok(
      await db.collection("user_app_registrations").findOne({ userId: userAId, clientId: "p5_app1" }),
      "Administrator-managed user_app_registrations must be preserved on owner disconnect"
    );
  });
});
