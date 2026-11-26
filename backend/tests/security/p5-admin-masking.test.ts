import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { enrollAndLoginAdminMfa } from "../fixtures/admin-mfa-fixture";

describe("P5.3 Admin Data Masking & Search", { timeout: 60_000 }, () => {
  let app: any;
  let db: any;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;
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
    process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);
    gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;
    origin = process.env.FRONTEND_URL;

    suiteCtx = await setupSuiteDatabase("p5_admin_masking");
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
      "x-forwarded-for": "198.51.100.93, 10.0.0.1",
      ...extra,
    };
  }

  it("masks full email in admin users, search, and logs while allowing search by username or ID", async () => {
    const adminEmail = `p53_admin_${Date.now()}@example.com`;
    const userEmail = `p53_secret_user_${Date.now()}@example.com`;
    const pass = "P53!Admin#Pass123";

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: adminEmail, password: pass, name: "Super Admin" }) });
    await db.collection("user").updateOne({ email: adminEmail }, { $set: { emailVerified: true, role: "super-admin" } });
    const adminCookie = await enrollAndLoginAdminMfa(app, adminEmail, pass, headers);

    await app.request("/api/auth/sign-up/email", { method: "POST", headers: headers(), body: JSON.stringify({ email: userEmail, password: pass, name: "Ordinary User" }) });
    await db.collection("user").updateOne({ email: userEmail }, { $set: { emailVerified: true, username: "masked_target", usernameNormalized: "masked_target" } });
    const targetUser = await db.collection("user").findOne({ email: userEmail });
    const targetId = String(targetUser._id);

    // 1. GET /api/admin/users omits full email
    const listRes = await app.request("/api/admin/users", { method: "GET", headers: headers({ Cookie: adminCookie }) });
    assert.equal(listRes.status, 200);
    const listText = await listRes.text();
    assert.equal(listText.includes(userEmail), false, "Full user email must be absent from /api/admin/users");
    assert.equal(listText.includes(adminEmail), false, "Full admin email must be absent from /api/admin/users");

    // 2. Search by username or ID works, search by full email returns empty
    const byUname = await app.request("/api/admin/users?q=masked_target", { method: "GET", headers: headers({ Cookie: adminCookie }) });
    assert.equal((await byUname.json()).length, 1);
    const byId = await app.request(`/api/admin/users?q=${targetId}`, { method: "GET", headers: headers({ Cookie: adminCookie }) });
    assert.equal((await byId.json()).length, 1);
    const byEmail = await app.request(`/api/admin/users?q=${encodeURIComponent(userEmail)}`, { method: "GET", headers: headers({ Cookie: adminCookie }) });
    assert.equal((await byEmail.json()).length, 0, "Admin search must not match by full email");

    // 3. App-user assignment and app-admin creation omit full email
    const clientRes = await app.request("/api/admin/clients", {
      method: "POST",
      headers: headers({ Cookie: adminCookie }),
      body: JSON.stringify({
        name: "P53 Test App",
        redirectUris: ["https://app.example.com/callback"],
        clientType: "confidential",
        accessPolicy: "private",
      }),
    });
    assert.equal(clientRes.status, 201);
    const clientJson = await clientRes.json();
    const clientId = clientJson.client?.clientId || clientJson.clientId;
    assert.ok(clientId, "Created client must return clientId");

    const assignRes = await app.request(`/api/admin/clients/${clientId}/users`, {
      method: "POST",
      headers: headers({ Cookie: adminCookie }),
      body: JSON.stringify({ email: userEmail }),
    });
    assert.equal(assignRes.status, 201);
    const assignText = await assignRes.text();
    assert.equal(assignText.includes(userEmail), false, "Full user email must be absent from app-user assignment response");
    const assignJson = JSON.parse(assignText);
    assert.ok(assignJson.user?.userId, "Opaque userId must be returned");
    assert.ok(assignJson.user?.displayLabel, "Approved displayLabel must be returned");

    const appAdminEmail = `p53_app_admin_${Date.now()}@example.com`;
    const createAdminRes = await app.request(`/api/admin/clients/${clientId}/app-admins`, {
      method: "POST",
      headers: headers({ Cookie: adminCookie }),
      body: JSON.stringify({
        email: appAdminEmail,
        password: pass,
        name: "App Admin",
        redirectUrl: "https://app.example.com/callback",
      }),
    });
    assert.equal(createAdminRes.status, 201);
    const createAdminText = await createAdminRes.text();
    assert.equal(createAdminText.includes(appAdminEmail), false, "Full email must be absent from app-admin creation response");
    const createAdminJson = JSON.parse(createAdminText);
    assert.ok(createAdminJson.admin?.id, "Opaque admin id must be returned");
    assert.ok(createAdminJson.admin?.displayLabel, "Approved displayLabel must be returned");

    // 4. GET /api/admin/logs omits full email including nested audit details, arrays, and objects
    const arrayEmail = `p53_array_${Date.now()}@example.com`;
    const nestedEmail = `p53_nested_${Date.now()}@example.com`;
    await db.collection("admin_audit").insertOne({
      actorUserId: String(targetUser._id),
      actorScope: "super_admin",
      action: "bulk_test_event",
      targetClientId: clientId,
      details: {
        updatedFields: ["name", "redirectUrl"],
        count: 2,
        recipients: [arrayEmail],
        targets: [{ email: nestedEmail, role: "member" }],
        nestedMatrix: [[nestedEmail, "safe_label"]],
      },
      timestamp: new Date(),
    });

    const logsRes = await app.request("/api/admin/logs", { method: "GET", headers: headers({ Cookie: adminCookie }) });
    assert.equal(logsRes.status, 200);
    const logsText = await logsRes.text();
    assert.equal(logsText.includes(userEmail), false, "Full user email must be absent from /api/admin/logs");
    assert.equal(logsText.includes(appAdminEmail), false, "Full app-admin email must be absent from /api/admin/logs");
    assert.equal(logsText.includes(arrayEmail), false, "Full email in array must be absent from /api/admin/logs");
    assert.equal(logsText.includes(nestedEmail), false, "Full email in nested object/array must be absent from /api/admin/logs");

    const logsJson = JSON.parse(logsText);
    const logList = Array.isArray(logsJson) ? logsJson : (logsJson.logs || logsJson.entries || []);
    const bulkEntry = logList.find((e: any) => e.action === "bulk_test_event");
    assert.ok(bulkEntry, "Bulk audit entry must be present");
    assert.deepEqual(bulkEntry.details?.updatedFields, ["name", "redirectUrl"]);
    assert.equal(bulkEntry.details?.count, 2);
  });
});
