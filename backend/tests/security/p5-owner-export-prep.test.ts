import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import { setupSuiteDatabase } from "../fixtures/test-docker-mongo";
import { isolateTestEnvironment } from "../fixtures/test-env-isolation";
import { prepareOwnerExport } from "../../src/identity/owner-export";

describe("P5 Bounded Owner Export Preparation", { timeout: 60_000 }, () => {
  let db: any;
  let suiteCtx: Awaited<ReturnType<typeof setupSuiteDatabase>> | undefined;

  before(async () => {
    process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
    process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
    process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
    process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
    process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
    isolateTestEnvironment();
    process.env.NODE_ENV = "test";
    process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || "c".repeat(32);
    process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

    suiteCtx = await setupSuiteDatabase("p5_owner_export_prep");
    const { getDb } = await import("../../src/db/mongo");
    db = await getDb();
  });

  after(async () => {
    const { closeDb } = await import("../../src/db/mongo");
    await closeDb();
    await suiteCtx?.cleanup();
  });

  it("collects allowlisted owner data with bounds, excludes secrets/other accounts, and marks truncation", async () => {
    const { ObjectId } = await import("mongodb");
    const idA = new ObjectId();
    const idB = new ObjectId();

    await db.collection("user").insertMany([
      {
        _id: idA,
        email: "export_a@example.com",
        emailVerified: true,
        name: "Export User A",
        username: "export_a",
        password: "hashed_password_secret",
        twoFactorSecret: "totp_secret_value",
        backupCodes: ["code1", "code2"],
        keyRef: "kms_key_ref_secret",
        operatorNotes: "private_operator_note",
        shareEmail: false,
        shareProfile: true,
        privacyVersion: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        _id: idB,
        email: "export_b@example.com",
        emailVerified: true,
        name: "Export User B",
        username: "export_b",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    await db.collection("oauthConsent").insertMany([
      { userId: String(idA), clientId: "client_a_1", scopes: ["openid", "email"], createdAt: new Date(Date.now() - 1000) },
      { userId: String(idA), clientId: "client_a_2", scopes: ["openid"], createdAt: new Date() },
      { userId: String(idB), clientId: "client_b_1", scopes: ["openid"], createdAt: new Date() },
    ]);

    await db.collection("auth_events").insertMany([
      { userId: String(idA), eventType: "sign_in", outcome: "success", clientId: "client_a_1", rawToken: "secret_tok", createdAt: new Date(Date.now() - 1000) },
      { userId: String(idA), eventType: "token_refresh", outcome: "success", clientId: "client_a_2", createdAt: new Date() },
      { userId: String(idB), eventType: "sign_in", outcome: "success", clientId: "client_b_1", createdAt: new Date() },
    ]);

    const exported = await prepareOwnerExport(db, String(idA), { maxGrants: 1, maxSecurityEvents: 1 });
    assert.ok(exported, "Export payload must be produced for A");
    assert.equal(exported.exportVersion, 1);
    assert.equal(exported.ownerUserId, String(idA));
    assert.equal(exported.profile.email, "export_a@example.com");
    assert.equal(exported.preferences.shareEmail, false);
    assert.equal(exported.preferences.shareProfile, true);

    assert.equal(exported.grants.length, 1);
    assert.equal(exported.bounds.grantsTruncated, true);
    assert.equal(exported.securityHistory.length, 1);
    assert.equal(exported.bounds.securityEventsTruncated, true);

    const serialized = JSON.stringify(exported);
    assert.equal(serialized.includes("hashed_password_secret"), false);
    assert.equal(serialized.includes("totp_secret_value"), false);
    assert.equal(serialized.includes("kms_key_ref_secret"), false);
    assert.equal(serialized.includes("private_operator_note"), false);
    assert.equal(serialized.includes("secret_tok"), false);
    assert.equal(serialized.includes("export_b@example.com"), false);
    assert.equal(serialized.includes("client_b_1"), false);
  });
});
