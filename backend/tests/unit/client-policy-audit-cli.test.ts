import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { MongoClient, Db } from "mongodb";
import { auditClientPolicies } from "../../src/identity/client-policy";
import { runClientPolicyAudit } from "../../scripts/audit-client-policies";
import { startSharedMongo, getBaseAdminUri } from "../fixtures/test-docker-mongo";

describe("OAuth V2 P1a: Client Policy Read-Only Audit & CLI Suite", () => {
  let adminClient: MongoClient;
  let roClient: MongoClient;
  let roDb: Db;
  let roUri: string;
  const dbName = `audit_cli_${crypto.randomBytes(4).toString("hex")}`;
  const rawSecret = "super-confidential-secret-do-not-leak";
  const sensitiveCredential = "SensitivePassword987!";

  before(async () => {
    const { port } = await startSharedMongo();
    adminClient = new MongoClient(getBaseAdminUri(port));
    await adminClient.connect();
    const adminDb = adminClient.db(dbName);

    // Drop user if left from any interrupted prior run, then create a strict read-only database user
    await adminDb.command({ dropUser: "audit_ro" }).catch(() => {});
    await adminDb.command({
      createUser: "audit_ro",
      pwd: "AuditRoPassword123!",
      roles: [{ role: "read", db: dbName }],
    });

    // Seed fixture clients covering all 4 clean classes, migrated class, and ambiguous class
    await adminDb.collection("oauthClient").insertMany([
      { clientId: "c-open-pub", isPublic: true, is_public: true, redirectUris: ["https://pub.example.com/cb"] },
      { clientId: "c-priv-conf", isPublic: false, clientSecret: rawSecret, redirectUris: ["https://priv.example.com/cb"] },
      { clientId: "c-open-conf", isPublic: true, client_secret: rawSecret, redirectUris: ["https://open-conf.example.com/cb"] },
      { clientId: "c-priv-pub", isPublic: false, application_type: "native", redirectUris: ["https://native.example.com/cb"] },
      { clientId: "c-migrated", clientType: "confidential", accessPolicy: "open", clientSecret: rawSecret, redirectUris: ["https://v2.example.com/cb"] },
      { clientId: "c-ambiguous", isPublic: true, redirectUris: [`https://user:${sensitiveCredential}@bad.example.com/cb#fragment`] },
    ]);

    // Connect with the read-only user
    roUri = `mongodb://audit_ro:AuditRoPassword123!@127.0.0.1:${port}/${dbName}?authSource=${dbName}&directConnection=true`;
    roClient = new MongoClient(roUri);
    await roClient.connect();
    roDb = roClient.db(dbName);
  });

  after(async () => {
    if (roClient) await roClient.close().catch(() => {});
    if (adminClient) {
      await adminClient.db(dbName).command({ dropUser: "audit_ro" }).catch(() => {});
      await adminClient.db(dbName).dropDatabase().catch(() => {});
      await adminClient.close().catch(() => {});
    }
  });

  it("proves read-only user cannot execute writes in MongoDB", async () => {
    try {
      await roDb.collection("oauthClient").insertOne({ clientId: "illegal-doc" });
      assert.fail("Write should have been rejected by MongoDB authorization engine");
    } catch (err: any) {
      assert.match(err.message, /not authorized|Unauthorized/i);
    }
  });

  it("audits client documents and produces accurate summary counts against read-only user", async () => {
    const summary = await auditClientPolicies(roDb);

    assert.equal(summary.totalClients, 6);
    assert.equal(summary.compatibleOpenPublicCount, 1);
    assert.equal(summary.compatiblePrivateConfidentialCount, 1);
    assert.equal(summary.compatibleOpenConfidentialCount, 1);
    assert.equal(summary.compatiblePrivatePublicCount, 1);
    assert.equal(summary.migratedCount, 1);
    assert.equal(summary.ambiguousCount, 1);
  });

  it("redacts secrets, credentials, and raw redirect URIs from audit summary and records", async () => {
    const summary = await auditClientPolicies(roDb);
    const jsonOutput = JSON.stringify(summary, null, 2);

    assert.ok(!jsonOutput.includes(rawSecret), "Audit summary must never leak raw client secrets");
    assert.ok(!jsonOutput.includes(sensitiveCredential), "Audit summary must never leak userinfo credentials");
    assert.ok(!jsonOutput.includes("https://"), "Audit summary must not include raw redirect URIs");

    for (const record of summary.clients) {
      assert.equal((record as any).clientSecret, undefined);
      assert.equal((record as any).client_secret, undefined);
      assert.equal((record as any).redirectUris, undefined);
      assert.equal((record as any).redirect_uris, undefined);
    }
  });

  it("CLI runClientPolicyAudit exits with code 1 when ambiguous records exist", async () => {
    const exitCode = await runClientPolicyAudit({ dbUri: roUri, dbName });
    assert.equal(exitCode, 1, "Audit CLI must exit with status 1 when ambiguous records require review");
  });

  it("CLI runClientPolicyAudit exits with code 0 when all records are clean", async () => {
    // Clean up the ambiguous document via admin client
    await adminClient.db(dbName).collection("oauthClient").deleteOne({ clientId: "c-ambiguous" });

    const exitCode = await runClientPolicyAudit({ dbUri: roUri, dbName });
    assert.equal(exitCode, 0, "Audit CLI must exit with status 0 on clean client inventory");
  });

  it("CLI runClientPolicyAudit fails closed with code 1 on missing configuration", async () => {
    const originalEnv = process.env.MONGO_URI;
    delete process.env.MONGO_URI;
    try {
      const exitCode = await runClientPolicyAudit({ dbUri: "" });
      assert.equal(exitCode, 1);
    } finally {
      if (originalEnv) process.env.MONGO_URI = originalEnv;
    }
  });
});
