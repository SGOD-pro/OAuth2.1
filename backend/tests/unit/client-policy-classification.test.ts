import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { resolveClientPolicy, auditClientPolicies } from "../../src/identity/client-policy";

describe("OAuth V2 P1a: Client Policy Classification & Read-Only Inventory", () => {
  // AC-P1A-01 & AC-P1A-03: Four Clean Combinations & Legacy Mapping
  it("classifies clean Class A: open public client (legacy isPublic=true, no secret)", () => {
    const doc = {
      clientId: "spa-client-1",
      client_id: "spa-client-1",
      name: "Single Page App",
      isPublic: true,
      is_public: true,
      redirectUris: ["https://app.example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.classification, "COMPATIBLE_OPEN_PUBLIC");
    assert.equal(res.clientType, "public");
    assert.equal(res.accessPolicy, "open");
    assert.equal(res.isDev, false);
    assert.equal(res.isExplicit, false);
    assert.equal(res.isAmbiguous, false);
    assert.equal(res.reasonCodes.length, 0);
  });

  it("classifies clean Class B: private confidential client (legacy isPublic=false, with secret)", () => {
    const doc = {
      clientId: "tenant-backend-1",
      name: "Tenant Service",
      isPublic: false,
      is_public: false,
      clientSecret: "super-secret-key-12345",
      redirectUris: ["https://api.tenant.com/oauth/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.classification, "COMPATIBLE_PRIVATE_CONFIDENTIAL");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "private");
    assert.equal(res.isDev, false);
    assert.equal(res.isAmbiguous, false);
  });

  it("classifies clean Class C: open confidential client (legacy isPublic=true, with secret)", () => {
    const doc = {
      clientId: "saas-web-1",
      name: "Open Web App",
      isPublic: true,
      client_secret: "secret-abc-xyz",
      redirectUris: ["https://saas.example.com/auth/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.classification, "COMPATIBLE_OPEN_CONFIDENTIAL");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "open");
    assert.equal(res.isAmbiguous, false);
  });

  it("classifies clean Class E: private public client (legacy isPublic=false, no secret)", () => {
    const doc = {
      clientId: "enterprise-mobile-1",
      name: "Enterprise Mobile App",
      isPublic: false,
      is_public: false,
      application_type: "native",
      redirectUris: ["https://mobile.company.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.classification, "COMPATIBLE_PRIVATE_PUBLIC");
    assert.equal(res.clientType, "public");
    assert.equal(res.accessPolicy, "private");
    assert.equal(res.isAmbiguous, false);
  });

  it("classifies explicit V2 migrated client", () => {
    const doc = {
      clientId: "migrated-client-1",
      name: "V2 Migrated Client",
      clientType: "confidential",
      accessPolicy: "open",
      clientSecret: "active-secret",
      redirectUris: ["https://v2.example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.classification, "MIGRATED");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "open");
    assert.equal(res.isExplicit, true);
    assert.equal(res.isAmbiguous, false);
  });

  it("preserves strict isDev boolean parsing and loopback redirect URIs", () => {
    const devDoc = {
      clientId: "local-dev-1",
      isDev: true,
      is_dev: true,
      isPublic: true,
      redirectUris: ["http://localhost:3000/callback", "http://127.0.0.1:8080/callback"],
    };
    const res = resolveClientPolicy(devDoc);
    assert.equal(res.isDev, true);
    assert.equal(res.isAmbiguous, false);
  });

  // AC-P1A-04: Ambiguity Detection & Reason Codes
  it("flags MISSING_REDIRECT_URIS when redirect URIs array is empty or missing", () => {
    const doc = { clientId: "no-uris", isPublic: true, redirectUris: [] };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.equal(res.classification, "AMBIGUOUS");
    assert.equal(res.accessPolicy, "private"); // Fails closed
    assert.ok(res.reasonCodes.includes("MISSING_REDIRECT_URIS"));
  });

  it("flags INVALID_REDIRECT_URI for URI fragments, wildcards, userinfo, and prod http", () => {
    const doc = {
      clientId: "bad-uris",
      isDev: false,
      isPublic: true,
      redirectUris: [
        "https://example.com/callback#fragment",
        "https://*.wildcard.com/cb",
        "https://user:pass@example.com/cb",
        "http://insecure.example.com/cb",
      ],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("INVALID_REDIRECT_URI"));
    assert.equal(res.accessPolicy, "private");
  });

  it("flags CONFLICTING_ACCESS_FLAGS when isPublic and is_public contradict", () => {
    const doc = {
      clientId: "conflict-access",
      isPublic: true,
      is_public: false,
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("CONFLICTING_ACCESS_FLAGS"));
    assert.equal(res.accessPolicy, "private");
  });

  it("flags CONFLICTING_DEV_FLAGS when isDev and is_dev contradict", () => {
    const doc = {
      clientId: "conflict-dev",
      isDev: true,
      is_dev: false,
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("CONFLICTING_DEV_FLAGS"));
  });

  it("flags CONFLICTING_ID_FIELDS when clientId and client_id differ", () => {
    const doc = {
      clientId: "id-a",
      client_id: "id-b",
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("CONFLICTING_ID_FIELDS"));
  });

  it("flags CONFLICTING_METADATA for public client with secret or native with secret", () => {
    const publicWithSecret = {
      clientId: "public-secret",
      clientType: "public",
      accessPolicy: "open",
      clientSecret: "stray-secret",
      redirectUris: ["https://example.com/cb"],
    };
    const res1 = resolveClientPolicy(publicWithSecret);
    assert.equal(res1.isAmbiguous, true);
    assert.ok(res1.reasonCodes.includes("CONFLICTING_METADATA"));

    const nativeWithSecret = {
      clientId: "native-secret",
      application_type: "native",
      clientSecret: "stray-secret",
      redirectUris: ["https://example.com/cb"],
    };
    const res2 = resolveClientPolicy(nativeWithSecret);
    assert.equal(res2.isAmbiguous, true);
    assert.ok(res2.reasonCodes.includes("CONFLICTING_METADATA"));
  });

  // AC-P1A-02: Read-Only Inventory Scanner & Zero Writes Proof
  it("audits client documents and produces accurate summary counts", async () => {
    const mockClients = [
      { clientId: "c1", isPublic: true, redirectUris: ["https://c1.com/cb"] },
      { clientId: "c2", isPublic: false, clientSecret: "s2", redirectUris: ["https://c2.com/cb"] },
      { clientId: "c3", isPublic: true, clientSecret: "s3", redirectUris: ["https://c3.com/cb"] },
      { clientId: "c4", isPublic: false, redirectUris: ["https://c4.com/cb"] },
      { clientId: "c5", clientType: "public", accessPolicy: "open", redirectUris: ["https://c5.com/cb"] },
      { clientId: "c6", isPublic: true, redirectUris: [] }, // Ambiguous
    ];

    const mockDb = {
      collection: (name: string) => {
        assert.equal(name, "oauthClient");
        return { find: () => ({ toArray: async () => mockClients }) };
      },
    };

    const summary = await auditClientPolicies(mockDb);
    assert.equal(summary.totalClients, 6);
    assert.equal(summary.compatibleOpenPublicCount, 1);
    assert.equal(summary.compatiblePrivateConfidentialCount, 1);
    assert.equal(summary.compatibleOpenConfidentialCount, 1);
    assert.equal(summary.compatiblePrivatePublicCount, 1);
    assert.equal(summary.migratedCount, 1);
    assert.equal(summary.ambiguousCount, 1);
    assert.equal(summary.clients.length, 6);
  });

  it("verifies zero database writes during inventory audit execution", async () => {
    let writeAttempts = 0;
    const forbidden = ["insertOne", "insertMany", "updateOne", "updateMany", "deleteOne", "deleteMany", "replaceOne", "bulkWrite"];
    const proxy = new Proxy({}, {
      get: (_t, prop: string) => {
        if (prop === "find") return () => ({ toArray: async () => [{ clientId: "c", isPublic: true, redirectUris: ["https://c.com/cb"] }] });
        if (forbidden.includes(prop)) {
          writeAttempts++;
          throw new Error(`Forbidden write operation called: ${prop}`);
        }
        return undefined;
      },
    });

    const summary = await auditClientPolicies({ collection: () => proxy });
    assert.equal(writeAttempts, 0);
    assert.equal(summary.totalClients, 1);
    assert.equal(summary.compatibleOpenPublicCount, 1);
  });

  it("never exposes client secrets in audit records or summary output", async () => {
    const rawSecret = "super-confidential-secret-do-not-leak";
    const mockClients = [
      { clientId: "sc", clientSecret: rawSecret, client_secret: rawSecret, isPublic: false, redirectUris: ["https://tenant.com/cb"] },
    ];
    const summary = await auditClientPolicies({
      collection: () => ({ find: () => ({ toArray: async () => mockClients }) }),
    });
    const serialized = JSON.stringify(summary);

    assert.ok(!serialized.includes(rawSecret), "Audit output must never leak raw client secret");
    for (const client of summary.clients) {
      assert.equal((client as any).clientSecret, undefined);
      assert.equal((client as any).client_secret, undefined);
    }
  });

  // AC-P1A-05: Runtime Boundary Isolation
  it("keeps classifier out of runtime authorization routes", () => {
    const runtimeFiles = [
      "src/routes/auth-authorize.ts",
      "src/routes/auth-consent.ts",
      "src/routes/auth-token.ts",
      "src/routes/auth-token-auth.ts",
      "src/routes/auth-token-code.ts",
      "src/routes/auth-token-refresh.ts",
    ];

    for (const relPath of runtimeFiles) {
      const fullPath = path.resolve(import.meta.dirname, "../../", relPath);
      const content = fs.readFileSync(fullPath, "utf-8");
      assert.ok(!content.includes("client-policy"), `Runtime route ${relPath} must not import client-policy in P1a`);
    }
  });
});
