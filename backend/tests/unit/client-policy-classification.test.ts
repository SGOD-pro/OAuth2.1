import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { resolveClientPolicy } from "../../src/identity/client-policy";

describe("OAuth V2 P1a: Client Policy Classification Unit Suite", () => {
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

  it("allows loopback redirect URIs for production native clients without isDev", () => {
    const doc = {
      clientId: "native-client",
      application_type: "native",
      isDev: false,
      isPublic: true,
      redirectUris: ["http://127.0.0.1:8080/callback", "http://localhost/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, false);
    assert.equal(res.clientType, "public");
    assert.equal(res.reasonCodes.length, 0);
  });

  // AC-P1A-04: Ambiguity Detection & Safe Reason Codes
  it("flags PARTIAL_EXPLICIT_POLICY when only one explicit dimension is specified", () => {
    const doc1 = {
      clientId: "partial-type-only",
      clientType: "public",
      redirectUris: ["https://example.com/cb"],
    };
    const res1 = resolveClientPolicy(doc1);
    assert.equal(res1.isAmbiguous, true);
    assert.ok(res1.reasonCodes.includes("PARTIAL_EXPLICIT_POLICY"));

    const doc2 = {
      clientId: "partial-policy-only",
      accessPolicy: "open",
      redirectUris: ["https://example.com/cb"],
    };
    const res2 = resolveClientPolicy(doc2);
    assert.equal(res2.isAmbiguous, true);
    assert.ok(res2.reasonCodes.includes("PARTIAL_EXPLICIT_POLICY"));
  });

  it("flags MISSING_ACCESS_METADATA when explicit policy and legacy flags are absent", () => {
    const doc = {
      clientId: "missing-access-flags",
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("MISSING_ACCESS_METADATA"));
    assert.equal(res.accessPolicy, "private"); // Fails closed
  });

  it("flags MALFORMED_ACCESS_METADATA when legacy access flags are non-boolean", () => {
    const doc = {
      clientId: "string-access-flag",
      isPublic: "true" as any,
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("MALFORMED_ACCESS_METADATA"));
  });

  it("flags MALFORMED_DEV_FLAGS when dev flags are non-boolean", () => {
    const doc = {
      clientId: "number-dev-flag",
      isDev: 1 as any,
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("MALFORMED_DEV_FLAGS"));
  });

  it("flags CONFLICTING_AUTH_METHOD for mismatch between auth method and secrets", () => {
    const noneWithSecret = {
      clientId: "none-with-secret",
      token_endpoint_auth_method: "none",
      clientSecret: "stray-secret",
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    };
    const res1 = resolveClientPolicy(noneWithSecret);
    assert.equal(res1.isAmbiguous, true);
    assert.ok(res1.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));

    const basicWithoutSecret = {
      clientId: "basic-without-secret",
      token_endpoint_auth_method: "client_secret_basic",
      isPublic: false,
      redirectUris: ["https://example.com/cb"],
    };
    const res2 = resolveClientPolicy(basicWithoutSecret);
    assert.equal(res2.isAmbiguous, true);
    assert.ok(res2.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));

    const invalidAuthMethod = {
      clientId: "invalid-auth-method",
      token_endpoint_auth_method: "unsupported_method",
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    };
    const res3 = resolveClientPolicy(invalidAuthMethod);
    assert.equal(res3.isAmbiguous, true);
    assert.ok(res3.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));
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
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    };
    const res2 = resolveClientPolicy(nativeWithSecret);
    assert.equal(res2.isAmbiguous, true);
    assert.ok(res2.reasonCodes.includes("CONFLICTING_METADATA"));
  });

  it("flags CONFLICTING_ACCESS_FLAGS, DEV_FLAGS, and ID_FIELDS", () => {
    const accessConflict = resolveClientPolicy({
      clientId: "c1", isPublic: true, is_public: false, redirectUris: ["https://example.com/cb"],
    });
    assert.ok(accessConflict.reasonCodes.includes("CONFLICTING_ACCESS_FLAGS"));

    const devConflict = resolveClientPolicy({
      clientId: "c2", isDev: true, is_dev: false, isPublic: true, redirectUris: ["https://example.com/cb"],
    });
    assert.ok(devConflict.reasonCodes.includes("CONFLICTING_DEV_FLAGS"));

    const idConflict = resolveClientPolicy({
      clientId: "id-a", client_id: "id-b", isPublic: true, redirectUris: ["https://example.com/cb"],
    });
    assert.ok(idConflict.reasonCodes.includes("CONFLICTING_ID_FIELDS"));
  });

  it("flags MISSING_REDIRECT_URIS and INVALID_REDIRECT_URI without leaking raw URIs or credentials", () => {
    const sensitivePassword = "SuperSensitivePassword123!";
    const badDoc = {
      clientId: "bad-uri-client",
      isDev: false,
      isPublic: true,
      redirectUris: [`https://user:${sensitivePassword}@example.com/cb#fragment`],
    };
    const res = resolveClientPolicy(badDoc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("INVALID_REDIRECT_URI"));

    const reasonsText = JSON.stringify(res.reasons);
    assert.ok(!reasonsText.includes(sensitivePassword), "Reasons must omit raw credentials");
    assert.ok(!reasonsText.includes("https://"), "Reasons must omit raw redirect URIs");
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
