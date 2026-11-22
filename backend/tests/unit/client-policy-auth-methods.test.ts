import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveClientPolicy } from "../../src/identity/client-policy";

describe("OAuth V2 P1a: Authentication Method Classification & Regressions", () => {
  it("flags private_key_jwt with missing jwks and jwks_uri as ambiguous, not public", () => {
    const doc = {
      clientId: "client-pk-jwt-no-key",
      isPublic: true,
      token_endpoint_auth_method: "private_key_jwt",
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.equal(res.classification, "AMBIGUOUS");
    assert.equal(res.clientType, "confidential");
    assert.ok(res.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));
    assert.ok(res.reasons.some((r) => r.includes("requires jwks or jwks_uri")));
  });

  it("resolves private_key_jwt with valid jwks_uri and no secret as confidential", () => {
    const doc = {
      clientId: "client-pk-jwt-valid",
      isPublic: false,
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://example.com/jwks.json",
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, false);
    assert.equal(res.classification, "COMPATIBLE_PRIVATE_CONFIDENTIAL");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "private");
    assert.equal(res.reasonCodes.length, 0);
  });

  it("resolves open private_key_jwt with jwks as open confidential, never public", () => {
    const doc = {
      clientId: "client-pk-jwt-open",
      isPublic: true,
      token_endpoint_auth_method: "private_key_jwt",
      jwks: { keys: [{ kty: "RSA", kid: "k1", n: "abc", e: "AQAB" }] },
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, false);
    assert.equal(res.classification, "COMPATIBLE_OPEN_CONFIDENTIAL");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "open");
    assert.equal(res.reasonCodes.length, 0);
  });

  it("flags private_key_jwt with client secret as conflicting", () => {
    const doc = {
      clientId: "client-pk-jwt-with-secret",
      clientSecret: "unexpected-secret",
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://example.com/jwks.json",
      isPublic: false,
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.ok(res.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));
    assert.ok(res.reasons.some((r) => r.includes("cannot possess a client secret")));
  });

  it("flags unsupported client_secret_jwt as ambiguous", () => {
    const doc = {
      clientId: "client-secret-jwt-unsupported",
      clientSecret: "some-secret",
      token_endpoint_auth_method: "client_secret_jwt",
      isPublic: true,
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.equal(res.classification, "AMBIGUOUS");
    assert.ok(res.reasonCodes.includes("CONFLICTING_AUTH_METHOD"));
    assert.ok(res.reasons.some((r) => r.includes("Unsupported token_endpoint_auth_method")));
  });

  it("flags explicit public client specifying private_key_jwt as conflicting", () => {
    const doc = {
      clientId: "explicit-public-pk-jwt",
      clientType: "public",
      accessPolicy: "open",
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://example.com/jwks.json",
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, true);
    assert.equal(res.classification, "AMBIGUOUS");
    assert.ok(res.reasonCodes.includes("CONFLICTING_METADATA"));
  });

  it("preserves explicit migrated confidential client with private_key_jwt and jwks", () => {
    const doc = {
      clientId: "migrated-pk-jwt",
      clientType: "confidential",
      accessPolicy: "private",
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://example.com/jwks.json",
      redirectUris: ["https://example.com/callback"],
    };
    const res = resolveClientPolicy(doc);
    assert.equal(res.isAmbiguous, false);
    assert.equal(res.classification, "MIGRATED");
    assert.equal(res.clientType, "confidential");
    assert.equal(res.accessPolicy, "private");
  });

  it("preserves all four legitimate policy combinations without token_endpoint_auth_method", () => {
    const openPublic = resolveClientPolicy({
      clientId: "legit-open-pub",
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    });
    assert.equal(openPublic.classification, "COMPATIBLE_OPEN_PUBLIC");
    assert.equal(openPublic.clientType, "public");
    assert.equal(openPublic.accessPolicy, "open");

    const privConf = resolveClientPolicy({
      clientId: "legit-priv-conf",
      clientSecret: "secret-123",
      isPublic: false,
      redirectUris: ["https://example.com/cb"],
    });
    assert.equal(privConf.classification, "COMPATIBLE_PRIVATE_CONFIDENTIAL");
    assert.equal(privConf.clientType, "confidential");
    assert.equal(privConf.accessPolicy, "private");

    const openConf = resolveClientPolicy({
      clientId: "legit-open-conf",
      clientSecret: "secret-123",
      isPublic: true,
      redirectUris: ["https://example.com/cb"],
    });
    assert.equal(openConf.classification, "COMPATIBLE_OPEN_CONFIDENTIAL");
    assert.equal(openConf.clientType, "confidential");
    assert.equal(openConf.accessPolicy, "open");

    const privPub = resolveClientPolicy({
      clientId: "legit-priv-pub",
      isPublic: false,
      redirectUris: ["https://example.com/cb"],
    });
    assert.equal(privPub.classification, "COMPATIBLE_PRIVATE_PUBLIC");
    assert.equal(privPub.clientType, "public");
    assert.equal(privPub.accessPolicy, "private");
  });
});
