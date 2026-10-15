/// <reference types="node" />
process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://localhost:27017/test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.INTERNAL_GATEWAY_SECRET = "g".repeat(32);

import assert from "node:assert/strict";
import { ObjectId } from "mongodb";

const {
  deriveAllowedOriginsFromRedirectUris,
  normalizeOAuthClientFields,
  validateOAuthClientConfiguration,
  resolveOAuthClient,
} = await import("../../src/utils/security");
const { deriveOrigins } = await import("../../../frontend/lib/security.ts");

console.log("=== Testing Slice 5: Application Configuration Simplification ===");

// TEST 1: Origin auto derivation from valid HTTPS and HTTP loopback URIs (AC-1)
{
  const uris = [
    "https://app.example.com/oauth/callback",
    "https://app.example.com/silent-renew.html",
    "http://localhost:3000/callback",
    "http://127.0.0.1:8080/callback",
    "https://partner.portal.io:8443/auth/cb",
  ];

  const origins = deriveAllowedOriginsFromRedirectUris(uris);

  assert.equal(origins.length, 4, "Should extract 4 unique web origins");
  assert.ok(origins.includes("https://app.example.com"), "Should include https://app.example.com");
  assert.ok(origins.includes("http://localhost:3000"), "Should include http://localhost:3000");
  assert.ok(origins.includes("http://127.0.0.1:8080"), "Should include http://127.0.0.1:8080");
  assert.ok(origins.includes("https://partner.portal.io:8443"), "Should include https://partner.portal.io:8443");

  console.log("PASS: AC-1: Origin auto derivation extracts unique web origins from redirect URIs");
}

// TEST 2: Origin auto derivation skips non web schemes and malformed URIs safely (AC-4)
{
  const mixedUris = [
    "com.swyra.mobileapp://oauth/callback",
    "myapp://auth",
    "https://mobile.swyra.com/callback",
    "javascript:alert(1)",
    "not-a-valid-url",
    "",
    "   ",
  ];

  const origins = deriveAllowedOriginsFromRedirectUris(mixedUris);

  assert.equal(origins.length, 1, "Should only extract the single valid HTTPS origin");
  assert.equal(origins[0], "https://mobile.swyra.com");

  // Also test non array input tolerance
  assert.deepEqual(deriveAllowedOriginsFromRedirectUris(null as any), []);
  assert.deepEqual(deriveAllowedOriginsFromRedirectUris(undefined as any), []);

  console.log("PASS: AC-4: Non web URI schemes and malformed URIs are safely skipped without errors");
}

// TEST 3: Validation automatically derives allowed origins when omitted or empty (AC-2)
{
  const targetState = {
    client_name: "Customer Dashboard",
    redirect_uris: ["https://dashboard.example.com/callback"],
    allowed_origins: [],
    isDev: false,
    isPublic: true,
  };

  const result = validateOAuthClientConfiguration(targetState, {
    serverEnvironment: "production",
    isNewClient: false,
  });

  assert.equal(result.valid, true, "Validation should succeed with auto derived origins");
  assert.deepEqual(result.effectiveAllowedOrigins, ["https://dashboard.example.com"]);
  assert.equal(result.effectiveApplicationType, "web");

  console.log("PASS: AC-2: Configuration validation auto derives allowed origins when empty");
}

// TEST 4: Explicit allowed origins are respected and preserved without unwanted overrides (AC-3)
{
  const targetState = {
    client_name: "Multi Domain Client",
    redirect_uris: ["https://auth.example.com/callback"],
    allowed_origins: ["https://cdn.example.com", "https://api.example.com"],
    isDev: false,
    isPublic: true,
  };

  const result = validateOAuthClientConfiguration(targetState, {
    serverEnvironment: "production",
    isNewClient: false,
  });

  assert.equal(result.valid, true, "Validation should succeed");
  assert.deepEqual(result.effectiveAllowedOrigins, ["https://cdn.example.com", "https://api.example.com"]);

  console.log("PASS: AC-3: Explicitly supplied allowed origins are preserved without overrides");
}

// TEST 5: Centralized client document field normalization across casing conventions (AC-5)
{
  // Test snake_case source
  const snakeDoc = {
    _id: new ObjectId(),
    client_id: "client-snake-123",
    client_name: "Snake App",
    redirect_uris: ["https://snake.example.com/callback"],
    allowed_origins: ["https://snake.example.com"],
    is_dev: true,
    is_public: false,
    client_secret: "secret-abc",
    skip_consent: true,
    disabled: false,
  };

  const normalizedFromSnake = normalizeOAuthClientFields(snakeDoc);

  assert.equal(normalizedFromSnake.clientId, "client-snake-123");
  assert.equal(normalizedFromSnake.client_id, "client-snake-123");
  assert.equal(normalizedFromSnake.name, "Snake App");
  assert.equal(normalizedFromSnake.client_name, "Snake App");
  assert.deepEqual(normalizedFromSnake.redirectUris, ["https://snake.example.com/callback"]);
  assert.deepEqual(normalizedFromSnake.redirect_uris, ["https://snake.example.com/callback"]);
  assert.deepEqual(normalizedFromSnake.allowedOrigins, ["https://snake.example.com"]);
  assert.deepEqual(normalizedFromSnake.allowed_origins, ["https://snake.example.com"]);
  assert.equal(normalizedFromSnake.isDev, true);
  assert.equal(normalizedFromSnake.is_dev, true);
  assert.equal(normalizedFromSnake.isPublic, false);
  assert.equal(normalizedFromSnake.is_public, false);
  assert.equal(normalizedFromSnake.clientSecret, "secret-abc");
  assert.equal(normalizedFromSnake.client_secret, "secret-abc");
  assert.equal(normalizedFromSnake.skipConsent, true);
  assert.equal(normalizedFromSnake.skip_consent, true);

  // Test camelCase source with omitted allowed origins (auto derivation in normalization)
  const camelDoc = {
    _id: new ObjectId(),
    clientId: "client-camel-456",
    name: "Camel App",
    redirectUris: ["https://camel.example.com/cb", "http://localhost:5000/cb"],
    isDev: true,
    isPublic: true,
    clientSecret: "secret-xyz",
    disabled: true,
  };

  const normalizedFromCamel = normalizeOAuthClientFields(camelDoc);

  assert.equal(normalizedFromCamel.clientId, "client-camel-456");
  assert.equal(normalizedFromCamel.client_id, "client-camel-456");
  assert.equal(normalizedFromCamel.name, "Camel App");
  assert.equal(normalizedFromCamel.client_name, "Camel App");
  assert.deepEqual(normalizedFromCamel.redirectUris, ["https://camel.example.com/cb", "http://localhost:5000/cb"]);
  assert.deepEqual(normalizedFromCamel.redirect_uris, ["https://camel.example.com/cb", "http://localhost:5000/cb"]);
  assert.deepEqual(normalizedFromCamel.allowedOrigins, ["https://camel.example.com", "http://localhost:5000"]);
  assert.deepEqual(normalizedFromCamel.allowed_origins, ["https://camel.example.com", "http://localhost:5000"]);
  assert.equal(normalizedFromCamel.isDev, true);
  assert.equal(normalizedFromCamel.is_dev, true);
  assert.equal(normalizedFromCamel.isPublic, true);
  assert.equal(normalizedFromCamel.is_public, true);
  assert.equal(normalizedFromCamel.disabled, true);

  console.log("PASS: AC-5: Centralized normalizeOAuthClientFields resolves camelCase and snake_case consistently");
}

// TEST 6: resolveOAuthClient retrieves and normalizes client by any identifier (AC-5)
{
  const targetId = new ObjectId();
  const mockClientDoc = {
    _id: targetId,
    client_id: "acme-corp-client",
    client_name: "Acme Corporation",
    redirect_uris: ["https://acme.com/oauth/callback"],
    is_dev: false,
    is_public: true,
  };

  const mockDb = {
    collection: (name: string) => {
      assert.equal(name, "oauthClient");
      return {
        findOne: async (query: any) => {
          if (query.$or) {
            const matches = query.$or.some((subQ: any) => {
              if (subQ.clientId === "acme-corp-client") return true;
              if (subQ.client_id === "acme-corp-client") return true;
              if (subQ.id === "acme-corp-client") return true;
              if (subQ._id && subQ._id.equals && subQ._id.equals(targetId)) return true;
              return false;
            });
            if (matches) return { ...mockClientDoc };
          }
          return null;
        },
      };
    },
  };

  // Resolve by client_id string
  const resolvedByClientId = await resolveOAuthClient(mockDb, "acme-corp-client");
  assert.ok(resolvedByClientId, "Client must be resolved by client_id");
  assert.equal(resolvedByClientId.clientId, "acme-corp-client");
  assert.equal(resolvedByClientId.client_id, "acme-corp-client");
  assert.equal(resolvedByClientId.name, "Acme Corporation");
  assert.deepEqual(resolvedByClientId.allowedOrigins, ["https://acme.com"]);
  assert.deepEqual(resolvedByClientId.allowed_origins, ["https://acme.com"]);

  // Resolve by ObjectId hex string
  const resolvedByHexId = await resolveOAuthClient(mockDb, targetId.toHexString());
  assert.ok(resolvedByHexId, "Client must be resolved by ObjectId string");
  assert.equal(resolvedByHexId.clientId, "acme-corp-client");

  // Non-existent client returns null
  const resolvedNonExistent = await resolveOAuthClient(mockDb, "does-not-exist");
  assert.equal(resolvedNonExistent, null, "Non-existent client returns null");

  console.log("PASS: AC-5: resolveOAuthClient resolves documents and returns canonical normalized fields");
}

// TEST 7: Frontend deriveOrigins utility extracts valid web origins and ignores non-web schemes (AC-1, AC-4, AC-6)
{
  const frontendUris = [
    "https://frontend.example.com/callback",
    "http://localhost:5173/auth",
    "myapp://mobile-callback",
    "invalid-uri",
    "javascript:void(0)",
  ];

  const origins = deriveOrigins(frontendUris);
  assert.equal(origins.length, 2, "Frontend helper should extract exactly 2 valid origins");
  assert.ok(origins.includes("https://frontend.example.com"));
  assert.ok(origins.includes("http://localhost:5173"));

  // Check defensive array handling
  assert.deepEqual(deriveOrigins(null as any), []);
  assert.deepEqual(deriveOrigins(undefined as any), []);

  console.log("PASS: AC-6: Frontend deriveOrigins extracts web origins and tolerates invalid/mobile URIs");
}

// TEST 8: Full parity between backend and frontend origin derivation helpers (AC-1, AC-6)
{
  const parityUris = [
    "https://portal.swyra.io/auth/callback",
    "https://portal.swyra.io/silent-renew",
    "http://127.0.0.1:3000/callback",
    "http://localhost:8080/callback",
    "com.swyra.app://oauth",
    "urn:ietf:wg:oauth:2.0:oob",
  ];

  const backendOrigins = deriveAllowedOriginsFromRedirectUris(parityUris).sort();
  const frontendOrigins = deriveOrigins(parityUris).sort();

  assert.deepEqual(
    backendOrigins,
    frontendOrigins,
    "Backend and frontend derivation helpers must produce identical origin lists"
  );
  assert.deepEqual(backendOrigins, [
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "https://portal.swyra.io",
  ]);

  console.log("PASS: AC-1 & AC-6: Parity verified between backend and frontend origin derivation");
}

// TEST 9: Origin derivation edge cases: IPv6 loopback, ports, case normalization, trailing slashes (AC-1, AC-4)
{
  const edgeUris = [
    "HTTPS://API.EXAMPLE.COM:8443/OAUTH/CALLBACK/",
    "http://[::1]:9090/cb",
    "https://app.example.com/",
    "file:///etc/hosts",
    "data:text/html,<html></html>",
    "blob:https://example.com/uuid",
  ];

  const backendResult = deriveAllowedOriginsFromRedirectUris(edgeUris);
  assert.ok(backendResult.includes("https://api.example.com:8443"), "Should lowercase host and preserve port");
  assert.ok(backendResult.includes("http://[::1]:9090"), "Should support IPv6 bracketed loopback with port");
  assert.ok(backendResult.includes("https://app.example.com"), "Should strip trailing slash from path");
  assert.equal(backendResult.length, 3, "Should exclude file, data, and blob URIs");

  const frontendResult = deriveOrigins(edgeUris);
  assert.deepEqual(frontendResult.sort(), backendResult.sort(), "Edge cases must have identical results");

  console.log("PASS: AC-1 & AC-4: Origin derivation handles IPv6, custom ports, casing, and dangerous pseudo-schemes");
}

// TEST 10: normalizeOAuthClientFields resilience with null/undefined, partial fields, and custom metadata (AC-5)
{
  // Null or primitive input tolerance
  assert.equal(normalizeOAuthClientFields(null as any), null);
  assert.equal(normalizeOAuthClientFields(undefined as any), undefined);
  assert.equal(normalizeOAuthClientFields("string" as any), "string");

  // Partial document with custom extra fields preserved
  const minimalDoc = {
    _id: "custom-id-123",
    name: "Minimal App",
    customMetadataField: "preserved-value",
  };
  const normalized = normalizeOAuthClientFields(minimalDoc);
  assert.equal(normalized.clientId, "custom-id-123");
  assert.equal(normalized.client_id, "custom-id-123");
  assert.equal(normalized.client_name, "Minimal App");
  assert.equal(normalized.customMetadataField, "preserved-value");
  assert.deepEqual(normalized.redirectUris, []);
  assert.deepEqual(normalized.redirect_uris, []);
  assert.deepEqual(normalized.allowedOrigins, []);
  assert.deepEqual(normalized.allowed_origins, []);
  assert.equal(normalized.isPublic, true);
  assert.equal(normalized.is_public, true);
  assert.equal(normalized.isDev, false);
  assert.equal(normalized.is_dev, false);

  console.log("PASS: AC-5: normalizeOAuthClientFields is resilient with nulls, defaults, and custom metadata");
}

console.log("=== All Slice 5 Unit Tests Passed Successfully! ===");

