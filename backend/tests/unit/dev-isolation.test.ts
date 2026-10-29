/// <reference types="node" />
process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb://localhost:27017/test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const {
  validateOAuthClientConfiguration,
  validateRedirectUri,
  validateRedirectUris,
  isLoopbackHost,
  isPrivateOrLocalHost,
} = await import("../../src/utils/security");
const { verifyGatewaySecret } = await import("../../src/middleware/admin-auth");
const { config } = await import("../../src/config");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "../../..");

async function runTest(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
  } catch (err: any) {
    console.error(`  FAIL: ${name}`);
    console.error(err);
    process.exitCode = 1;
    throw err;
  }
}

console.log("=== Testing Slice 4: Dev Isolation and Dual Mode Client URIs ===");

// -----------------------------------------------------------------------------
// AC-1: Development enabled clients permit loopback and HTTPS, reject bad URIs
// -----------------------------------------------------------------------------
await runTest("AC-1: Dev client permits strict loopback URIs (localhost, 127.0.0.1, [::1], *.localhost)", () => {
  const loopbackUris = [
    "http://localhost:3000/callback",
    "http://127.0.0.1:3000/callback",
    "http://[::1]:3000/callback",
    "http://sub.localhost:8080/auth/callback",
    "https://localhost:3000/callback",
  ];

  for (const uri of loopbackUris) {
    assert.equal(validateRedirectUri(uri, { isDev: true, env: "production" }), true, `Expected valid redirect URI: ${uri}`);
    assert.equal(validateRedirectUri(uri, { isDev: true, env: "development" }), true, `Expected valid redirect URI: ${uri}`);
  }

  const res = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: loopbackUris, allowedOrigins: ["http://localhost:3000", "http://127.0.0.1:3000"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res.valid, true);
  assert.equal(res.effectiveApplicationType, "native");
});

await runTest("AC-1: Dev client permits valid public HTTPS URIs and allowed origins", () => {
  const httpsUris = [
    "https://preview.swyra.com/callback",
    "https://staging.myapp.io/auth/callback",
  ];

  for (const uri of httpsUris) {
    assert.equal(validateRedirectUri(uri, { isDev: true, env: "production" }), true, `Expected valid redirect URI: ${uri}`);
  }

  const res = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: httpsUris, allowedOrigins: ["https://preview.swyra.com"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res.valid, true);
});

await runTest("AC-1: Dev client permits dual mode URIs (both loopback and public HTTPS)", () => {
  const dualUris = [
    "http://localhost:3000/callback",
    "https://preview.swyra.com/callback",
  ];
  const dualOrigins = [
    "http://localhost:3000",
    "https://preview.swyra.com",
  ];

  const res = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: dualUris, allowedOrigins: dualOrigins },
    { serverEnvironment: "production" }
  );
  assert.equal(res.valid, true);
  assert.equal(res.effectiveApplicationType, "native");
});

await runTest("AC-1: Dev client strictly rejects wildcards, fragments, userinfo, and non-loopback HTTP", () => {
  // Wildcards
  assert.equal(validateRedirectUri("https://*.swyra.com/callback", { isDev: true }), false);
  const wildcardRes = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["https://*.swyra.com/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(wildcardRes.valid, false);
  assert.ok(wildcardRes.error?.includes("Wildcards are strictly forbidden"));

  // URI fragments
  assert.equal(validateRedirectUri("https://app.swyra.com/callback#token=123", { isDev: true }), false);
  const fragmentRes = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["https://app.swyra.com/callback#token=123"] },
    { serverEnvironment: "production" }
  );
  assert.equal(fragmentRes.valid, false);
  assert.ok(fragmentRes.error?.includes("fragment"));

  // User credentials
  assert.equal(validateRedirectUri("https://admin:pass@app.swyra.com/callback", { isDev: true }), false);
  const userinfoRes = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["https://admin:pass@app.swyra.com/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(userinfoRes.valid, false);
  assert.ok(userinfoRes.error?.includes("Userinfo"));

  // Non-loopback HTTP
  assert.equal(validateRedirectUri("http://example.com/callback", { isDev: true }), false);
  const nonLoopbackHttpRes = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://example.com/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(nonLoopbackHttpRes.valid, false);
  assert.ok(nonLoopbackHttpRes.error?.includes("HTTPS"));

  // Non-loopback HTTP in allowed origins
  const nonLoopbackOriginRes = validateOAuthClientConfiguration(
    { isDev: true, redirectUris: ["http://localhost:3000/callback"], allowedOrigins: ["http://example.com"] },
    { serverEnvironment: "production" }
  );
  assert.equal(nonLoopbackOriginRes.valid, false);
  assert.ok(nonLoopbackOriginRes.error?.includes("HTTPS"));
});

await runTest("AC-1: Dev client strictly rejects RFC1918 private intranet IP addresses", () => {
  const privateIps = [
    "https://10.0.0.1/callback",
    "https://192.168.1.100:3000/callback",
    "https://172.16.0.1/callback",
    "https://172.31.255.255/callback",
    "https://169.254.169.254/latest/meta-data",
  ];

  for (const uri of privateIps) {
    assert.equal(validateRedirectUri(uri, { isDev: true }), false, `Private IP must be rejected: ${uri}`);
    const res = validateOAuthClientConfiguration(
      { isDev: true, redirectUris: [uri] },
      { serverEnvironment: "production" }
    );
    assert.equal(res.valid, false, `Private IP must be rejected in client config: ${uri}`);
    assert.ok(res.error?.includes("Private and intranet IP addresses are forbidden"));
  }
});

await runTest("AC-1: Dev client rejects lookalike deceptive loopback hosts and link-local IPv6", () => {
  const deceptiveUris = [
    "http://localhost.evil.com/callback",
    "http://localhost.attacker.io/callback",
    "http://127.0.0.1.attacker.com/callback",
    "http://[fe80::1]/callback",
    "https://[::ffff:192.168.1.1]/callback",
    "https://[::ffff:c0a8:101]/callback",
    "https://[::ffff:169.254.169.254]/callback",
    "https://[::ffff:a9fe:a9fe]/callback",
  ];

  for (const uri of deceptiveUris) {
    assert.equal(validateRedirectUri(uri, { isDev: true }), false, `Deceptive URI must be rejected: ${uri}`);
    const res = validateOAuthClientConfiguration(
      { isDev: true, redirectUris: [uri] },
      { serverEnvironment: "production" }
    );
    assert.equal(res.valid, false, `Deceptive URI must be rejected: ${uri}`);
  }
});

await runTest("AC-1: Dev client automatically resolves application_type to native (RFC 8252)", () => {
  const res = validateOAuthClientConfiguration(
    {
      isDev: true,
      application_type: "web",
      redirectUris: ["http://localhost:3000/callback"],
    },
    { serverEnvironment: "production" }
  );
  assert.equal(res.valid, true);
  assert.equal(res.effectiveApplicationType, "native");
});

// -----------------------------------------------------------------------------
// AC-2: Production OAuth clients remain strictly HTTPS only
// -----------------------------------------------------------------------------
await runTest("AC-2: Production clients permit valid public HTTPS URIs", () => {
  const res = validateOAuthClientConfiguration(
    { isDev: false, redirectUris: ["https://auth.swyra.com/callback"], allowedOrigins: ["https://auth.swyra.com"] },
    { serverEnvironment: "production" }
  );
  assert.equal(res.valid, true);
  assert.equal(res.effectiveApplicationType, "web");
});

await runTest("AC-2: Production clients strictly forbid loopback and private IPs", () => {
  const loopbackUris = [
    "http://localhost:3000/callback",
    "http://127.0.0.1:3000/callback",
    "https://localhost:3000/callback",
  ];

  for (const uri of loopbackUris) {
    assert.equal(validateRedirectUri(uri, { isDev: false }), false);
    const res = validateOAuthClientConfiguration(
      { isDev: false, redirectUris: [uri] },
      { serverEnvironment: "production" }
    );
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes("Loopback redirect URIs are permitted only for development-mode"));
  }

  // Private IPs
  const resPrivate = validateOAuthClientConfiguration(
    { isDev: false, redirectUris: ["https://192.168.1.1/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(resPrivate.valid, false);
  assert.ok(resPrivate.error?.includes("Private and intranet IP addresses are forbidden"));

  // Non-HTTPS
  const resHttp = validateOAuthClientConfiguration(
    { isDev: false, redirectUris: ["http://example.com/callback"] },
    { serverEnvironment: "production" }
  );
  assert.equal(resHttp.valid, false);
  assert.ok(resHttp.error?.includes("Production OAuth clients require HTTPS"));
});

// -----------------------------------------------------------------------------
// AC-3: Super Admins can provision dev clients in production without global flag
// -----------------------------------------------------------------------------
await runTest("AC-3: Verified Super Admin creates dev client with loopback and HTTPS in production", () => {
  const res = validateOAuthClientConfiguration(
    {
      isDev: true,
      redirectUris: ["http://localhost:3000/callback", "https://preview.swyra.com/callback"],
      allowedOrigins: ["http://localhost:3000", "https://preview.swyra.com"],
    },
    {
      serverEnvironment: "production",
      isNewClient: true,
      allowDevClientsInProduction: false,
      isSuperAdminOp: true,
    }
  );
  assert.equal(res.valid, true);
});

await runTest("AC-3: Non Super Admin fails to create dev client in production when disabled", () => {
  const res = validateOAuthClientConfiguration(
    {
      isDev: true,
      redirectUris: ["http://localhost:3000/callback"],
      allowedOrigins: ["http://localhost:3000"],
    },
    {
      serverEnvironment: "production",
      isNewClient: true,
      allowDevClientsInProduction: false,
      isSuperAdminOp: false,
    }
  );
  assert.equal(res.valid, false);
  assert.ok(res.error?.includes("Only Super Admins may create new OAuth clients in development mode"));
});

// -----------------------------------------------------------------------------
// AC-4: Production mode gateway secret verification strictly fails closed
// -----------------------------------------------------------------------------
await runTest("AC-4: Production mode fails closed on missing/invalid secret or header", () => {
  const origSecret = process.env.INTERNAL_GATEWAY_SECRET;
  const origNodeEnv = process.env.NODE_ENV;

  try {
    process.env.NODE_ENV = "production";

    // 1. Unconfigured secret in production -> false (even for localhost host)
    delete process.env.INTERNAL_GATEWAY_SECRET;
    const mockContextLocal = {
      req: {
        header: (name: string) => (name.toLowerCase() === "host" ? "localhost:3000" : undefined),
        url: "http://localhost:3000/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextLocal), false);

    // 2. Configured secret, but missing x-gateway-secret header -> false
    const validSecret = "a_very_secure_internal_gateway_secret_minimum_32_characters";
    process.env.INTERNAL_GATEWAY_SECRET = validSecret;
    const mockContextNoHeader = {
      req: {
        header: (name: string) => undefined,
        url: "https://auth.swyra.com/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextNoHeader), false);

    // 3. Configured secret, but mismatched x-gateway-secret header -> false
    const mockContextWrongHeader = {
      req: {
        header: (name: string) => (name.toLowerCase() === "x-gateway-secret" ? "invalid_secret_value_that_does_not_match" : undefined),
        url: "https://auth.swyra.com/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextWrongHeader), false);

    // 4. Configured secret and matching x-gateway-secret header -> true
    const mockContextValid = {
      req: {
        header: (name: string) => (name.toLowerCase() === "x-gateway-secret" ? validSecret : undefined),
        url: "https://auth.swyra.com/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextValid), true);
  } finally {
    if (origSecret !== undefined) {
      process.env.INTERNAL_GATEWAY_SECRET = origSecret;
    } else {
      delete process.env.INTERNAL_GATEWAY_SECRET;
    }
    process.env.NODE_ENV = origNodeEnv;
  }
});

// -----------------------------------------------------------------------------
// AC-5: Development mode permits loopback requests when secret is unconfigured
// -----------------------------------------------------------------------------
await runTest("AC-5: Development mode loopback bypass and non-loopback rejection", () => {
  const origSecret = process.env.INTERNAL_GATEWAY_SECRET;
  const origNodeEnv = process.env.NODE_ENV;

  try {
    process.env.NODE_ENV = "development";
    delete process.env.INTERNAL_GATEWAY_SECRET;

    // 1. Unconfigured secret with localhost host header -> true (bypass permitted)
    const mockContextLocalhost = {
      req: {
        header: (name: string) => (name.toLowerCase() === "host" ? "localhost:5174" : undefined),
        url: "http://localhost:5174/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextLocalhost), true);

    // 2. Unconfigured secret with 127.0.0.1 host header -> true
    const mockContext127 = {
      req: {
        header: (name: string) => (name.toLowerCase() === "host" ? "127.0.0.1:3000" : undefined),
        url: "http://127.0.0.1:3000/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContext127), true);

    // 3. Unconfigured secret with [::1] IPv6 host header -> true
    const mockContextIpv6 = {
      req: {
        header: (name: string) => (name.toLowerCase() === "host" ? "[::1]:3000" : undefined),
        url: "http://[::1]:3000/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextIpv6), true);

    // 4. Unconfigured secret with external non-loopback host header -> false
    const mockContextExternal = {
      req: {
        header: (name: string) => (name.toLowerCase() === "host" ? "api.external.com" : undefined),
        url: "http://api.external.com/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextExternal), false);

    // 5. Configured secret in development still enforces secret header
    const devSecret = "dev_internal_gateway_secret_minimum_32_characters_long";
    process.env.INTERNAL_GATEWAY_SECRET = devSecret;
    const mockContextWithSecret = {
      req: {
        header: (name: string) => (name.toLowerCase() === "x-gateway-secret" ? devSecret : undefined),
        url: "http://localhost:3000/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextWithSecret), true);

    const mockContextWrongSecret = {
      req: {
        header: (name: string) => (name.toLowerCase() === "x-gateway-secret" ? "wrong" : undefined),
        url: "http://localhost:3000/api/admin/metrics",
      },
    };
    assert.equal(verifyGatewaySecret(mockContextWrongSecret), false);
  } finally {
    if (origSecret !== undefined) {
      process.env.INTERNAL_GATEWAY_SECRET = origSecret;
    } else {
      delete process.env.INTERNAL_GATEWAY_SECRET;
    }
    process.env.NODE_ENV = origNodeEnv;
  }
});

await runTest("AC-4: Gateway secret rotation supports comma separated secrets with trimming", () => {
  const origSecret = process.env.INTERNAL_GATEWAY_SECRET;
  const origNodeEnv = process.env.NODE_ENV;

  try {
    process.env.NODE_ENV = "production";
    const secretA = "first_secret_that_is_at_least_32_characters_long";
    const secretB = "second_secret_that_is_at_least_32_characters_long";
    process.env.INTERNAL_GATEWAY_SECRET = `  ${secretA}  ,  ${secretB}  `;

    // Secret A matches
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "x-gateway-secret" ? secretA : undefined),
          url: "https://auth.swyra.com/api/admin",
        },
      }),
      true
    );

    // Secret B matches
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "x-gateway-secret" ? secretB : undefined),
          url: "https://auth.swyra.com/api/admin",
        },
      }),
      true
    );

    // Mismatched secret fails
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "x-gateway-secret" ? "invalid" : undefined),
          url: "https://auth.swyra.com/api/admin",
        },
      }),
      false
    );
  } finally {
    if (origSecret !== undefined) {
      process.env.INTERNAL_GATEWAY_SECRET = origSecret;
    } else {
      delete process.env.INTERNAL_GATEWAY_SECRET;
    }
    process.env.NODE_ENV = origNodeEnv;
  }
});

await runTest("AC-5: Development mode gateway bypass rejects deceptive lookalike hosts and supports x-forwarded-host", () => {
  const origSecret = process.env.INTERNAL_GATEWAY_SECRET;
  const origNodeEnv = process.env.NODE_ENV;

  try {
    process.env.NODE_ENV = "development";
    delete process.env.INTERNAL_GATEWAY_SECRET;

    // Deceptive lookalike host header in dev -> rejected
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "host" ? "localhost.evil.com:5174" : undefined),
          url: "http://localhost.evil.com:5174/api/admin",
        },
      }),
      false
    );

    // x-forwarded-host header fallback -> permitted when loopback
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "x-forwarded-host" ? "127.0.0.1:3000" : undefined),
          url: "http://127.0.0.1:3000/api/admin",
        },
      }),
      true
    );

    // External socket remoteAddress spoofing Host: localhost -> rejected
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "host" ? "localhost:5174" : undefined),
          url: "http://localhost:5174/api/admin",
          socket: { remoteAddress: "192.168.1.50" },
        },
      }),
      false
    );

    // Loopback socket remoteAddress -> permitted
    assert.equal(
      verifyGatewaySecret({
        req: {
          header: (n: string) => (n.toLowerCase() === "host" ? "localhost:5174" : undefined),
          url: "http://localhost:5174/api/admin",
          socket: { remoteAddress: "127.0.0.1" },
        },
      }),
      true
    );
  } finally {
    if (origSecret !== undefined) {
      process.env.INTERNAL_GATEWAY_SECRET = origSecret;
    } else {
      delete process.env.INTERNAL_GATEWAY_SECRET;
    }
    process.env.NODE_ENV = origNodeEnv;
  }
});

// -----------------------------------------------------------------------------
// AC-6: Monorepo root .env.example verification
// -----------------------------------------------------------------------------
await runTest("AC-6: Root .env.example defaults to development and defines gateway secret", () => {
  const envExamplePath = path.join(rootDir, ".env.example");
  assert.ok(fs.existsSync(envExamplePath), ".env.example file must exist");

  const content = fs.readFileSync(envExamplePath, "utf8");
  assert.ok(content.includes("NODE_ENV=development"), ".env.example must default to development");
  assert.ok(content.includes("INTERNAL_GATEWAY_SECRET="), ".env.example must define INTERNAL_GATEWAY_SECRET");
  assert.ok(content.includes("ALLOW_DEV_CLIENTS_IN_PRODUCTION=false"), ".env.example must document ALLOW_DEV_CLIENTS_IN_PRODUCTION=false");

  // Verify secret length >= 32
  const match = content.match(/^INTERNAL_GATEWAY_SECRET=(.*)$/m);
  assert.ok(match && match[1], "INTERNAL_GATEWAY_SECRET value must be present");
  assert.ok(match[1].trim().length >= 32, "INTERNAL_GATEWAY_SECRET value must be at least 32 characters");
});

// -----------------------------------------------------------------------------
// AC-7: Script path alignments and convenience scripts in root package.json
// -----------------------------------------------------------------------------
await runTest("AC-7: start-all.sh correctly references backend instead of legacy hono", () => {
  const startAllPath = path.join(rootDir, "start-all.sh");
  assert.ok(fs.existsSync(startAllPath), "start-all.sh must exist");

  const content = fs.readFileSync(startAllPath, "utf8");
  assert.ok(!content.includes('HONO_DIR="$ROOT_DIR/hono"'), "start-all.sh must not reference HONO_DIR");
  assert.ok(content.includes('BACKEND_DIR="$ROOT_DIR/backend"'), "start-all.sh must define BACKEND_DIR");
});

await runTest("AC-7: check_users.mjs and test_signup.mjs do not reference legacy hono/.env", () => {
  const checkUsersPath = path.join(rootDir, "backend/check_users.mjs");
  const testSignupPath = path.join(rootDir, "backend/test_signup.mjs");

  const checkUsersContent = fs.readFileSync(checkUsersPath, "utf8");
  const testSignupContent = fs.readFileSync(testSignupPath, "utf8");

  assert.ok(!checkUsersContent.includes("hono/.env"), "check_users.mjs must not reference hono/.env");
  assert.ok(!testSignupContent.includes("hono/.env"), "test_signup.mjs must not reference hono/.env");
});

await runTest("AC-7: Root package.json registers convenience developer scripts", () => {
  const pkgPath = path.join(rootDir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

  assert.ok(pkg.scripts?.dev, "Root package.json must include dev script");
  assert.ok(pkg.scripts?.["dev:backend"], "Root package.json must include dev:backend script");
  assert.ok(pkg.scripts?.["dev:frontend"], "Root package.json must include dev:frontend script");
  assert.ok(pkg.scripts?.["admin:create"], "Root package.json must include admin:create script");
});

console.log("=== All Slice 4 Tests Passed Successfully! ===");
