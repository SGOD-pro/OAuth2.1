/**
 * Test Environment & Infrastructure Isolation Guard
 *
 * Guarantees that tests and benchmarks NEVER inherit or contact production
 * infrastructure (MongoDB, Upstash Redis, or external APIs).
 * Must be executed before any application or configuration modules load.
 */

export const MONGO_ALIAS_ENV_VARS = [
  "MONGO_URI",
  "MONGODB_URI",
  "DATABASE_URL",
  "MONGO_URL",
];

export const REDIS_ALIAS_ENV_VARS = [
  "UPSTASH_REDIS_REST_URL",
  "UPSTASH_REDIS_REST_TOKEN",
  "UPSTASH_REDIS_API_KEY",
  "REDIS_URL",
  "REDIS_TOKEN",
  "REDIS_REST_URL",
  "REDIS_REST_TOKEN",
];

export function isolateTestEnvironment(): void {
  process.env.NODE_ENV = "test";

  // Strip all Redis environment variables to prevent accidental connection to production Redis
  for (const envVar of REDIS_ALIAS_ENV_VARS) {
    delete process.env[envVar];
  }

  // Also scan for any other stray *REDIS* environment variables
  for (const key of Object.keys(process.env)) {
    if (key.includes("REDIS") && !key.startsWith("TEST_REDIS")) {
      delete process.env[key];
    }
  }

  // Validate all Mongo environment variable aliases: must never be a remote production database
  for (const envVar of MONGO_ALIAS_ENV_VARS) {
    if (process.env[envVar]) {
      validateDisposableMongoUri(process.env[envVar]!, envVar);
    }
  }
}

export interface ParsedMongoEndpoint {
  protocol: string;
  host: string;
  port: number;
}

export function parseMongoEndpoint(uri: string): ParsedMongoEndpoint {
  if (!uri || typeof uri !== "string") {
    throw new Error("[SECURITY_VIOLATION] Empty or non-string Mongo URI provided.");
  }

  const lower = uri.toLowerCase();

  // Reject mongodb+srv://
  if (lower.startsWith("mongodb+srv://")) {
    throw new Error("[SECURITY_VIOLATION] Remote SRV Mongo URIs are rejected in test environment.");
  }

  // Reject multi-host URIs (e.g. mongodb://host1:27017,host2:27017/db)
  const afterScheme = uri.replace(/^mongodb:\/\//i, "");
  const authorityPart = afterScheme.split("/")[0].split("?")[0];
  if (authorityPart.includes(",")) {
    throw new Error("[SECURITY_VIOLATION] Multi-host Mongo URIs are rejected in test environment.");
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("[SECURITY_VIOLATION] Malformed Mongo URI provided.");
  }

  if (parsed.protocol !== "mongodb:") {
    throw new Error("[SECURITY_VIOLATION] Disallowed protocol in Mongo URI.");
  }

  let hostname = parsed.hostname.toLowerCase();
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") {
    hostname = "127.0.0.1";
  }

  if (hostname !== "127.0.0.1") {
    throw new Error("[SECURITY_VIOLATION] Non-loopback host in Mongo URI.");
  }

  const port = parsed.port ? parseInt(parsed.port, 10) : 27017;
  if (isNaN(port) || port <= 0 || port > 65535) {
    throw new Error("[SECURITY_VIOLATION] Invalid port in Mongo URI.");
  }

  return {
    protocol: parsed.protocol,
    host: hostname,
    port,
  };
}

export function validateDisposableMongoUri(uri: string, varName: string = "MONGO_URI"): void {
  if (!uri || typeof uri !== "string") return;
  try {
    parseMongoEndpoint(uri);
  } catch {
    throw new Error(
      `[SECURITY_VIOLATION] Inherited non-disposable Mongo URI detected in test environment (variable: ${varName}). ` +
      "Tests and benchmarks must strictly run against a local disposable MongoMemoryServer."
    );
  }
}

/**
 * Proves that the active MONGO_URI matches the URI of a specific MongoMemoryServer
 * instance. Call this immediately after MongoMemoryServer.create() and before any
 * database operations to assert that no inherited or ambient URI is in use.
 *
 * Parses the actual connection endpoint, verifies the host is loopback, and proves
 * the port matches the disposable instance's exact port. Does not print credentials
 * or raw connection strings in error messages.
 *
 * @param mongodUri - The URI returned by mongod.getUri() from your MongoMemoryServer.
 * @param envVar - The environment variable to check (defaults to "MONGO_URI").
 */
export function assertIsMemoryServerUri(mongodUri: string, envVar: string = "MONGO_URI"): void {
  const activeUri = process.env[envVar];
  if (!activeUri) return; // No ambient URI is set — safe by absence.

  const expected = parseMongoEndpoint(mongodUri);
  const active = parseMongoEndpoint(activeUri);

  if (active.host !== expected.host || active.port !== expected.port) {
    throw new Error(
      `[SECURITY_VIOLATION] Active ${envVar} endpoint does not match the disposable MongoMemoryServer. ` +
      "Target host or port mismatch. Tests must strictly use the test-created MongoMemoryServer."
    );
  }
}

export function assertNoExternalInfrastructure(): void {
  for (const envVar of REDIS_ALIAS_ENV_VARS) {
    if (process.env[envVar]) {
      throw new Error(
        `[SECURITY_VIOLATION] Disallowed Redis environment variable active in test environment (variable: ${envVar}). ` +
        "Tests and benchmarks must strictly run against a local disposable mock Redis server."
      );
    }
  }

  for (const envVar of MONGO_ALIAS_ENV_VARS) {
    if (process.env[envVar]) {
      validateDisposableMongoUri(process.env[envVar]!, envVar);
    }
  }
}

// Automatically isolate upon import
isolateTestEnvironment();
