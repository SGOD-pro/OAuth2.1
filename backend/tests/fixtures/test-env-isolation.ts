/**
 * Test Environment & Infrastructure Isolation Guard
 *
 * Guarantees that tests and benchmarks NEVER inherit or contact production
 * infrastructure (MongoDB, Upstash Redis, or external APIs).
 * Must be executed before any application or configuration modules load.
 */

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

  // Validate MONGO_URI if already set in environment: must never be a remote production database
  if (process.env.MONGO_URI) {
    validateDisposableMongoUri(process.env.MONGO_URI);
  }
}

export function validateDisposableMongoUri(uri: string): void {
  if (!uri || typeof uri !== "string") return;
  const lower = uri.toLowerCase();

  const isRemote =
    lower.startsWith("mongodb+srv://") ||
    lower.includes(".mongodb.net") ||
    lower.includes("cluster") ||
    lower.includes("atlas") ||
    lower.includes("prod");

  const isLoopback =
    lower.includes("127.0.0.1") ||
    lower.includes("localhost") ||
    lower.includes("::1");

  if (isRemote || !isLoopback) {
    throw new Error(
      `[SECURITY_VIOLATION] Inherited non-disposable Mongo URI detected in test environment: "${uri}". ` +
      "Tests and benchmarks must strictly run against a local disposable MongoMemoryServer."
    );
  }
}

export function assertNoExternalInfrastructure(): void {
  for (const envVar of REDIS_ALIAS_ENV_VARS) {
    if (process.env[envVar]) {
      throw new Error(
        `[SECURITY_VIOLATION] Disallowed Redis environment variable active in test environment: ${envVar}=${process.env[envVar]}`
      );
    }
  }

  if (process.env.MONGO_URI) {
    validateDisposableMongoUri(process.env.MONGO_URI);
  }
}

// Automatically isolate upon import
isolateTestEnvironment();
