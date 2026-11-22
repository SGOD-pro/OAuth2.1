import { createLocalAccountIssuer } from "@better-auth/core/db";
import { getDatabaseFieldIndexName, resolveDatabaseTableIndexes } from "@better-auth/core/db/internal";
import { createAuthMiddleware } from "better-auth/api";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import { MongoClient } from "mongodb";
import { createEngineTransactionBoundary } from "../../src/identity/engine-transaction";
import { isolateTestEnvironment } from "./test-env-isolation";

export async function p0Fixture() {
  isolateTestEnvironment();
  const replica = await MongoMemoryReplSet.create({
    replSet: { count: 1, storageEngine: "wiredTiger" },
    binary: { version: "7.0.24" },
    instanceOpts: [{ args: ["--nounixsocket"] }],
  });
  const client = await new MongoClient(replica.getUri()).connect();
  const db = client.db("p0_compatibility");
  Object.assign(process.env, {
    MONGO_URI: replica.getUri("p0_compatibility"), NODE_ENV: "test",
    BETTER_AUTH_SECRET: "p0-disposable-engine-secret-000000000000",
    BETTER_AUTH_URL: "http://localhost:3000", FRONTEND_URL: "http://localhost:5174",
    GOOGLE_CLIENT_ID: "p0-unused", GOOGLE_CLIENT_SECRET: "p0-unused",
    INTERNAL_GATEWAY_SECRET: "p0-disposable-gateway-secret-0000000000",
    AUTH_EMAIL_VERIFICATION_ENABLED: "false", AUTH_PUBLIC_SIGNUP_ENABLED: "true",
  });
  const { authProvider } = await import("../../src/utils/auth");
  const { closeDb } = await import("../../src/db/mongo");
  const boundary = createEngineTransactionBoundary(db, client);
  let failAt: "user" | "credential" | null = null;
  const proofSchema: BetterAuthPlugin = {
    id: "p0-proof-fixture",
    schema: {
      p0Proof: { fields: {
        digest: { type: "string", unique: true },
        email: { type: "string" },
        expiresAt: { type: "date" },
      } },
    },
  };
  let held: { notify: () => void; wait: Promise<void> } | null = null;
  const engine = betterAuth({
    ...authProvider.options,
    database: boundary.database,
    hooks: { before: createAuthMiddleware(async ctx => {
      if (held && ctx.path === "/oauth2/authorize" && ctx.headers?.get("x-p0-hold") === "yes") {
        held.notify();
        await held.wait;
      }
    }) },
    plugins: [...(authProvider.options.plugins ?? []), proofSchema],
    user: { ...authProvider.options.user, additionalFields: {
      ...authProvider.options.user?.additionalFields,
      username: { type: "string", unique: true, required: false },
    } },
    databaseHooks: {
      ...authProvider.options.databaseHooks,
      user: { create: { before: async (user) => {
        if (failAt === "user") throw new Error("injected identity failure");
        return authProvider.options.databaseHooks!.user!.create!.before!(user);
      } } },
      account: { create: { before: async (account) => {
        if (failAt === "credential") throw new Error("injected credential failure");
        return { data: account };
      } } },
    },
  });
  const context = await engine.$context;
  // Pre-create collections/indexes outside transactions. P2 owns real migrations.
  for (const [model, table] of Object.entries(context.tables)) {
    const name = table.modelName ?? model;
    await db.createCollection(name);
    for (const [field, definition] of Object.entries(table.fields)) {
      if (!definition.index && !definition.unique) continue;
      const column = definition.fieldName ?? field;
      try {
        await db.collection(name).createIndex({ [column]: 1 }, {
          name: getDatabaseFieldIndexName(name, column, definition.unique ?? false),
          unique: definition.unique ?? false,
        });
      } catch (err: any) {
        if (err?.code !== 86 && !err?.message?.includes("already exists")) throw err;
      }
    }
    for (const index of resolveDatabaseTableIndexes({
      fields: table.fields, indexes: table.indexes, tableName: name,
    })) {
      try {
        await db.collection(name).createIndex(Object.fromEntries(
          index.columns.map(field => [field === "id" ? "_id" : field, 1]),
        ), { name: index.name, unique: index.unique ?? false });
      } catch (err: any) {
        if (err?.code !== 86 && !err?.message?.includes("already exists")) throw err;
      }
    }
  }
  const hash = await context.password.hash("P0-Disposable-Password!123");
  async function proof(digest: string, email: string, expired = false) {
    await context.adapter.create({ model: "p0Proof", data: {
      digest, email, expiresAt: new Date(Date.now() + (expired ? -60_000 : 60_000)),
    } });
  }
  async function complete(digest: string, username: string) {
    return boundary.run(engine, async ({ adapter, internalAdapter }) => {
      const consumed = await adapter.consumeOne<{ email: string }>({
        model: "p0Proof", where: [
          { field: "digest", value: digest },
          { field: "expiresAt", operator: "gt", value: new Date() },
        ],
      });
      if (!consumed) throw new Error("Proof unavailable");
      const user = await internalAdapter.createUser({
        email: consumed.email, emailVerified: true, name: username, username,
      } as Parameters<typeof internalAdapter.createUser>[0], { method: "email-password" });
      if (!user) throw new Error("Identity not created");
      const account = await internalAdapter.linkAccount({
        userId: user.id, accountId: user.id, providerId: "credential", issuer: createLocalAccountIssuer("credential"), password: hash,
      });
      if (!account) throw new Error("Credential not created");
      return user;
    });
  }
  return {
    engine, context, db, boundary, proof, complete,
    holdAuthorize: () => {
      let notify!: () => void;
      let release!: () => void;
      const reached = new Promise<void>(resolve => { notify = resolve; });
      const wait = new Promise<void>(resolve => { release = resolve; });
      held = { notify, wait };
      return { reached, release: () => { release(); held = null; } };
    },
    fail: (at: typeof failAt) => { failAt = at; },
    close: async () => { await closeDb(); await client.close(); await replica.stop(); },
  };
}
