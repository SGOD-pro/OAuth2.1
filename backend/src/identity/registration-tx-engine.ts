import crypto from "node:crypto";
import { createLocalAccountIssuer } from "@better-auth/core/db";
import { getDatabaseFieldIndexName, resolveDatabaseTableIndexes } from "@better-auth/core/db/internal";
import { betterAuth, type Auth, type BetterAuthOptions, type BetterAuthPlugin } from "better-auth";
import type { Db, MongoClient } from "mongodb";
import { authProvider } from "../utils/auth";
import { toApprovedDisplayLabel } from "../utils/security";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { createEngineTransactionBoundary } from "./engine-transaction";
import { runWithVerifiedCreation } from "./registration-context";

const identityTxSchemaPlugin: BetterAuthPlugin = {
  id: "identity-tx-schema",
  schema: {
    registration_intents: {
      disableMigration: true,
      fields: {
        intentId: { type: "string" }, emailLookup: { type: "string" },
        encryptedEmail: { type: "string", required: false }, browserBindingHash: { type: "string" },
        purpose: { type: "string" }, termsVersion: { type: "string" }, status: { type: "string" },
        proofDigest: { type: "string", required: false }, proofExpiresAt: { type: "date", required: false },
        consumedAt: { type: "date", required: false }, committedUserId: { type: "string", required: false },
        committedUsername: { type: "string", required: false }, completeIdempotencyKey: { type: "string", required: false },
        expiresAt: { type: "date" }, updatedAt: { type: "date" },
      },
    },
    identity_lookup: {
      disableMigration: true,
      fields: { kind: { type: "string" }, keyVersion: { type: "number" }, keyedLookup: { type: "string" }, userId: { type: "string" }, createdAt: { type: "date" } },
    },
    identity_profiles: {
      disableMigration: true,
      fields: {
        userId: { type: "string" }, username: { type: "string" }, normalizedUsername: { type: "string" },
        privacyVersion: { type: "string" }, schemaVersion: { type: "number" }, acceptedTermsVersion: { type: "string" },
        keyRef: { type: "string", required: false }, encryptedAttributes: { type: "string", required: false },
        createdAt: { type: "date" }, updatedAt: { type: "date" },
      },
    },
    auth_events: {
      disableMigration: true,
      fields: {
        eventId: { type: "string" }, eventType: { type: "string" }, outcome: { type: "string" },
        userId: { type: "string" }, intentId: { type: "string" }, targetIdentifier: { type: "string" },
        clientId: { type: "string", required: false }, ipAddress: { type: "string", required: false },
        userAgent: { type: "string", required: false }, timestamp: { type: "date" },
      },
    },
    identity_outbox: {
      disableMigration: true,
      fields: { eventId: { type: "string" }, eventType: { type: "string" }, userId: { type: "string" }, intentId: { type: "string" }, status: { type: "string" }, createdAt: { type: "date" } },
    },
  },
};

type CachedTxEngine = {
  db: Db;
  client: MongoClient;
  boundary: ReturnType<typeof createEngineTransactionBoundary>;
  engine: Auth<BetterAuthOptions>;
  ready: Promise<void>;
};

let cached: CachedTxEngine | null = null;

async function prepareIndexes(db: Db, engine: Auth<BetterAuthOptions>): Promise<void> {
  await ensureIdentityCollectionIndexes(db);
  const context = await engine.$context;
  for (const [model, table] of Object.entries(context.tables)) {
    if (table.disableMigrations) continue;
    const name = table.modelName ?? model;
    await db.createCollection(name).catch(() => {});
    for (const [field, def] of Object.entries(table.fields)) {
      if (!def.index && !def.unique) continue;
      const col = def.fieldName ?? field;
      await db.collection(name).createIndex({ [col]: 1 }, { name: getDatabaseFieldIndexName(name, col, def.unique ?? false), unique: def.unique ?? false }).catch(() => {});
    }
    for (const idx of resolveDatabaseTableIndexes({ fields: table.fields, indexes: table.indexes, tableName: name })) {
      await db.collection(name).createIndex(Object.fromEntries(idx.columns.map((f) => [f === "id" ? "_id" : f, 1])), { name: idx.name, unique: idx.unique ?? false }).catch(() => {});
    }
  }
}

export async function getRegistrationTxEngine(db: Db, mongoClient: MongoClient): Promise<CachedTxEngine> {
  if (cached && cached.db === db && cached.client === mongoClient) {
    await cached.ready;
    return cached;
  }
  const boundary = createEngineTransactionBoundary(db, mongoClient);
  const engine = betterAuth({
    ...authProvider.options,
    database: boundary.database,
    plugins: [...(authProvider.options.plugins ?? []), identityTxSchemaPlugin],
  }) as unknown as Auth<BetterAuthOptions>;
  const ready = prepareIndexes(db, engine);
  const entry: CachedTxEngine = { db, client: mongoClient, boundary, engine, ready };
  cached = entry;
  await ready;
  return entry;
}

export class CompletionHttpError extends Error {
  constructor(public readonly httpStatus: number, public readonly error: string, public readonly code: string) {
    super(code);
  }
}

export async function executeCompletionTransaction(
  txEngine: CachedTxEngine,
  params: {
    intentId: string; browserBindingHash: string; proofDigest: string;
    email: string; emailLookup: string; displayUsername: string; normalizedUsername: string; usernameLookup: string;
    acceptedTermsVersion: string; passwordHash: string; idemLookup?: string; clientIp: string | null; userAgent: string | null;
    onInsideAfterUser?: () => void | Promise<void>;
  }
): Promise<string> {
  let createdUserId = "";
  await txEngine.boundary.run(txEngine.engine, async ({ adapter, internalAdapter }) => {
    const txNow = new Date();
    const lockedIntent = await adapter.findOne<any>({
      model: "registration_intents",
      where: [{ field: "intentId", value: params.intentId }, { field: "browserBindingHash", value: params.browserBindingHash }],
    });
    if (!lockedIntent || lockedIntent.status !== "verified" || lockedIntent.proofDigest !== params.proofDigest) {
      throw new CompletionHttpError(409, "conflict", "ERR_PROOF_CONSUMED");
    }
    if (txNow.getTime() >= new Date(lockedIntent.expiresAt).getTime() || txNow.getTime() >= new Date(lockedIntent.proofExpiresAt).getTime()) {
      throw new CompletionHttpError(400, "expired", "ERR_PROOF_EXPIRED");
    }
    if (await adapter.findOne<any>({ model: "user", where: [{ field: "email", value: params.email }] })) {
      throw new CompletionHttpError(409, "conflict", "ERR_EMAIL_ALREADY_REGISTERED");
    }
    if (await adapter.findOne<any>({ model: "identity_lookup", where: [{ field: "kind", value: "username" }, { field: "keyVersion", value: 1 }, { field: "keyedLookup", value: params.usernameLookup }] })) {
      throw new CompletionHttpError(409, "conflict", "ERR_USERNAME_TAKEN");
    }

    const createdUser = await runWithVerifiedCreation(() =>
      internalAdapter.createUser({
        email: params.email, emailVerified: true, name: params.displayUsername,
        username: params.displayUsername, usernameLookup: params.usernameLookup, emailLookup: params.emailLookup,
        acceptedTermsVersion: params.acceptedTermsVersion, role: "user", scopedClientId: null, mustChangePassword: false, tokenVersion: 1,
      } as any, { method: "verified-registration" })
    );
    if (!createdUser?.id) throw new Error("Identity creation returned null");
    createdUserId = createdUser.id;
    await params.onInsideAfterUser?.();

    const linked = await internalAdapter.linkAccount({
      userId: createdUserId, accountId: createdUserId, providerId: "credential",
      issuer: createLocalAccountIssuer("credential"), password: params.passwordHash,
    });
    if (!linked) throw new Error("Credential account linking failed");

    const intentUpdate: Record<string, any> = {
      status: "consumed", proofDigest: null, encryptedEmail: null,
      consumedAt: txNow, committedUserId: createdUserId, committedUsername: params.displayUsername, updatedAt: txNow,
    };
    if (params.idemLookup) intentUpdate.completeIdempotencyKey = params.idemLookup;
    const consumed = await adapter.update<any>({
      model: "registration_intents",
      where: [{ field: "intentId", value: params.intentId }, { field: "browserBindingHash", value: params.browserBindingHash }, { field: "status", value: "verified" }],
      update: intentUpdate,
    });
    if (!consumed) throw new CompletionHttpError(409, "conflict", "ERR_PROOF_CONSUMED");

    await adapter.create({ model: "identity_lookup", data: { kind: "email", keyVersion: 1, keyedLookup: params.emailLookup, userId: createdUserId, createdAt: txNow } });
    await adapter.create({ model: "identity_lookup", data: { kind: "username", keyVersion: 1, keyedLookup: params.usernameLookup, userId: createdUserId, createdAt: txNow } });
    await adapter.create({
      model: "identity_profiles",
      data: { userId: createdUserId, username: params.displayUsername, normalizedUsername: params.normalizedUsername, privacyVersion: "v1", schemaVersion: 1, acceptedTermsVersion: params.acceptedTermsVersion, keyRef: null, encryptedAttributes: null, createdAt: txNow, updatedAt: txNow },
    });
    await adapter.create({
      model: "auth_events",
      data: { eventId: crypto.randomUUID(), eventType: "registration_complete", outcome: "success", userId: createdUserId, intentId: params.intentId, targetIdentifier: toApprovedDisplayLabel(params.email, params.displayUsername), clientId: null, ipAddress: params.clientIp, userAgent: params.userAgent, timestamp: txNow },
    });
    await adapter.create({
      model: "identity_outbox",
      data: { eventId: crypto.randomUUID(), eventType: "identity.account_created", userId: createdUserId, intentId: params.intentId, status: "pending", createdAt: txNow },
    });
  });
  return createdUserId;
}
