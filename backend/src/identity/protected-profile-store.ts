import type { AccountKeyProvider } from "./account-key-provider";
import { parseScopeSet, resolveOwnerPrivacyPreferences } from "./claim-policy";
import { openProtectedField, ProtectedFieldError, sealProtectedField, type ProtectedEnvelope } from "./protected-envelope";

export interface ProtectedProfileDoc {
  userId: string;
  schemaVersion: number;
  keyVersion: number;
  nameEnvelope: ProtectedEnvelope;
  emailEnvelope: ProtectedEnvelope;
  updatedAt: string;
}

export interface ProtectedProfileCollection {
  findByUserId(userId: string, options?: { session?: unknown }): Promise<ProtectedProfileDoc | null>;
  upsertByUserId(doc: ProtectedProfileDoc, options?: { session?: unknown }): Promise<void>;
}

export class InMemoryProfileCollection implements ProtectedProfileCollection {
  private readonly docs = new Map<string, ProtectedProfileDoc>();

  async findByUserId(userId: string, _options?: { session?: unknown }): Promise<ProtectedProfileDoc | null> {
    const doc = this.docs.get(userId);
    return doc ? structuredClone(doc) : null;
  }

  async upsertByUserId(doc: ProtectedProfileDoc, _options?: { session?: unknown }): Promise<void> {
    this.docs.set(doc.userId, structuredClone(doc));
  }
}

export class MongoProfileCollection implements ProtectedProfileCollection {
  constructor(private readonly database: any) {}

  async findByUserId(userId: string, options?: { session?: unknown }): Promise<ProtectedProfileDoc | null> {
    const doc = await this.database
      .collection("identity_profiles")
      .findOne({ userId }, options?.session ? { session: options.session } : undefined);
    return doc && doc.nameEnvelope && doc.emailEnvelope ? (doc as ProtectedProfileDoc) : null;
  }

  async upsertByUserId(doc: ProtectedProfileDoc, options?: { session?: unknown }): Promise<void> {
    await this.database.collection("identity_profiles").updateOne(
      { userId: doc.userId },
      { $set: doc },
      { upsert: true, ...(options?.session ? { session: options.session } : {}) }
    );
  }
}

/**
 * Independently seals and updates only the provided profile fields (name and/or email)
 * so concurrent name and email updates never overwrite each other.
 */
export async function writeProtectedProfileFields(params: {
  store: ProtectedProfileCollection;
  provider: AccountKeyProvider;
  accountId: string;
  name?: string;
  email?: string;
  fallbackName?: string;
  fallbackEmail?: string;
  session?: unknown;
}): Promise<ProtectedProfileDoc> {
  const existing = await params.store.findByUserId(params.accountId, { session: params.session });
  const nameToSeal = params.name ?? (!existing ? (params.fallbackName ?? "") : undefined);
  const emailToSeal = params.email ?? (!existing ? (params.fallbackEmail ?? "") : undefined);

  const [nameEnvelope, emailEnvelope] = await Promise.all([
    nameToSeal !== undefined
      ? sealProtectedField({
          provider: params.provider,
          accountId: params.accountId,
          collection: "identity_profiles",
          recordId: params.accountId,
          fieldPurpose: "profile.name",
          plaintext: nameToSeal,
        })
      : Promise.resolve(existing!.nameEnvelope),
    emailToSeal !== undefined
      ? sealProtectedField({
          provider: params.provider,
          accountId: params.accountId,
          collection: "identity_profiles",
          recordId: params.accountId,
          fieldPurpose: "profile.email",
          plaintext: emailToSeal,
        })
      : Promise.resolve(existing!.emailEnvelope),
  ]);

  const doc: ProtectedProfileDoc = {
    userId: params.accountId,
    schemaVersion: 1,
    keyVersion: 1,
    nameEnvelope,
    emailEnvelope,
    updatedAt: new Date().toISOString(),
  };
  await params.store.upsertByUserId(doc, { session: params.session });
  return doc;
}

/**
 * Seals both name and email before writing so any key-provider failure leaves zero partial writes.
 */
export async function writeProtectedProfile(params: {
  store: ProtectedProfileCollection;
  provider: AccountKeyProvider;
  accountId: string;
  name: string;
  email: string;
}): Promise<ProtectedProfileDoc> {
  const [nameEnvelope, emailEnvelope] = await Promise.all([
    sealProtectedField({
      provider: params.provider,
      accountId: params.accountId,
      collection: "identity_profiles",
      recordId: params.accountId,
      fieldPurpose: "profile.name",
      plaintext: params.name,
    }),
    sealProtectedField({
      provider: params.provider,
      accountId: params.accountId,
      collection: "identity_profiles",
      recordId: params.accountId,
      fieldPurpose: "profile.email",
      plaintext: params.email,
    }),
  ]);

  const doc: ProtectedProfileDoc = {
    userId: params.accountId,
    schemaVersion: 1,
    keyVersion: 1,
    nameEnvelope,
    emailEnvelope,
    updatedAt: new Date().toISOString(),
  };
  await params.store.upsertByUserId(doc);
  return doc;
}

/**
 * Reads protected profile fields, failing closed on any decrypt/provider error without plaintext fallback.
 * Legacy plaintext fallback applies only when no protected record exists and migrationMode is "compat".
 */
export async function readProtectedProfile(params: {
  store: ProtectedProfileCollection;
  provider: AccountKeyProvider;
  accountId: string;
  migrationMode: "compat" | "strict";
  legacyUserDoc?: { name?: unknown; email?: unknown } | null;
  counters?: { plaintextFallbackCount: number };
  fields?: Array<"name" | "email">;
}): Promise<{ name: string; email: string; source: "protected" | "legacy_plaintext" }> {
  const fields = new Set(params.fields ?? ["name", "email"]);
  if (fields.size === 0) {
    return { name: "", email: "", source: "protected" };
  }
  const doc = await params.store.findByUserId(params.accountId);
  if (doc) {
    const [name, email] = await Promise.all([
      fields.has("name")
        ? openProtectedField({
            provider: params.provider,
            accountId: params.accountId,
            collection: "identity_profiles",
            recordId: params.accountId,
            fieldPurpose: "profile.name",
            envelope: doc.nameEnvelope,
          })
        : Promise.resolve(""),
      fields.has("email")
        ? openProtectedField({
            provider: params.provider,
            accountId: params.accountId,
            collection: "identity_profiles",
            recordId: params.accountId,
            fieldPurpose: "profile.email",
            envelope: doc.emailEnvelope,
          })
        : Promise.resolve(""),
    ]);
    return { name, email, source: "protected" };
  }

  if (params.migrationMode === "compat" && params.legacyUserDoc) {
    if (params.counters) {
      params.counters.plaintextFallbackCount += 1;
    }
    return {
      name: fields.has("name") ? String(params.legacyUserDoc.name ?? "") : "",
      email: fields.has("email") ? String(params.legacyUserDoc.email ?? "") : "",
      source: "legacy_plaintext",
    };
  }

  throw new ProtectedFieldError("profile_not_found", "Protected profile record not found");
}

/**
 * Resolves only the protected profile fields authorized by granted OAuth scope and owner privacy settings.
 */
export async function resolveAuthorizedProtectedUserInfoClaims(params: {
  store: ProtectedProfileCollection;
  provider: AccountKeyProvider;
  accountId: string;
  migrationMode: "compat" | "strict";
  userDoc: any;
  scopes: string | string[];
  claims: Record<string, any>;
}): Promise<Record<string, any>> {
  const scopeSet = parseScopeSet(params.scopes);
  const prefs = resolveOwnerPrivacyPreferences(params.userDoc);
  const needEmail = scopeSet.has("email") && prefs.shareEmail;
  const needProfile = scopeSet.has("profile") && prefs.shareProfile;
  const neededFields: Array<"name" | "email"> = [
    ...(needProfile ? (["name"] as const) : []),
    ...(needEmail ? (["email"] as const) : []),
  ];
  if (neededFields.length === 0) {
    return params.claims;
  }
  const resolved = await readProtectedProfile({
    store: params.store,
    provider: params.provider,
    accountId: params.accountId,
    migrationMode: params.migrationMode,
    legacyUserDoc: params.userDoc,
    fields: neededFields,
  });
  const next = { ...params.claims };
  if (needEmail) {
    next.email = resolved.email;
    next.email_verified = params.userDoc?.emailVerified ?? false;
  }
  if (needProfile) {
    next.name = resolved.name;
  }
  return next;
}

/**
 * Resolves protected name (and email only when needed for masked displayLabel fallback)
 * for admin list projections without decrypting unscoped or hidden fields.
 */
export async function resolveProtectedAdminDisplayFields(params: {
  userDoc: any;
  store?: ProtectedProfileCollection;
  provider?: AccountKeyProvider;
  migrationMode?: "compat" | "strict";
}): Promise<{ name: string; email: string }> {
  const { userDoc, store, provider, migrationMode = "compat" } = params;
  if (!userDoc) return { name: "", email: "" };
  if (!store || !provider) {
    return { name: String(userDoc.name ?? ""), email: String(userDoc.email ?? "") };
  }
  const accountId = String(userDoc._id || userDoc.id || "");
  const nameRes = await readProtectedProfile({
    store,
    provider,
    accountId,
    migrationMode,
    legacyUserDoc: userDoc,
    fields: ["name"],
  });
  const trimmedName = nameRes.name.trim();
  const needsEmailFallback = !trimmedName || trimmedName.toLowerCase() === "user" || trimmedName.includes("@");
  if (!needsEmailFallback) {
    return { name: nameRes.name, email: "" };
  }
  const emailRes = await readProtectedProfile({
    store,
    provider,
    accountId,
    migrationMode,
    legacyUserDoc: userDoc,
    fields: ["email"],
  });
  return { name: nameRes.name, email: emailRes.email };
}
