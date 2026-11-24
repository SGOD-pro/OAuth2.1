import crypto from "crypto";
import { normalizeOAuthClientFields } from "../utils/security";
import { extractClientTimestamps, stripSensitiveClientFields } from "./admin-client-policy-helper";

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function deleteClientCredentialsAndCodes(
  database: any,
  canonicalId: string,
  session?: any
): Promise<void> {
  const opt = session ? { session } : {};
  const existingCodes = await database
    .collection("oauthAuthorizationCode")
    .find({ clientId: canonicalId }, { projection: { code: 1 }, ...opt })
    .toArray();

  const verificationIdentifiers: string[] = [];
  for (const row of existingCodes) {
    if (row?.code && typeof row.code === "string") {
      verificationIdentifiers.push(row.code);
      verificationIdentifiers.push(crypto.createHash("sha256").update(row.code).digest("base64url"));
    }
  }

  const escapedClientId = escapeRegex(canonicalId);
  const verificationFilter: Record<string, any> = {
    $or: [
      ...(verificationIdentifiers.length > 0 ? [{ identifier: { $in: verificationIdentifiers } }] : []),
      {
        value: new RegExp(
          `("type":"authorization_code"[\\s\\S]*"client_id":"${escapedClientId}")|("client_id":"${escapedClientId}"[\\s\\S]*"type":"authorization_code")`
        ),
      },
    ],
  };

  await Promise.all([
    database.collection("oauthAccessToken").deleteMany({ clientId: canonicalId }, opt),
    database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalId }, opt),
    database.collection("oauthAuthorizationCode").deleteMany({ clientId: canonicalId }, opt),
    database.collection("oauth_token_families").deleteMany({ clientId: canonicalId }, opt),
    database.collection("verification").deleteMany(verificationFilter, opt),
  ]);
}

function buildRollbackSnapshot(oldClient: any): { $set: Record<string, any>; $unset?: Record<string, string> } {
  const restoreSet: Record<string, any> = {};
  const restoreUnset: Record<string, string> = {};
  const trackedKeys = [
    "clientType",
    "accessPolicy",
    "tokenEndpointAuthMethod",
    "token_endpoint_auth_method",
    "clientSecret",
    "client_secret",
    "isPublic",
    "is_public",
    "isDev",
    "is_dev",
    "policyVersion",
    "credentialVersion",
    "clientSecretRevokedAt",
    "name",
    "redirectUris",
    "redirect_uris",
    "allowedOrigins",
    "allowed_origins",
    "updatedAt",
  ];
  for (const key of trackedKeys) {
    if (oldClient[key] !== undefined) {
      restoreSet[key] = oldClient[key];
    } else {
      restoreUnset[key] = "";
    }
  }
  return Object.keys(restoreUnset).length > 0 ? { $set: restoreSet, $unset: restoreUnset } : { $set: restoreSet };
}

export interface ClientPatchTransitionInput {
  database: any;
  id: string;
  canonicalId: string;
  oldClient: any;
  dbUpdates: Record<string, any>;
  dbUnsets: Record<string, string>;
  revokeCredentials: boolean;
}

/**
 * Executes an oauthClient policy/credential update atomically with dependent token, code,
 * and family revocation using a MongoDB multi-document transaction when available, falling back
 * to snapshot restoration if transactions are unavailable on a test mock database.
 */
export async function executeClientPatchTransition(input: ClientPatchTransitionInput): Promise<any> {
  const { database, id, canonicalId, oldClient, dbUpdates, dbUnsets, revokeCredentials } = input;
  const filter = { $or: [{ clientId: id }, { client_id: id }, { id }] };
  const mongoUpdate: Record<string, any> = { $set: dbUpdates };
  if (Object.keys(dbUnsets).length > 0) mongoUpdate.$unset = dbUnsets;

  const mongoClient = database?.client;
  if (mongoClient && typeof mongoClient.startSession === "function") {
    const session = mongoClient.startSession();
    try {
      await session.withTransaction(async () => {
        await database.collection("oauthClient").updateOne(filter, mongoUpdate, { session });
        if (revokeCredentials) {
          await deleteClientCredentialsAndCodes(database, canonicalId, session);
        }
      });
    } finally {
      await session.endSession().catch(() => {});
    }
    return database.collection("oauthClient").findOne(filter);
  }

  await database.collection("oauthClient").updateOne(filter, mongoUpdate);
  if (revokeCredentials) {
    try {
      await deleteClientCredentialsAndCodes(database, canonicalId);
    } catch (cleanupErr) {
      const rollback = buildRollbackSnapshot(oldClient);
      await database.collection("oauthClient").updateOne(filter, rollback).catch(() => {});
      throw cleanupErr;
    }
  }
  return database.collection("oauthClient").findOne(filter);
}

/**
 * Formats a normalized, secret-stripped administrative client response.
 */
export function formatAdminClientResponse(
  rawDoc: any,
  canonicalId: string,
  fallbackRedirectUris?: string[],
  fallbackAllowedOrigins?: string[]
): Record<string, any> {
  const { createdDate, updatedDate } = extractClientTimestamps(rawDoc);
  const normalized = normalizeOAuthClientFields({
    ...rawDoc,
    id: canonicalId,
    clientId: canonicalId,
    ...(fallbackRedirectUris ? { redirectUris: rawDoc?.redirectUris || fallbackRedirectUris } : {}),
    ...(fallbackAllowedOrigins ? { allowedOrigins: rawDoc?.allowedOrigins || fallbackAllowedOrigins } : {}),
  });
  return stripSensitiveClientFields({
    ...normalized,
    client_id: normalized.clientId,
    createdAt: createdDate,
    created_at: createdDate,
    updatedAt: updatedDate,
    updated_at: updatedDate,
  });
}
