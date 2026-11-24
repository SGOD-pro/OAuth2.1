/**
 * OAuth V2 Client Policy Classifier and Audit Scanner (Slice P1a)
 *
 * Resolves clientType, accessPolicy, and isDev independently.
 * Enforces legacy mapping rules, ambiguity reason codes, and zero write audit.
 */

import type {
  ClientType,
  AccessPolicy,
  ClientClassification,
  AmbiguityReasonCode,
  ResolvedClientPolicy,
  ClientAuditRecord,
  ClientAuditSummary,
} from "./client-policy-types";
import { validateRedirectUriSyntax } from "./client-policy-types";

export * from "./client-policy-types";

export function resolveClientPolicy(clientDoc: Record<string, any>): ResolvedClientPolicy {
  const reasonCodes: AmbiguityReasonCode[] = [];
  const reasons: string[] = [];

  const rawClientId = clientDoc.clientId;
  const rawSnakeClientId = clientDoc.client_id;
  if (
    typeof rawClientId === "string" &&
    typeof rawSnakeClientId === "string" &&
    rawClientId.trim() !== "" &&
    rawSnakeClientId.trim() !== "" &&
    rawClientId.trim() !== rawSnakeClientId.trim()
  ) {
    reasonCodes.push("CONFLICTING_ID_FIELDS");
    reasons.push("Conflicting clientId and client_id identifier fields");
  }

  const hasCamelDev = clientDoc.isDev !== undefined;
  const hasSnakeDev = clientDoc.is_dev !== undefined;
  if (hasCamelDev && typeof clientDoc.isDev !== "boolean") {
    reasonCodes.push("MALFORMED_DEV_FLAGS");
    reasons.push("isDev flag must be a boolean");
  }
  if (hasSnakeDev && typeof clientDoc.is_dev !== "boolean") {
    reasonCodes.push("MALFORMED_DEV_FLAGS");
    reasons.push("is_dev flag must be a boolean");
  }
  if (
    typeof clientDoc.isDev === "boolean" &&
    typeof clientDoc.is_dev === "boolean" &&
    clientDoc.isDev !== clientDoc.is_dev
  ) {
    reasonCodes.push("CONFLICTING_DEV_FLAGS");
    reasons.push("Conflicting isDev and is_dev boolean flags");
  }

  const hasCamelPublic = clientDoc.isPublic !== undefined;
  const hasSnakePublic = clientDoc.is_public !== undefined;
  if (hasCamelPublic && typeof clientDoc.isPublic !== "boolean") {
    reasonCodes.push("MALFORMED_ACCESS_METADATA");
    reasons.push("isPublic flag must be a boolean");
  }
  if (hasSnakePublic && typeof clientDoc.is_public !== "boolean") {
    reasonCodes.push("MALFORMED_ACCESS_METADATA");
    reasons.push("is_public flag must be a boolean");
  }
  if (
    typeof clientDoc.isPublic === "boolean" &&
    typeof clientDoc.is_public === "boolean" &&
    clientDoc.isPublic !== clientDoc.is_public
  ) {
    reasonCodes.push("CONFLICTING_ACCESS_FLAGS");
    reasons.push("Conflicting isPublic and is_public access flags");
  }

  const explicitType = clientDoc.clientType;
  const explicitPolicy = clientDoc.accessPolicy;
  const hasExplicitType = explicitType !== undefined;
  const hasExplicitPolicy = explicitPolicy !== undefined;

  const isTypeValid = explicitType === "public" || explicitType === "confidential";
  const isPolicyValid = explicitPolicy === "open" || explicitPolicy === "private";

  if (hasExplicitType && !isTypeValid) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push("Invalid explicit clientType value");
  }
  if (hasExplicitPolicy && !isPolicyValid) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push("Invalid explicit accessPolicy value");
  }

  if (hasExplicitType !== hasExplicitPolicy) {
    reasonCodes.push("PARTIAL_EXPLICIT_POLICY");
    reasons.push("Partial explicit policy: clientType and accessPolicy must both be defined");
  }

  if (!hasExplicitPolicy && !hasCamelPublic && !hasSnakePublic) {
    reasonCodes.push("MISSING_ACCESS_METADATA");
    reasons.push("Client is missing both explicit accessPolicy and legacy access flags");
  }

  const isDev = Boolean(clientDoc.isDev ?? clientDoc.is_dev);
  const appType = clientDoc.application_type || clientDoc.applicationType;
  const isNative = appType === "native";
  const rawUris = clientDoc.redirectUris || clientDoc.redirect_uris;
  const redirectUris = Array.isArray(rawUris) ? rawUris : [];

  if (redirectUris.length === 0) {
    reasonCodes.push("MISSING_REDIRECT_URIS");
    reasons.push("Client has no registered redirect URIs");
  } else {
    for (const uri of redirectUris) {
      const err = validateRedirectUriSyntax(uri, isDev, isNative);
      if (err) {
        reasonCodes.push("INVALID_REDIRECT_URI");
        reasons.push(err);
      }
    }
  }

  const rawSecret = clientDoc.clientSecret ?? clientDoc.client_secret;
  const hasSecret = typeof rawSecret === "string" && rawSecret.trim().length > 0;
  const authMethod = clientDoc.token_endpoint_auth_method || clientDoc.metadata?.token_endpoint_auth_method;

  const supportedAuthMethods = ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"];
  if (authMethod !== undefined && !supportedAuthMethods.includes(authMethod)) {
    reasonCodes.push("CONFLICTING_AUTH_METHOD");
    reasons.push("Unsupported token_endpoint_auth_method");
  }
  if (authMethod === "none" && hasSecret) {
    reasonCodes.push("CONFLICTING_AUTH_METHOD");
    reasons.push("token_endpoint_auth_method is none but a client secret is registered");
  }
  if ((authMethod === "client_secret_basic" || authMethod === "client_secret_post") && !hasSecret) {
    reasonCodes.push("CONFLICTING_AUTH_METHOD");
    reasons.push("token_endpoint_auth_method requires a secret but none is registered");
  }

  const rawJwks = clientDoc.jwks ?? clientDoc.metadata?.jwks;
  const rawJwksUri = clientDoc.jwks_uri ?? clientDoc.jwksUri ?? clientDoc.metadata?.jwks_uri ?? clientDoc.metadata?.jwksUri;
  const hasJwks = Boolean(
    rawJwks &&
      ((Array.isArray(rawJwks?.keys) && rawJwks.keys.length > 0) ||
        (Array.isArray(rawJwks) && rawJwks.length > 0) ||
        (typeof rawJwks === "object" && Object.keys(rawJwks).length > 0))
  );
  const hasJwksUri = typeof rawJwksUri === "string" && rawJwksUri.trim().length > 0;

  if (authMethod === "private_key_jwt") {
    if (hasSecret) {
      reasonCodes.push("CONFLICTING_AUTH_METHOD");
      reasons.push("private_key_jwt client authentication cannot possess a client secret");
    }
    if (!hasJwks && !hasJwksUri) {
      reasonCodes.push("CONFLICTING_AUTH_METHOD");
      reasons.push("private_key_jwt client authentication requires jwks or jwks_uri metadata");
    }
  }

  if (appType === "native" && !isDev && hasSecret) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push("Native application type registered with a client secret");
  }

  if (isTypeValid && isPolicyValid) {
    if (explicitType === "public" && (hasSecret || (authMethod && authMethod !== "none"))) {
      reasonCodes.push("CONFLICTING_METADATA");
      reasons.push("Explicit public client cannot possess a client secret or confidential auth method");
    }
    if (explicitType === "confidential" && !hasSecret && authMethod !== "private_key_jwt") {
      reasonCodes.push("CONFLICTING_METADATA");
      reasons.push("Explicit confidential client must possess a registered client secret or key assertion metadata");
    }
    if (explicitType === "confidential" && authMethod === "none") {
      reasonCodes.push("CONFLICTING_METADATA");
      reasons.push("Explicit confidential client cannot use none auth method");
    }

    if (reasonCodes.length === 0) {
      return {
        clientType: explicitType,
        accessPolicy: explicitPolicy,
        isDev,
        classification: "MIGRATED",
        isExplicit: true,
        isAmbiguous: false,
        reasonCodes: [],
        reasons: [],
      };
    }
  }

  let derivedClientType: ClientType = "public";
  if (authMethod === "none") {
    derivedClientType = "public";
  } else if (
    hasSecret ||
    authMethod === "client_secret_basic" ||
    authMethod === "client_secret_post" ||
    authMethod === "private_key_jwt"
  ) {
    derivedClientType = "confidential";
  } else {
    derivedClientType = "public";
  }

  const legacyIsPublic = clientDoc.isPublic === true || clientDoc.is_public === true;
  const derivedAccessPolicy: AccessPolicy = legacyIsPublic ? "open" : "private";

  if (reasonCodes.length > 0) {
    return {
      clientType: derivedClientType,
      accessPolicy: "private", // Fail closed
      isDev,
      classification: "AMBIGUOUS",
      isExplicit: false,
      isAmbiguous: true,
      reasonCodes,
      reasons,
    };
  }

  let classification: ClientClassification = "COMPATIBLE_PRIVATE_PUBLIC";
  if (derivedClientType === "public" && derivedAccessPolicy === "open") {
    classification = "COMPATIBLE_OPEN_PUBLIC";
  } else if (derivedClientType === "confidential" && derivedAccessPolicy === "private") {
    classification = "COMPATIBLE_PRIVATE_CONFIDENTIAL";
  } else if (derivedClientType === "confidential" && derivedAccessPolicy === "open") {
    classification = "COMPATIBLE_OPEN_CONFIDENTIAL";
  }

  return {
    clientType: derivedClientType,
    accessPolicy: derivedAccessPolicy,
    isDev,
    classification,
    isExplicit: false,
    isAmbiguous: false,
    reasonCodes: [],
    reasons: [],
  };
}

export async function auditClientPolicies(db: any): Promise<ClientAuditSummary> {
  const cursor = db.collection("oauthClient").find({});
  const clients: ClientAuditRecord[] = [];
  const counts = {
    MIGRATED: 0,
    COMPATIBLE_OPEN_PUBLIC: 0,
    COMPATIBLE_PRIVATE_CONFIDENTIAL: 0,
    COMPATIBLE_OPEN_CONFIDENTIAL: 0,
    COMPATIBLE_PRIVATE_PUBLIC: 0,
    AMBIGUOUS: 0,
  };

  const processDoc = (doc: any) => {
    const res = resolveClientPolicy(doc);
    const id = String(doc.id || doc.clientId || doc.client_id || (doc._id ? String(doc._id) : ""));
    const clientId = String(doc.clientId || doc.client_id || doc.id || id);
    const name = String(doc.name || doc.client_name || doc.clientName || "Unnamed Client").trim();
    counts[res.classification]++;
    clients.push({
      id,
      clientId,
      name,
      classification: res.classification,
      resolvedClientType: res.clientType,
      resolvedAccessPolicy: res.accessPolicy,
      isDev: res.isDev,
      isAmbiguous: res.isAmbiguous,
      reasonCodes: res.reasonCodes,
      reasons: res.reasons,
    });
  };

  if (typeof (cursor as any)[Symbol.asyncIterator] === "function") {
    for await (const doc of cursor as any) processDoc(doc);
  } else {
    const rawDocs: any[] = typeof cursor.toArray === "function" ? await cursor.toArray() : await cursor;
    for (const doc of rawDocs) processDoc(doc);
  }

  return {
    totalClients: clients.length,
    migratedCount: counts.MIGRATED,
    compatibleOpenPublicCount: counts.COMPATIBLE_OPEN_PUBLIC,
    compatiblePrivateConfidentialCount: counts.COMPATIBLE_PRIVATE_CONFIDENTIAL,
    compatibleOpenConfidentialCount: counts.COMPATIBLE_OPEN_CONFIDENTIAL,
    compatiblePrivatePublicCount: counts.COMPATIBLE_PRIVATE_PUBLIC,
    ambiguousCount: counts.AMBIGUOUS,
    clients,
    timestamp: new Date().toISOString(),
  };
}
