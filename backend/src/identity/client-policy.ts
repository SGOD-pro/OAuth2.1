/**
 * OAuth V2 Client Policy Classifier and Audit Scanner (Slice P1a)
 *
 * Resolves clientType, accessPolicy, and isDev independently.
 * Enforces legacy mapping rules, ambiguity reason codes, and zero write audit.
 */

export type ClientType = "public" | "confidential";
export type AccessPolicy = "open" | "private";

export type ClientClassification =
  | "MIGRATED"
  | "COMPATIBLE_OPEN_PUBLIC"
  | "COMPATIBLE_PRIVATE_CONFIDENTIAL"
  | "COMPATIBLE_OPEN_CONFIDENTIAL"
  | "COMPATIBLE_PRIVATE_PUBLIC"
  | "AMBIGUOUS";

export type AmbiguityReasonCode =
  | "MISSING_REDIRECT_URIS"
  | "INVALID_REDIRECT_URI"
  | "CONFLICTING_ACCESS_FLAGS"
  | "CONFLICTING_DEV_FLAGS"
  | "CONFLICTING_ID_FIELDS"
  | "CONFLICTING_METADATA"
  | "UNCERTAIN_AUTHENTICATION_TYPE";

export interface ResolvedClientPolicy {
  clientType: ClientType;
  accessPolicy: AccessPolicy;
  isDev: boolean;
  classification: ClientClassification;
  isExplicit: boolean;
  isAmbiguous: boolean;
  reasonCodes: AmbiguityReasonCode[];
  reasons: string[];
}

export interface ClientAuditRecord {
  id: string;
  clientId: string;
  name: string;
  classification: ClientClassification;
  resolvedClientType?: ClientType;
  resolvedAccessPolicy?: AccessPolicy;
  isDev: boolean;
  isAmbiguous: boolean;
  reasonCodes: AmbiguityReasonCode[];
  reasons: string[];
}

export interface ClientAuditSummary {
  totalClients: number;
  migratedCount: number;
  compatibleOpenPublicCount: number;
  compatiblePrivateConfidentialCount: number;
  compatibleOpenConfidentialCount: number;
  compatiblePrivatePublicCount: number;
  ambiguousCount: number;
  clients: ClientAuditRecord[];
  timestamp: string;
}

function isLoopbackHostname(hostname: string): boolean {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return clean === "localhost" || clean === "127.0.0.1" || clean === "::1" || clean.endsWith(".localhost");
}

function validateRedirectUriSyntax(uri: string, isDev: boolean, isNative = false): string | null {
  if (!uri || typeof uri !== "string" || uri.trim() === "") return "Redirect URI must be a non-empty string";
  if (uri.includes("#")) return `URI contains fragment component: ${uri}`;
  if (uri.includes("*")) return `URI contains wildcard component: ${uri}`;

  let parsed: URL;
  try {
    parsed = new URL(uri.trim());
  } catch {
    return `Malformed URL syntax: ${uri}`;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return `Unsupported scheme '${parsed.protocol}' in URI: ${uri}`;
  }
  if (parsed.username || parsed.password) return `URI contains userinfo credentials: ${uri}`;
  if (!parsed.hostname) return `URI missing hostname: ${uri}`;

  if (parsed.protocol === "http:") {
    const isLoopback = isLoopbackHostname(parsed.hostname);
    if ((!isDev && !isNative) || !isLoopback) {
      return `Insecure HTTP redirect URI forbidden for non-loopback or production client: ${uri}`;
    }
  }

  return null;
}

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
    reasons.push(`Conflicting clientId ('${rawClientId}') and client_id ('${rawSnakeClientId}')`);
  }

  if (
    typeof clientDoc.isPublic === "boolean" &&
    typeof clientDoc.is_public === "boolean" &&
    clientDoc.isPublic !== clientDoc.is_public
  ) {
    reasonCodes.push("CONFLICTING_ACCESS_FLAGS");
    reasons.push(`Conflicting isPublic (${clientDoc.isPublic}) and is_public (${clientDoc.is_public})`);
  }

  if (
    typeof clientDoc.isDev === "boolean" &&
    typeof clientDoc.is_dev === "boolean" &&
    clientDoc.isDev !== clientDoc.is_dev
  ) {
    reasonCodes.push("CONFLICTING_DEV_FLAGS");
    reasons.push(`Conflicting isDev (${clientDoc.isDev}) and is_dev (${clientDoc.is_dev})`);
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

  if (appType === "native" && hasSecret) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push("Native application type registered with a client secret");
  }

  const explicitType = clientDoc.clientType;
  const explicitPolicy = clientDoc.accessPolicy;
  const isTypeValid = explicitType === "public" || explicitType === "confidential";
  const isPolicyValid = explicitPolicy === "open" || explicitPolicy === "private";

  if (explicitType !== undefined && !isTypeValid) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push(`Invalid clientType value: '${explicitType}'`);
  }
  if (explicitPolicy !== undefined && !isPolicyValid) {
    reasonCodes.push("CONFLICTING_METADATA");
    reasons.push(`Invalid accessPolicy value: '${explicitPolicy}'`);
  }

  if (isTypeValid && isPolicyValid) {
    if (explicitType === "public" && hasSecret) {
      reasonCodes.push("CONFLICTING_METADATA");
      reasons.push("Explicit public client cannot possess a client secret");
    }
    if (explicitType === "confidential" && !hasSecret) {
      reasonCodes.push("CONFLICTING_METADATA");
      reasons.push("Explicit confidential client must possess a registered client secret");
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
  } else if (hasSecret || authMethod === "client_secret_basic" || authMethod === "client_secret_post") {
    derivedClientType = "confidential";
  } else {
    derivedClientType = "public";
  }

  const legacyIsPublic = clientDoc.isPublic !== false && clientDoc.is_public !== false;
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

  let classification: ClientClassification;
  if (derivedClientType === "public" && derivedAccessPolicy === "open") {
    classification = "COMPATIBLE_OPEN_PUBLIC";
  } else if (derivedClientType === "confidential" && derivedAccessPolicy === "private") {
    classification = "COMPATIBLE_PRIVATE_CONFIDENTIAL";
  } else if (derivedClientType === "confidential" && derivedAccessPolicy === "open") {
    classification = "COMPATIBLE_OPEN_CONFIDENTIAL";
  } else {
    classification = "COMPATIBLE_PRIVATE_PUBLIC";
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
  const rawDocs: any[] = typeof cursor.toArray === "function" ? await cursor.toArray() : await cursor;

  const clients: ClientAuditRecord[] = [];
  const counts = {
    MIGRATED: 0,
    COMPATIBLE_OPEN_PUBLIC: 0,
    COMPATIBLE_PRIVATE_CONFIDENTIAL: 0,
    COMPATIBLE_OPEN_CONFIDENTIAL: 0,
    COMPATIBLE_PRIVATE_PUBLIC: 0,
    AMBIGUOUS: 0,
  };

  for (const doc of rawDocs) {
    const resolved = resolveClientPolicy(doc);
    const id = String(doc.id || doc.clientId || doc.client_id || (doc._id ? String(doc._id) : ""));
    const clientId = String(doc.clientId || doc.client_id || doc.id || id);
    const name = String(doc.name || doc.client_name || doc.clientName || "Unnamed Client").trim();

    counts[resolved.classification]++;

    clients.push({
      id,
      clientId,
      name,
      classification: resolved.classification,
      resolvedClientType: resolved.clientType,
      resolvedAccessPolicy: resolved.accessPolicy,
      isDev: resolved.isDev,
      isAmbiguous: resolved.isAmbiguous,
      reasonCodes: resolved.reasonCodes,
      reasons: resolved.reasons,
    });
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
