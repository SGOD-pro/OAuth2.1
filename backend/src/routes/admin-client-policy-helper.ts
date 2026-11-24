import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import type { ClientType, AccessPolicy } from "../identity/client-policy-types";

export const V2_POLICY_FIELDS = [
  "clientType",
  "accessPolicy",
  "tokenEndpointAuthMethod",
  "token_endpoint_auth_method",
  "regenerateSecret",
  "rotateSecret",
  "policyVersion",
];

export function hasV2PolicyMutationFields(body: Record<string, any>): boolean {
  if (!body || typeof body !== "object") return false;
  return V2_POLICY_FIELDS.some((field) => body[field] !== undefined);
}

export function stripSensitiveClientFields<T extends Record<string, any>>(doc: T): Omit<T, "clientSecret" | "client_secret" | "_id"> {
  const { clientSecret: _s1, client_secret: _s2, _id: _id, ...safe } = doc;
  return safe;
}

export function extractClientTimestamps(doc: Record<string, any> | null | undefined): {
  createdDate: string;
  updatedDate: string;
} {
  const docIdStr = doc?._id ? String(doc._id) : "";
  const rawCreated = doc?.createdAt ?? doc?.created_at;
  const createdDate = rawCreated instanceof Date
    ? rawCreated.toISOString()
    : typeof rawCreated === "string"
      ? rawCreated
      : (docIdStr && ObjectId.isValid(docIdStr))
        ? new ObjectId(docIdStr).getTimestamp().toISOString()
        : new Date().toISOString();
  const rawUpdated = doc?.updatedAt ?? doc?.updated_at;
  const updatedDate = rawUpdated instanceof Date
    ? rawUpdated.toISOString()
    : typeof rawUpdated === "string"
      ? rawUpdated
      : createdDate;
  return { createdDate, updatedDate };
}

export interface ParsedNewPolicyResult {
  valid: boolean;
  error?: string;
  clientType: ClientType;
  accessPolicy: AccessPolicy;
  isPublic: boolean;
  isDev: boolean;
  tokenEndpointAuthMethod: string;
}

export function parseNewClientPolicy(body: Record<string, any>): ParsedNewPolicyResult {
  const fail = (error: string): ParsedNewPolicyResult => ({
    valid: false,
    error,
    clientType: "confidential",
    accessPolicy: "private",
    isPublic: false,
    isDev: false,
    tokenEndpointAuthMethod: "client_secret_basic",
  });

  if (body.isDev !== undefined && typeof body.isDev !== "boolean") return fail("isDev must be a boolean");
  if (body.is_dev !== undefined && typeof body.is_dev !== "boolean") return fail("is_dev must be a boolean");
  if (typeof body.isDev === "boolean" && typeof body.is_dev === "boolean" && body.isDev !== body.is_dev) {
    return fail("Conflicting isDev and is_dev boolean flags");
  }
  const isDev = Boolean(body.isDev ?? body.is_dev ?? false);

  if (body.isPublic !== undefined && typeof body.isPublic !== "boolean") return fail("isPublic must be a boolean");
  if (body.is_public !== undefined && typeof body.is_public !== "boolean") return fail("is_public must be a boolean");
  if (typeof body.isPublic === "boolean" && typeof body.is_public === "boolean" && body.isPublic !== body.is_public) {
    return fail("Conflicting isPublic and is_public boolean flags");
  }

  let clientType: ClientType = "confidential";
  if (body.clientType !== undefined) {
    if (body.clientType !== "public" && body.clientType !== "confidential") {
      return fail("clientType must be 'public' or 'confidential'");
    }
    clientType = body.clientType;
  }

  let accessPolicy: AccessPolicy = "private";
  const hasLegacyPublic = typeof body.isPublic === "boolean" || typeof body.is_public === "boolean";
  const legacyPublicVal = hasLegacyPublic ? Boolean(body.isPublic ?? body.is_public) : undefined;
  if (body.accessPolicy !== undefined) {
    if (body.accessPolicy !== "open" && body.accessPolicy !== "private") {
      return fail("accessPolicy must be 'open' or 'private'");
    }
    if (legacyPublicVal !== undefined && legacyPublicVal !== (body.accessPolicy === "open")) {
      return fail("Conflicting accessPolicy and legacy isPublic flag");
    }
    accessPolicy = body.accessPolicy;
  } else if (legacyPublicVal !== undefined) {
    accessPolicy = legacyPublicVal ? "open" : "private";
  }

  const requestedAuthMethod = body.token_endpoint_auth_method ?? body.tokenEndpointAuthMethod;
  let tokenEndpointAuthMethod = clientType === "public" ? "none" : "client_secret_basic";
  if (requestedAuthMethod !== undefined) {
    if (clientType === "public") {
      if (requestedAuthMethod !== "none") {
        return fail("Public clients must use token_endpoint_auth_method 'none'");
      }
      tokenEndpointAuthMethod = "none";
    } else {
      const allowedConfidential = ["client_secret_basic", "client_secret_post", "private_key_jwt"];
      if (!allowedConfidential.includes(String(requestedAuthMethod))) {
        return fail("Unsupported token_endpoint_auth_method for confidential client");
      }
      tokenEndpointAuthMethod = String(requestedAuthMethod);
    }
  }

  return {
    valid: true,
    clientType,
    accessPolicy,
    isPublic: accessPolicy === "open",
    isDev,
    tokenEndpointAuthMethod,
  };
}

export interface PatchPolicyPlan {
  valid: boolean;
  error?: string;
  targetClientType: ClientType;
  targetAccessPolicy: AccessPolicy;
  targetIsPublic: boolean;
  targetIsDev: boolean;
  targetAuthMethod: string;
  isExplicitMigration: boolean;
  isPolicyChange: boolean;
  deleteSecret: boolean;
  freshSecret?: string;
  freshSecretHash?: string;
}

export function resolvePatchClientPolicy(
  oldClient: Record<string, any>,
  body: Record<string, any>,
  isSuper: boolean,
): PatchPolicyPlan {
  const fail = (error: string): PatchPolicyPlan => ({
    valid: false,
    error,
    targetClientType: oldClient.clientType === "public" ? "public" : "confidential",
    targetAccessPolicy: oldClient.accessPolicy === "open" ? "open" : "private",
    targetIsPublic: false,
    targetIsDev: false,
    targetAuthMethod: "client_secret_basic",
    isExplicitMigration: false,
    isPolicyChange: false,
    deleteSecret: false,
  });

  if (!isSuper) {
    return {
      valid: true,
      targetClientType: oldClient.clientType === "public" ? "public" : "confidential",
      targetAccessPolicy: oldClient.accessPolicy === "open" ? "open" : "private",
      targetIsPublic: Boolean(oldClient.isPublic ?? oldClient.is_public ?? true),
      targetIsDev: Boolean(oldClient.isDev ?? oldClient.is_dev),
      targetAuthMethod: oldClient.tokenEndpointAuthMethod || oldClient.token_endpoint_auth_method || "client_secret_basic",
      isExplicitMigration: false,
      isPolicyChange: false,
      deleteSecret: false,
    };
  }

  if (body.isDev !== undefined && typeof body.isDev !== "boolean") return fail("isDev must be a boolean");
  if (body.is_dev !== undefined && typeof body.is_dev !== "boolean") return fail("is_dev must be a boolean");
  if (typeof body.isDev === "boolean" && typeof body.is_dev === "boolean" && body.isDev !== body.is_dev) {
    return fail("Conflicting isDev and is_dev boolean flags");
  }
  if (body.isPublic !== undefined && typeof body.isPublic !== "boolean") return fail("isPublic must be a boolean");
  if (body.is_public !== undefined && typeof body.is_public !== "boolean") return fail("is_public must be a boolean");
  if (typeof body.isPublic === "boolean" && typeof body.is_public === "boolean" && body.isPublic !== body.is_public) {
    return fail("Conflicting isPublic and is_public boolean flags");
  }

  const targetIsDev = typeof (body.isDev ?? body.is_dev) === "boolean"
    ? Boolean(body.isDev ?? body.is_dev)
    : Boolean(oldClient.isDev ?? oldClient.is_dev);

  const oldType: ClientType = oldClient.clientType === "public" ? "public" : "confidential";
  let targetClientType: ClientType = oldType;
  if (body.clientType !== undefined) {
    if (body.clientType !== "public" && body.clientType !== "confidential") {
      return fail("clientType must be 'public' or 'confidential'");
    }
    targetClientType = body.clientType;
  }

  const oldPolicy: AccessPolicy = oldClient.accessPolicy === "open"
    ? "open"
    : (oldClient.accessPolicy === "private" ? "private" : (oldClient.isPublic === true || oldClient.is_public === true ? "open" : "private"));
  let targetAccessPolicy: AccessPolicy = oldPolicy;
  const hasLegacyPublic = typeof body.isPublic === "boolean" || typeof body.is_public === "boolean";
  const legacyPublicVal = hasLegacyPublic ? Boolean(body.isPublic ?? body.is_public) : undefined;

  if (body.accessPolicy !== undefined) {
    if (body.accessPolicy !== "open" && body.accessPolicy !== "private") {
      return fail("accessPolicy must be 'open' or 'private'");
    }
    if (legacyPublicVal !== undefined && legacyPublicVal !== (body.accessPolicy === "open")) {
      return fail("Conflicting accessPolicy and legacy isPublic flag");
    }
    targetAccessPolicy = body.accessPolicy;
  } else if (legacyPublicVal !== undefined) {
    targetAccessPolicy = legacyPublicVal ? "open" : "private";
  }

  const existingHasSecret = Boolean(oldClient.clientSecret || oldClient.client_secret);
  const existingAuthMethod = oldClient.tokenEndpointAuthMethod || oldClient.token_endpoint_auth_method;
  const requestedAuthMethod = body.token_endpoint_auth_method ?? body.tokenEndpointAuthMethod;
  const wantsRegenerate = body.regenerateSecret === true || body.rotateSecret === true;

  let targetAuthMethod = existingAuthMethod || (targetClientType === "public" ? "none" : "client_secret_basic");
  let deleteSecret = false;
  let freshSecret: string | undefined;
  let freshSecretHash: string | undefined;

  if (targetClientType === "public") {
    if (requestedAuthMethod !== undefined && requestedAuthMethod !== "none") {
      return fail("Public clients must use token_endpoint_auth_method 'none'");
    }
    targetAuthMethod = "none";
    if (existingHasSecret) deleteSecret = true;
  } else {
    const allowedConfidential = ["client_secret_basic", "client_secret_post", "private_key_jwt"];
    if (requestedAuthMethod !== undefined) {
      if (!allowedConfidential.includes(String(requestedAuthMethod))) {
        return fail("Unsupported token_endpoint_auth_method for confidential client");
      }
      targetAuthMethod = String(requestedAuthMethod);
    } else if (!existingAuthMethod || existingAuthMethod === "none") {
      targetAuthMethod = "client_secret_basic";
    }
    if (targetAuthMethod !== "private_key_jwt" && (!existingHasSecret || wantsRegenerate)) {
      freshSecret = crypto.randomBytes(24).toString("base64url");
      freshSecretHash = crypto.createHash("sha256").update(freshSecret).digest("base64url");
    }
  }

  const isExplicitMigration = body.clientType !== undefined || body.accessPolicy !== undefined;
  const isPolicyChange =
    isExplicitMigration ||
    body.isDev !== undefined ||
    body.is_dev !== undefined ||
    hasLegacyPublic ||
    wantsRegenerate;

  return {
    valid: true,
    targetClientType,
    targetAccessPolicy,
    targetIsPublic: targetAccessPolicy === "open",
    targetIsDev,
    targetAuthMethod,
    isExplicitMigration,
    isPolicyChange,
    deleteSecret,
    freshSecret,
    freshSecretHash,
  };
}
