import { authProvider } from "../utils/auth";
import { getDb } from "../db/mongo";
import { config } from "../config";
import {
  getHeaders,
  getTrustedClientIp,
  deriveAllowedOriginsFromRedirectUris,
  normalizeOAuthClientFields,
  validateOAuthClientConfiguration,
  resolveOAuthClient,
} from "../utils/security";
import { isSuperAdmin } from "../middleware/admin-auth";
import { recordAdminAudit } from "../db/state";
import { invalidateClientOrigins } from "../cache/origin-cache";
import { resolveClientPolicy } from "../identity/client-policy";
import {
  hasV2PolicyMutationFields,
  resolvePatchClientPolicy,
  stripSensitiveClientFields,
  extractClientTimestamps,
} from "./admin-client-policy-helper";

const authApi = authProvider.api as any;

export async function handleGetClientById(c: any): Promise<Response> {
  const id = c.req.param("id");

  try {
    const database = await getDb();
    const clientDoc = await database.collection("oauthClient").findOne({
      $or: [{ id }, { clientId: id }, { client_id: id }],
    });

    if (!clientDoc) return c.json({ error: "Client not found" }, 404);

    const { createdDate: createdAtIso, updatedDate: updatedAtIso } = extractClientTimestamps(clientDoc);
    const canonicalId = clientDoc.clientId || clientDoc.client_id || clientDoc.id || String(clientDoc._id);
    const normalized = normalizeOAuthClientFields({ ...clientDoc, id: canonicalId, clientId: canonicalId });
    return c.json(stripSensitiveClientFields({
      ...normalized,
      client_id: normalized.clientId,
      createdAt: createdAtIso,
      created_at: createdAtIso,
      updatedAt: updatedAtIso,
      updated_at: updatedAtIso,
    }));
  } catch (err: any) {
    return c.json({ error: "Client not found" }, 404);
  }
}

export async function handlePatchClientById(c: any): Promise<Response> {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  // Prevent modifying client_id, clientId, id, userId, or role (strip tampering fields)
  delete body.client_id;
  delete body.clientId;
  delete body.id;
  delete body.userId;
  delete body.role;

  const isSuper = isSuperAdmin(sessionUser);
  if (!isSuper && hasV2PolicyMutationFields(body)) {
    return c.json(
      {
        error: "forbidden",
        code: "ERR_POLICY_FORBIDDEN",
        message: "Only platform super administrators can modify client policy dimensions",
      },
      403
    );
  }

  if (!isSuper) {
    for (const k of ["isPublic", "is_public", "isDev", "is_dev", "disabled", "is_active", "clientId", "clientSecret", "client_secret", "adminEmail", "admin_email", "adminUserId", "admin_user_id"]) {
      delete body[k];
    }
  }

  let oldClient: any = null;
  const database = await getDb();
  try {
    oldClient = await resolveOAuthClient(database, id);
    if (!oldClient) {
      oldClient = await authApi.getOAuthClient({
        headers: getHeaders(c),
        query: { client_id: id },
      });
    }
  } catch {}

  if (!oldClient) {
    return c.json({ error: "Client not found" }, 404);
  }

  const hasNewRedirectUris = Array.isArray(body.redirect_uris || body.redirectUris) && (body.redirect_uris || body.redirectUris).length > 0;
  const targetRedirectUris: string[] = hasNewRedirectUris
    ? ((body.redirect_uris || body.redirectUris) as string[])
    : ((oldClient.redirectUris || oldClient.redirect_uris || []) as string[]);

  const hasNewAllowedOrigins = Array.isArray(body.allowed_origins || body.allowedOrigins) && (body.allowed_origins || body.allowedOrigins).length > 0;
  let targetAllowedOrigins: string[] = hasNewAllowedOrigins
    ? ((body.allowed_origins || body.allowedOrigins) as string[])
    : ((oldClient.allowedOrigins || oldClient.allowed_origins || []) as string[]);

  if (targetAllowedOrigins.length === 0 && targetRedirectUris.length > 0) {
    targetAllowedOrigins = deriveAllowedOriginsFromRedirectUris(targetRedirectUris);
  }

  const policyPlan = resolvePatchClientPolicy(oldClient, body, isSuper);
  if (!policyPlan.valid) {
    return c.json({ error: policyPlan.error }, 400);
  }

  const targetIsDev = policyPlan.targetIsDev;
  const targetIsPublic = policyPlan.targetIsPublic;
  const targetClientName = typeof body.client_name === "string"
    ? body.client_name.trim()
    : (typeof body.name === "string" ? body.name.trim() : oldClient.name);

  // Construct target state to validate final desired client configuration atomically
  const targetState = {
    ...oldClient,
    name: targetClientName,
    client_name: targetClientName,
    redirectUris: targetRedirectUris,
    redirect_uris: targetRedirectUris,
    allowedOrigins: targetAllowedOrigins,
    allowed_origins: targetAllowedOrigins,
    isDev: targetIsDev,
    is_dev: targetIsDev,
    isPublic: targetIsPublic,
    is_public: targetIsPublic,
  };

  let applicationType = oldClient.applicationType || oldClient.application_type || "web";
  if (
    hasNewRedirectUris ||
    hasNewAllowedOrigins ||
    policyPlan.isPolicyChange ||
    targetIsDev !== Boolean(oldClient.isDev ?? oldClient.is_dev)
  ) {
    const validation = validateOAuthClientConfiguration(targetState, {
      serverEnvironment: config.env,
      isNewClient: false,
      allowDevClientsInProduction: config.allowDevClientsInProduction,
      isSuperAdminOp: isSuper,
    });

    if (!validation.valid) {
      return c.json({ error: validation.error }, 400);
    }
    applicationType = validation.effectiveApplicationType;
  }

  const now = new Date();
  const dbUpdates: any = { updatedAt: now };
  const dbUnsets: Record<string, string> = {};
  if (hasNewRedirectUris) {
    dbUpdates.redirectUris = targetRedirectUris;
    dbUpdates.redirect_uris = targetRedirectUris;
  }
  if (applicationType) {
    dbUpdates.applicationType = applicationType;
    dbUpdates.application_type = applicationType;
  }
  if (targetClientName) dbUpdates.name = targetClientName;
  if (hasNewAllowedOrigins || (hasNewRedirectUris && targetAllowedOrigins.length > 0)) {
    dbUpdates.allowedOrigins = targetAllowedOrigins;
    dbUpdates.allowed_origins = targetAllowedOrigins;
  }
  if (isSuper && policyPlan.isPolicyChange) {
    dbUpdates.isDev = targetIsDev;
    dbUpdates.is_dev = targetIsDev;
    dbUpdates.isPublic = targetIsPublic;
    dbUpdates.is_public = targetIsPublic;
    dbUpdates.clientType = policyPlan.targetClientType;
    dbUpdates.accessPolicy = policyPlan.targetAccessPolicy;
    dbUpdates.tokenEndpointAuthMethod = policyPlan.targetAuthMethod;
    dbUpdates.token_endpoint_auth_method = policyPlan.targetAuthMethod;
    if (policyPlan.isExplicitMigration) {
      dbUpdates.policyVersion = 2;
      dbUpdates.policyMigratedAt = now;
      dbUpdates.policyMigratedBy = sessionUser?.id || null;
    }
    if (policyPlan.deleteSecret) {
      dbUnsets.clientSecret = "";
      dbUnsets.client_secret = "";
    } else if (policyPlan.freshSecretHash) {
      dbUpdates.clientSecret = policyPlan.freshSecretHash;
      dbUnsets.client_secret = "";
    }
  }

  const candidateDoc: Record<string, any> = { ...oldClient, ...dbUpdates };
  for (const k of Object.keys(dbUnsets)) delete candidateDoc[k];
  if (policyPlan.isExplicitMigration) {
    const candidatePolicy = resolveClientPolicy(candidateDoc);
    if (candidatePolicy.classification !== "MIGRATED") {
      return c.json(
        {
          error: candidatePolicy.reasons[0] || "Client policy validation failed",
          reasonCodes: candidatePolicy.reasonCodes,
          reasons: candidatePolicy.reasons,
        },
        400
      );
    }
  }

  const updatePayload: any = {};
  if (targetClientName) updatePayload.client_name = targetClientName;
  if (hasNewRedirectUris) updatePayload.redirect_uris = targetRedirectUris;
  if (applicationType) updatePayload.application_type = applicationType;
  if (typeof body.skip_consent === "boolean") updatePayload.skip_consent = body.skip_consent;
  if (typeof body.skipConsent === "boolean") updatePayload.skip_consent = body.skipConsent;
  if (typeof body.enable_end_session === "boolean") updatePayload.enable_end_session = body.enable_end_session;
  if (typeof body.enableEndSession === "boolean") updatePayload.enable_end_session = body.enableEndSession;
  if (typeof body.disabled === "boolean") updatePayload.disabled = body.disabled;
  if (typeof body.is_active === "boolean") updatePayload.disabled = !body.is_active;

  let result: any = null;
  try {
    result = await authApi.adminUpdateOAuthClient({
      headers: getHeaders(c),
      body: { client_id: id, update: updatePayload },
    });
  } catch (err: any) {
    console.warn("[ADMIN_PATCH_CLIENT] Better-Auth update error, proceeding with direct DB update:", err?.body || err?.message);
  }

  if (typeof updatePayload.skip_consent === "boolean") dbUpdates.skipConsent = updatePayload.skip_consent;
  if (typeof updatePayload.enable_end_session === "boolean") dbUpdates.enableEndSession = updatePayload.enable_end_session;
  if (typeof updatePayload.disabled === "boolean") dbUpdates.disabled = updatePayload.disabled;

  const mongoUpdate: Record<string, any> = { $set: dbUpdates };
  if (Object.keys(dbUnsets).length > 0) mongoUpdate.$unset = dbUnsets;
  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId: id }, { client_id: id }, { id }] },
    mongoUpdate
  );
  const updatedDoc = await database.collection("oauthClient").findOne({
    $or: [{ clientId: id }, { client_id: id }, { id }],
  });

  if (!result && !updatedDoc) return c.json({ error: "Client not found" }, 404);

  // Invalidate CORS origin cache across Redis and MongoDB after database update (prevents races)
  await invalidateClientOrigins(oldClient, updatedDoc || { ...oldClient, ...dbUpdates, ...body });

  // Token revocation on client disable or Confidential -> Public secret revocation
  const canonicalId = updatedDoc?.clientId || oldClient.clientId || id;
  if (body.disabled === true || body.is_active === false || policyPlan.deleteSecret) {
    await Promise.all([
      database.collection("oauthAccessToken").deleteMany({ clientId: canonicalId }),
      database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalId }),
      database.collection("oauthAuthorizationCode").deleteMany({ clientId: canonicalId }),
      database.collection("oauth_token_families").deleteMany({ clientId: canonicalId }),
    ]);
  }

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_patched",
    targetClientId: canonicalId,
    details: { modifiedFields: Object.keys(body) },
    ipAddress: getTrustedClientIp(c),
    timestamp: now,
  });

  const { createdDate, updatedDate } = extractClientTimestamps(updatedDoc);

  const normalized = normalizeOAuthClientFields({
    ...(updatedDoc || result || {}),
    id: canonicalId,
    clientId: canonicalId,
    redirectUris: updatedDoc?.redirectUris || targetRedirectUris || [],
    allowedOrigins: updatedDoc?.allowedOrigins || targetAllowedOrigins || [],
  });

  const safeResult = stripSensitiveClientFields({
    ...normalized,
    client_id: normalized.clientId,
    createdAt: createdDate,
    created_at: createdDate,
    updatedAt: updatedDate,
    updated_at: updatedDate,
  });
  return c.json(policyPlan.freshSecret ? { ...safeResult, client_secret: policyPlan.freshSecret } : safeResult);
}
