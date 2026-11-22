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

const authApi = authProvider.api as any;

export async function handleGetAppConfig(c: any): Promise<Response> {
  const clientId = c.req.param("clientId");
  try {
    const database = await getDb();
    let result: any = await resolveOAuthClient(database, clientId);
    if (!result) {
      try {
        result = (await authApi.getOAuthClient({
          headers: getHeaders(c),
          query: { client_id: clientId },
        })) as Record<string, unknown> | null;
      } catch {}
    }

    if (!result) return c.json({ error: "Application not found" }, 404);
    const normalized = normalizeOAuthClientFields({ ...(result || {}), id: result.clientId || clientId, clientId: result.clientId || clientId });
    const { client_secret: _omit, clientSecret: _omit2, _id: _omit3, ...safeResult } = normalized as any;
    return c.json(safeResult);
  } catch {
    return c.json({ error: "Application not found or unauthorized" }, 404);
  }
}

export async function handlePatchAppConfig(c: any): Promise<Response> {
  const clientId = c.req.param("clientId");
  const body = await c.req.json().catch(() => ({}));
  const sessionUser = c.get("user") as any;

  // Disallow forbidden privilege and identity fields
  const forbiddenFields = [
    "role",
    "scopedClientId",
    "ownerId",
    "permissions",
    "isSuperAdmin",
    "clientId",
    "client_id",
    "id",
    "_id",
    "userId",
    "clientSecret",
    "client_secret",
  ];
  for (const field of forbiddenFields) {
    delete body[field];
  }

  const database = await getDb();
  let oldClient: any = await resolveOAuthClient(database, clientId);
  if (!oldClient) {
    try {
      oldClient = await authApi.getOAuthClient({
        headers: getHeaders(c),
        query: { client_id: clientId },
      });
    } catch {}
  }
  if (!oldClient) return c.json({ error: "Application not found" }, 404);

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

  const targetIsDev = isSuperAdmin(sessionUser) && typeof (body.is_dev ?? body.isDev) === "boolean"
    ? Boolean(body.is_dev ?? body.isDev)
    : Boolean(oldClient.isDev ?? oldClient.is_dev);

  const targetIsPublic = isSuperAdmin(sessionUser) && typeof (body.is_public ?? body.isPublic) === "boolean"
    ? Boolean(body.is_public ?? body.isPublic)
    : Boolean(oldClient.isPublic ?? oldClient.is_public ?? true);

  const targetClientName = typeof body.client_name === "string" ? body.client_name.trim() : (typeof body.name === "string" ? body.name.trim() : oldClient.name);

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

  const validation = validateOAuthClientConfiguration(targetState, {
    serverEnvironment: config.env,
    isNewClient: false,
    allowDevClientsInProduction: config.allowDevClientsInProduction,
    isSuperAdminOp: isSuperAdmin(sessionUser),
  });

  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  // Construct explicitly allowlisted update object
  const safeUpdate: Record<string, any> = { updatedAt: new Date() };
  if (targetClientName) {
    safeUpdate.name = targetClientName;
    safeUpdate.client_name = targetClientName;
  }
  if (hasNewRedirectUris) {
    safeUpdate.redirect_uris = targetRedirectUris;
    safeUpdate.redirectUris = targetRedirectUris;
  }
  if (hasNewAllowedOrigins || (hasNewRedirectUris && targetAllowedOrigins.length > 0)) {
    safeUpdate.allowed_origins = targetAllowedOrigins;
    safeUpdate.allowedOrigins = targetAllowedOrigins;
  }
  safeUpdate.applicationType = validation.effectiveApplicationType;
  safeUpdate.application_type = validation.effectiveApplicationType;

  if (isSuperAdmin(sessionUser)) {
    if (typeof (body.is_dev ?? body.isDev) === "boolean") {
      safeUpdate.is_dev = targetIsDev;
      safeUpdate.isDev = targetIsDev;
    }
    if (typeof (body.is_public ?? body.isPublic) === "boolean") {
      safeUpdate.is_public = targetIsPublic;
      safeUpdate.isPublic = targetIsPublic;
    }
  }
  if (typeof (body.skip_consent ?? body.skipConsent) === "boolean") {
    safeUpdate.skip_consent = Boolean(body.skip_consent ?? body.skipConsent);
    safeUpdate.skipConsent = Boolean(body.skip_consent ?? body.skipConsent);
  }
  if (typeof (body.enable_end_session ?? body.enableEndSession) === "boolean") {
    safeUpdate.enable_end_session = Boolean(body.enable_end_session ?? body.enableEndSession);
    safeUpdate.enableEndSession = Boolean(body.enable_end_session ?? body.enableEndSession);
  }
  if (typeof body.logo_uri === "string") safeUpdate.logo_uri = body.logo_uri;
  if (typeof body.icon === "string") safeUpdate.icon = body.icon;
  if (body.metadata && typeof body.metadata === "object" && !Array.isArray(body.metadata)) {
    safeUpdate.metadata = body.metadata;
  }

  let result: any = null;
  try {
    result = await authApi.updateOAuthClient({
      headers: getHeaders(c),
      body: { client_id: clientId, update: safeUpdate },
    });
  } catch {
    await database.collection("oauthClient").updateOne(
      { $or: [{ clientId }, { client_id: clientId }, { id: clientId }] },
      { $set: safeUpdate }
    );
    result = await database.collection("oauthClient").findOne({
      $or: [{ clientId }, { client_id: clientId }, { id: clientId }],
    });
  }

  if (!result) return c.json({ error: "Application not found" }, 404);

  // Invalidate CORS origin cache across Redis and MongoDB after database update
  await invalidateClientOrigins(oldClient, result || { ...oldClient, ...safeUpdate, ...body });

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "scoped_app_config_patched",
    targetClientId: clientId,
    details: { modifiedFields: Object.keys(safeUpdate) },
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  const normalized = normalizeOAuthClientFields({ ...(result || {}), id: clientId, clientId });
  const { client_secret: _omit, clientSecret: _omit2, ...safeResult } = normalized as any;
  return c.json(safeResult);
}
