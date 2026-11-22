import { ObjectId } from "mongodb";
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

export async function handleGetClientById(c: any): Promise<Response> {
  const id = c.req.param("id");

  try {
    const database = await getDb();
    const clientDoc = await database.collection("oauthClient").findOne({
      $or: [{ id }, { clientId: id }, { client_id: id }],
    });

    if (!clientDoc) return c.json({ error: "Client not found" }, 404);

    const { clientSecret, client_secret, _id, ...rest } = clientDoc;
    const rawDate = rest.createdAt || rest.created_at || (ObjectId.isValid(_id) ? new ObjectId(_id).getTimestamp() : new Date());
    const createdAtIso = rawDate instanceof Date ? rawDate.toISOString() : (typeof rawDate === "string" ? rawDate : new Date(rawDate).toISOString());
    const rawUpdateDate = rest.updatedAt || rest.updated_at || rawDate;
    const updatedAtIso = rawUpdateDate instanceof Date ? rawUpdateDate.toISOString() : (typeof rawUpdateDate === "string" ? rawUpdateDate : new Date(rawUpdateDate).toISOString());

    const normalized = normalizeOAuthClientFields({ ...clientDoc, ...rest, id: rest.clientId || rest.client_id || rest.id || String(_id) });
    return c.json({
      ...normalized,
      client_id: normalized.clientId,
      createdAt: createdAtIso,
      created_at: createdAtIso,
      updatedAt: updatedAtIso,
      updated_at: updatedAtIso,
    });
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

  if (!isSuperAdmin(sessionUser)) {
    delete body.isPublic;
    delete body.is_public;
    delete body.isDev;
    delete body.is_dev;
    delete body.disabled;
    delete body.is_active;
    delete body.clientId;
    delete body.clientSecret;
    delete body.client_secret;
    delete body.adminEmail;
    delete body.admin_email;
    delete body.adminUserId;
    delete body.admin_user_id;
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

  const targetIsDev = isSuperAdmin(sessionUser) && typeof (body.isDev ?? body.is_dev) === "boolean"
    ? Boolean(body.isDev ?? body.is_dev)
    : Boolean(oldClient.isDev ?? oldClient.is_dev);

  const targetIsPublic = isSuperAdmin(sessionUser) && typeof (body.isPublic ?? body.is_public) === "boolean"
    ? Boolean(body.isPublic ?? body.is_public)
    : Boolean(oldClient.isPublic ?? oldClient.is_public ?? true);

  const targetClientName = typeof body.client_name === "string" ? body.client_name.trim() : (typeof body.name === "string" ? body.name.trim() : oldClient.name);

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
  if (hasNewRedirectUris || targetIsDev !== Boolean(oldClient.isDev ?? oldClient.is_dev) || hasNewAllowedOrigins) {
    const validation = validateOAuthClientConfiguration(targetState, {
      serverEnvironment: config.env,
      isNewClient: false,
      allowDevClientsInProduction: config.allowDevClientsInProduction,
      isSuperAdminOp: isSuperAdmin(sessionUser),
    });

    if (!validation.valid) {
      return c.json({ error: validation.error }, 400);
    }
    applicationType = validation.effectiveApplicationType;
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

  // Fallback / sync direct update to DB for custom fields (allowedOrigins, isDev, etc.)
  const dbUpdates: any = { updatedAt: new Date() };
  if (hasNewAllowedOrigins || (hasNewRedirectUris && targetAllowedOrigins.length > 0)) {
    dbUpdates.allowedOrigins = targetAllowedOrigins;
    dbUpdates.allowed_origins = targetAllowedOrigins;
  }
  if (isSuperAdmin(sessionUser)) {
    if (typeof (body.isDev ?? body.is_dev) === "boolean") {
      dbUpdates.isDev = targetIsDev;
      dbUpdates.is_dev = targetIsDev;
    }
    if (typeof (body.isPublic ?? body.is_public) === "boolean") {
      dbUpdates.isPublic = targetIsPublic;
      dbUpdates.is_public = targetIsPublic;
    }
  }
  if (typeof updatePayload.skip_consent === "boolean") dbUpdates.skipConsent = updatePayload.skip_consent;
  if (typeof updatePayload.enable_end_session === "boolean") dbUpdates.enableEndSession = updatePayload.enable_end_session;
  if (typeof updatePayload.disabled === "boolean") dbUpdates.disabled = updatePayload.disabled;
  if (hasNewRedirectUris) {
    dbUpdates.redirectUris = targetRedirectUris;
    dbUpdates.redirect_uris = targetRedirectUris;
  }
  if (applicationType) {
    dbUpdates.applicationType = applicationType;
    dbUpdates.application_type = applicationType;
  }
  if (targetClientName) dbUpdates.name = targetClientName;

  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId: id }, { client_id: id }, { id }] },
    { $set: dbUpdates }
  );
  const updatedDoc = await database.collection("oauthClient").findOne({
    $or: [{ clientId: id }, { client_id: id }, { id }],
  });

  if (!result && !updatedDoc) return c.json({ error: "Client not found" }, 404);

  // Invalidate CORS origin cache across Redis and MongoDB after database update (prevents races)
  await invalidateClientOrigins(oldClient, updatedDoc || { ...oldClient, ...dbUpdates, ...body });

  // Token revocation on client disable
  if (body.disabled === true || body.is_active === false) {
    await Promise.all([
      database.collection("oauthAccessToken").deleteMany({ clientId: id }),
      database.collection("oauthRefreshToken").deleteMany({ clientId: id }),
      database.collection("oauthAuthorizationCode").deleteMany({ clientId: id }),
      database.collection("oauth_token_families").deleteMany({ clientId: id }),
    ]);
  }

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_patched",
    targetClientId: id,
    details: { modifiedFields: Object.keys(body) },
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  const docIdStr = updatedDoc?._id ? String(updatedDoc._id) : "";
  const createdDate = updatedDoc?.createdAt instanceof Date
    ? updatedDoc.createdAt.toISOString()
    : typeof updatedDoc?.createdAt === "string"
      ? updatedDoc.createdAt
      : (docIdStr && ObjectId.isValid(docIdStr))
        ? new ObjectId(docIdStr).getTimestamp().toISOString()
        : new Date().toISOString();
  const updatedDate = updatedDoc?.updatedAt instanceof Date
    ? updatedDoc.updatedAt.toISOString()
    : typeof updatedDoc?.updatedAt === "string"
      ? updatedDoc.updatedAt
      : new Date().toISOString();

  const normalized = normalizeOAuthClientFields({
    ...(result || {}),
    ...(updatedDoc || {}),
    id: updatedDoc?.clientId || id,
    clientId: updatedDoc?.clientId || id,
    redirectUris: updatedDoc?.redirectUris || targetRedirectUris || [],
    allowedOrigins: updatedDoc?.allowedOrigins || targetAllowedOrigins || [],
  });

  const finalResult = {
    ...normalized,
    client_id: normalized.clientId,
    createdAt: createdDate,
    created_at: createdDate,
    updatedAt: updatedDate,
    updated_at: updatedDate,
  };

  const { client_secret: _omit, clientSecret: _omit2, _id: _omit3, ...safeResult } = finalResult as any;
  return c.json(safeResult);
}
