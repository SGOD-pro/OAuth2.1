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

export async function handleGetClients(c: any): Promise<Response> {
  try {
    const database = await getDb();

    const [clients, appAdminClientIds] = await Promise.all([
      database.collection("oauthClient").find({}).sort({ createdAt: -1, _id: -1 }).toArray(),
      database.collection("app_admins").distinct("clientId"),
    ]);

    const appAdminSet = new Set((appAdminClientIds || []).map((id: any) => String(id)));

    const safeClients = clients.map((doc: any) => {
      const { clientSecret, client_secret, _id, ...rest } = doc;
      const canonicalClientId = rest.clientId || rest.client_id || rest.id || String(_id);
      const hasCustomAdmins = Boolean(
        rest.adminEmail ||
        rest.admin_email ||
        rest.adminUserId ||
        rest.admin_user_id ||
        appAdminSet.has(canonicalClientId)
      );

      const rawDate = rest.createdAt || rest.created_at || (ObjectId.isValid(_id) ? new ObjectId(_id).getTimestamp() : new Date());
      const createdAtIso = rawDate instanceof Date ? rawDate.toISOString() : (typeof rawDate === "string" ? rawDate : new Date(rawDate).toISOString());
      const rawUpdateDate = rest.updatedAt || rest.updated_at || rawDate;
      const updatedAtIso = rawUpdateDate instanceof Date ? rawUpdateDate.toISOString() : (typeof rawUpdateDate === "string" ? rawUpdateDate : new Date(rawUpdateDate).toISOString());

      const normalized = normalizeOAuthClientFields({ ...doc, ...rest, id: canonicalClientId, clientId: canonicalClientId });
      return {
        ...normalized,
        client_id: canonicalClientId,
        clientId: canonicalClientId,
        adminEmail: rest.adminEmail || rest.admin_email || null,
        adminUserId: rest.adminUserId || rest.admin_user_id || null,
        has_custom_admins: hasCustomAdmins,
        hasCustomAdmins: hasCustomAdmins,
        createdAt: createdAtIso,
        created_at: createdAtIso,
        updatedAt: updatedAtIso,
        updated_at: updatedAtIso,
      };
    });

    safeClients.sort((a, b) => {
      const timeA = new Date(a.createdAt).getTime() || 0;
      const timeB = new Date(b.createdAt).getTime() || 0;
      return timeB - timeA;
    });

    return c.json(safeClients);
  } catch (err: any) {
    console.error("[ADMIN_CLIENTS] Error listing clients:", err);
    return c.json({ error: "Failed to fetch clients" }, 500);
  }
}

export async function handlePostClients(c: any): Promise<Response> {
  const body = await c.req.json();
  const sessionUser = c.get("user") as any;

  const isDev = Boolean(body.isDev || body.is_dev);
  const clientName = (body.name || body.client_name || "").trim();
  if (!clientName) {
    return c.json({ error: "Application name is required" }, 400);
  }

  const redirectUris = (body.redirect_uris || body.redirectUris || []) as string[];
  let allowedOrigins = (body.allowed_origins || body.allowedOrigins || []) as string[];
  if (allowedOrigins.length === 0 && redirectUris.length > 0) {
    allowedOrigins = deriveAllowedOriginsFromRedirectUris(redirectUris);
  }
  const isPublic = typeof body.isPublic === "boolean" ? body.isPublic : (typeof body.is_public === "boolean" ? body.is_public : true);

  if (allowedOrigins.length === 0) {
    return c.json({ error: "At least one allowed origin is required" }, 400);
  }

  const targetState = {
    client_name: clientName,
    redirect_uris: redirectUris,
    allowed_origins: allowedOrigins,
    isDev,
    isPublic,
    skip_consent: Boolean(body.skip_consent ?? body.skipConsent),
    enable_end_session: body.enable_end_session !== false && body.enableEndSession !== false,
  };

  const validation = validateOAuthClientConfiguration(targetState, {
    serverEnvironment: config.env,
    isNewClient: true,
    allowDevClientsInProduction: config.allowDevClientsInProduction,
    isSuperAdminOp: isSuperAdmin(sessionUser),
  });

  if (!validation.valid) {
    return c.json({ error: validation.error }, 400);
  }

  // application_type is strictly security-derived; request body cannot override
  const applicationType = validation.effectiveApplicationType;
  const effectiveOrigins = validation.effectiveAllowedOrigins.length > 0 ? validation.effectiveAllowedOrigins : allowedOrigins;

  const createBody: any = {
    client_name: clientName,
    redirect_uris: redirectUris,
    application_type: applicationType,
    skip_consent: Boolean(body.skip_consent ?? body.skipConsent),
    enable_end_session: body.enable_end_session !== false && body.enableEndSession !== false,
    metadata: {
      allowedOrigins: effectiveOrigins,
      isDev,
    },
  };

  let result: any = null;
  try {
    result = await authApi.adminCreateOAuthClient({
      headers: getHeaders(c),
      body: createBody,
    });
  } catch (err: any) {
    console.error("[ADMIN_CREATE_CLIENT] Better-Auth error:", err.body || err.message);
    const msg = err.body?.error_description || err.body?.error || err.message || "Failed to create OAuth client";
    const statusCode = typeof err.statusCode === "number" ? err.statusCode : (err.status === "BAD_REQUEST" ? 400 : 500);
    return c.json({ error: msg }, statusCode as any);
  }

  if (!result) {
    return c.json({ error: "Failed to create client" }, 500);
  }

  const clientId = result.client_id || result.clientId || result.id;

  const now = new Date();
  // Persist extra fields in MongoDB oauthClient collection
  const database = await getDb();
  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId }, { id: clientId }, { client_id: clientId }] },
    {
      $set: {
        allowedOrigins: effectiveOrigins,
        allowed_origins: effectiveOrigins,
        redirectUris,
        redirect_uris: redirectUris,
        isDev,
        isPublic,
        skipConsent: Boolean(body.skip_consent ?? body.skipConsent),
        enableEndSession: body.enable_end_session !== false && body.enableEndSession !== false,
        updatedAt: now,
      },
      $setOnInsert: {
        createdAt: now,
      },
    },
  );
  await database.collection("oauthClient").updateOne(
    { $or: [{ clientId }, { id: clientId }, { client_id: clientId }], createdAt: { $exists: false } },
    { $set: { createdAt: now } }
  );

  await invalidateClientOrigins(null, {
    allowedOrigins: effectiveOrigins,
    redirectUris,
  });

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_created",
    targetClientId: String(clientId),
    details: { name: clientName, client_id: clientId },
    ipAddress: getTrustedClientIp(c),
    timestamp: now,
  });

  const responsePayload = {
    ...result,
    client_id: clientId,
    client_secret: result.client_secret || result.clientSecret,
    client_name: clientName,
    redirect_uris: redirectUris,
    redirectUris: redirectUris,
    allowed_origins: effectiveOrigins,
    allowedOrigins: effectiveOrigins,
    is_dev: isDev,
    is_public: isPublic,
    isPublic: isPublic,
    skip_consent: Boolean(body.skip_consent ?? body.skipConsent),
    enable_end_session: body.enable_end_session !== false && body.enableEndSession !== false,
    createdAt: now.toISOString(),
    created_at: now.toISOString(),
    updatedAt: now.toISOString(),
    updated_at: now.toISOString(),
  };

  return c.json(responsePayload, 201);
}

export async function handleDeleteClient(c: any): Promise<Response> {
  const id = c.req.param("id");
  const sessionUser = c.get("user") as any;
  let database: any;
  let existingClient: any;

  try {
    database = await getDb();
    existingClient = await resolveOAuthClient(database, id);
  } catch (err: any) {
    console.error("[ADMIN_DELETE_CLIENT] DB error resolving client:", err);
    return c.json({ error: "Failed to resolve client due to database error" }, 500);
  }

  if (!existingClient) {
    return c.json({ error: "Client not found" }, 404);
  }

  const canonicalClientId = existingClient.clientId;
  const clientMongoId = existingClient._id;

  // Delete exact client by MongoDB _id, and all dependent resources by canonicalClientId
  await Promise.all([
    database.collection("oauthClient").deleteOne({ _id: clientMongoId }),
    database.collection("user_app_registrations").deleteMany({ clientId: canonicalClientId }),
    database.collection("oauthAccessToken").deleteMany({ clientId: canonicalClientId }),
    database.collection("oauthRefreshToken").deleteMany({ clientId: canonicalClientId }),
    database.collection("oauthAuthorizationCode").deleteMany({ clientId: canonicalClientId }),
    database.collection("oauthConsent").deleteMany({ clientId: canonicalClientId }),
    database.collection("oauth_token_families").deleteMany({ clientId: canonicalClientId }),
    database.collection("app_admins").deleteMany({ clientId: canonicalClientId }),
  ]);

  // Invalidate origin cache across Redis and MongoDB after database deletion (prevents races)
  await invalidateClientOrigins(existingClient, null);

  await recordAdminAudit({
    actorUserId: sessionUser?.id,
    actorEmail: sessionUser?.email,
    actorScope: sessionUser?.scopedClientId || "super_admin",
    action: "client_deleted",
    targetClientId: canonicalClientId,
    ipAddress: getTrustedClientIp(c),
    timestamp: new Date(),
  });

  return c.json({ success: true, message: "Client deleted successfully" });
}
