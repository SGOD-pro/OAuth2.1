import { ObjectId } from "mongodb";
import { resolveOwnerPrivacyPreferences } from "./claim-policy";

export const EXPORT_POLICY_VERSION = 1;
export const DEFAULT_MAX_GRANTS = 50;
export const DEFAULT_MAX_SECURITY_EVENTS = 50;

export interface OwnerExportBounds {
  maxGrants: number;
  maxSecurityEvents: number;
  grantsTruncated: boolean;
  securityEventsTruncated: boolean;
}

export interface OwnerExportPayload {
  exportVersion: number;
  generatedAt: string;
  ownerUserId: string;
  profile: {
    userId: string;
    username: string | null;
    name: string;
    email: string;
    emailVerified: boolean;
    createdAt: string | null;
    updatedAt: string | null;
  };
  preferences: {
    privacyVersion: number;
    shareEmail: boolean;
    shareProfile: boolean;
  };
  grants: Array<{
    clientId: string;
    scopes: string[];
    grantedAt: string | null;
  }>;
  securityHistory: Array<{
    action: string;
    outcome: string | null;
    clientId: string | null;
    createdAt: string | null;
  }>;
  bounds: OwnerExportBounds;
  omittedCategories: string[];
}

export async function prepareOwnerExport(
  database: any,
  ownerUserId: string,
  options: { maxGrants?: number; maxSecurityEvents?: number } = {}
): Promise<OwnerExportPayload | null> {
  if (!ownerUserId || !ObjectId.isValid(ownerUserId)) {
    return null;
  }

  const maxGrants = Math.max(1, Math.min(options.maxGrants ?? DEFAULT_MAX_GRANTS, 200));
  const maxSecurityEvents = Math.max(
    1,
    Math.min(options.maxSecurityEvents ?? DEFAULT_MAX_SECURITY_EVENTS, 200)
  );

  const userDoc = await database.collection("user").findOne({ _id: new ObjectId(ownerUserId) });
  if (!userDoc) {
    return null;
  }

  const prefs = resolveOwnerPrivacyPreferences(userDoc);

  const rawGrants = await database
    .collection("oauthConsent")
    .find({ userId: ownerUserId })
    .sort({ createdAt: -1 })
    .limit(maxGrants + 1)
    .toArray();
  const grantsTruncated = rawGrants.length > maxGrants;
  const grants = rawGrants.slice(0, maxGrants).map((g: any) => ({
    clientId: String(g.clientId || ""),
    scopes: Array.isArray(g.scopes) ? g.scopes.map((s: any) => String(s)) : [],
    grantedAt: g.createdAt instanceof Date ? g.createdAt.toISOString() : null,
  }));

  const rawEvents = await database
    .collection("auth_events")
    .find({ userId: ownerUserId })
    .sort({ createdAt: -1 })
    .limit(maxSecurityEvents + 1)
    .toArray();
  const securityEventsTruncated = rawEvents.length > maxSecurityEvents;
  const securityHistory = rawEvents.slice(0, maxSecurityEvents).map((e: any) => ({
    action: String(e.eventType || e.action || "auth_event"),
    outcome: e.outcome ? String(e.outcome) : null,
    clientId: e.clientId ? String(e.clientId) : null,
    createdAt: e.createdAt instanceof Date ? e.createdAt.toISOString() : null,
  }));

  return {
    exportVersion: EXPORT_POLICY_VERSION,
    generatedAt: new Date().toISOString(),
    ownerUserId,
    profile: {
      userId: ownerUserId,
      username: userDoc.username ?? null,
      name: String(userDoc.name || ""),
      email: String(userDoc.email || ""),
      emailVerified: Boolean(userDoc.emailVerified),
      createdAt: userDoc.createdAt instanceof Date ? userDoc.createdAt.toISOString() : null,
      updatedAt: userDoc.updatedAt instanceof Date ? userDoc.updatedAt.toISOString() : null,
    },
    preferences: {
      privacyVersion: prefs.privacyVersion,
      shareEmail: prefs.shareEmail,
      shareProfile: prefs.shareProfile,
    },
    grants,
    securityHistory,
    bounds: {
      maxGrants,
      maxSecurityEvents,
      grantsTruncated,
      securityEventsTruncated,
    },
    omittedCategories: [
      "passwords",
      "recovery_secrets",
      "raw_tokens",
      "encryption_keys",
      "other_accounts",
      "operator_notes",
    ],
  };
}
