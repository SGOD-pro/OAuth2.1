/**
 * P5.4 Owner Privacy & Consumer Claim Filtering Policy.
 *
 * Versioned defaults (v1):
 * - shareEmail: true
 * - shareProfile: true
 *
 * Both the granted OAuth scope AND the owner's privacy preference must allow
 * a claim before it is emitted to a consumer application (id_token or userinfo).
 * Immutable `sub` and required protocol claims (`iss`, `aud`, `exp`, `iat`,
 * `nonce`, `at_hash`, `role`, `scoped_client_id`) are always preserved.
 */

export const PRIVACY_POLICY_VERSION = 1;

export interface OwnerPrivacyPreferences {
  privacyVersion: number;
  shareEmail: boolean;
  shareProfile: boolean;
}

export function resolveOwnerPrivacyPreferences(userDoc: any): OwnerPrivacyPreferences {
  return {
    privacyVersion:
      typeof userDoc?.privacyVersion === "number" ? userDoc.privacyVersion : PRIVACY_POLICY_VERSION,
    shareEmail: userDoc?.shareEmail !== false,
    shareProfile: userDoc?.shareProfile !== false,
  };
}

export function parseScopeSet(scope: string | string[] | undefined | null): Set<string> {
  if (Array.isArray(scope)) {
    return new Set(scope.map((s) => String(s).trim().toLowerCase()).filter(Boolean));
  }
  if (typeof scope === "string") {
    return new Set(
      scope
        .split(/\s+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
  }
  return new Set(["openid"]);
}

const EMAIL_CLAIMS = ["email", "email_verified"] as const;
const PROFILE_CLAIMS = [
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "updated_at",
] as const;

export function filterConsumerClaims<T extends Record<string, any>>(
  claims: T,
  scope: string | string[] | undefined | null,
  userDoc: any
): T {
  const scopeSet = parseScopeSet(scope);
  const prefs = resolveOwnerPrivacyPreferences(userDoc);
  const filtered: Record<string, any> = { ...claims };

  if (!scopeSet.has("email") || !prefs.shareEmail) {
    for (const key of EMAIL_CLAIMS) {
      delete filtered[key];
    }
  }

  if (!scopeSet.has("profile") || !prefs.shareProfile) {
    for (const key of PROFILE_CLAIMS) {
      delete filtered[key];
    }
  }

  return filtered as T;
}
