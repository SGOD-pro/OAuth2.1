import { config } from "../config";

export interface AccountEligibilityResult {
  eligible: boolean;
  reason?:
    | "user_not_found"
    | "account_banned"
    | "account_disabled"
    | "account_inactive"
    | "account_deleting"
    | "account_deleted"
    | "email_not_verified"
    | "tokens_revoked";
}

/**
 * Authoritative Account Eligibility Policy for SWYRA Auth.
 *
 * Applies uniformly across:
 * - Authorization code issuance (/oauth2/authorize)
 * - Code exchange & token minting (/oauth2/token)
 * - Refresh token rotation (/oauth2/token)
 * - UserInfo claims release (/oauth2/userinfo)
 * - Token Introspection (/oauth2/introspect, both plugin and JWT branches)
 * - Administrative and management authentication
 *
 * Invariants:
 * 1. Account must exist.
 * 2. Account must not be banned (banned === true).
 * 3. Account must not be disabled (disabled === true).
 * 4. Account must not be inactive (isActive === false or status === "inactive").
 * 5. Account must not be in deleting or deleted state (status === "deleting" | "deleted" or deletedAt set).
 * 6. Email verification enforced when required by active policy. Existing unverified accounts cannot bypass.
 * 7. Token issuance or refresh cannot survive account revocation (tokensRevokedBefore / passwordChangedAt).
 */
export function checkAccountEligibility(
  user: any,
  options?: {
    requireEmailVerified?: boolean;
    tokenIssuedAtSec?: number;
  }
): AccountEligibilityResult {
  if (!user) {
    return { eligible: false, reason: "user_not_found" };
  }

  if (user.banned === true) {
    return { eligible: false, reason: "account_banned" };
  }

  if (user.disabled === true) {
    return { eligible: false, reason: "account_disabled" };
  }

  if (user.isActive === false || user.status === "inactive") {
    return { eligible: false, reason: "account_inactive" };
  }

  if (user.status === "deleting") {
    return { eligible: false, reason: "account_deleting" };
  }

  if (user.deletedAt || user.status === "deleted") {
    return { eligible: false, reason: "account_deleted" };
  }

  const requireEmail =
    options?.requireEmailVerified ?? (config.auth.emailVerificationEnabled === true);
  if (requireEmail && user.emailVerified !== true) {
    // Safe Rollout Support:
    // To safely activate verification without bricking existing unverified accounts before email delivery is active,
    // operators can configure AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE="enforce_new" and AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER=<ISO date>.
    // Accounts created prior to that date are granted a temporary grace period, while all newly created accounts fail closed.
    // Existing accounts are NEVER marked emailVerified=true in DB to bypass migration.
    const rolloutMode = process.env.AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE || "enforce_all";
    const enforcedAfter = process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER
      ? new Date(process.env.AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER).getTime()
      : null;

    let inGraceWindow = false;
    if (rolloutMode === "enforce_new" && enforcedAfter && user.createdAt) {
      const userCreatedMs = new Date(user.createdAt).getTime();
      if (userCreatedMs < enforcedAfter) {
        // Eligible under rollout grace window for email verification only.
        // DO NOT return early: execution MUST continue to revocation, password-change,
        // and token-lifecycle checks below.
        inGraceWindow = true;
      }
    }

    if (!inGraceWindow) {
      return { eligible: false, reason: "email_not_verified" };
    }
  }

  if (options?.tokenIssuedAtSec !== undefined) {
    if (user.tokensRevokedBefore) {
      const revokedSec = Math.floor(
        new Date(user.tokensRevokedBefore).getTime() / 1000
      );
      if (options.tokenIssuedAtSec < revokedSec) {
        return { eligible: false, reason: "tokens_revoked" };
      }
    }

    if (user.passwordChangedAt) {
      const pwdSec = Math.floor(
        new Date(user.passwordChangedAt).getTime() / 1000
      );
      if (options.tokenIssuedAtSec < pwdSec) {
        return { eligible: false, reason: "tokens_revoked" };
      }
    }
  }

  return { eligible: true };
}
