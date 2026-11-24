import crypto from "crypto";
import type { Db } from "mongodb";

// S256 challenge must be 43 characters base64url (RFC 7636 Section 4.1 & 4.2: BASE64URL(SHA256(verifier)))
const PKCE_S256_CHALLENGE_REGEX = /^[A-Za-z0-9_-]{43}$/;

// Verifier must be 43-128 characters from unreserved charset (RFC 7636 Section 4.1)
const PKCE_VERIFIER_REGEX = /^[A-Za-z0-9_.~-]{43,128}$/;

export interface PkceValidationResult {
  valid: boolean;
  challenge?: string;
  method?: "S256";
  error?: string;
  description?: string;
}

/**
 * Validates PKCE parameters on the authorization endpoint (/oauth2/authorize).
 * Enforces mandatory S256 code challenge for both public and confidential clients.
 */
export function validatePkceAuthorizationParams(params: {
  codeChallenge?: string | null;
  codeChallengeMethod?: string | null;
  responseType?: string | null;
}): PkceValidationResult {
  const { codeChallenge, codeChallengeMethod, responseType } = params;

  // Authorization code grant flows (response_type=code or unset default)
  if (responseType && responseType !== "code") {
    return { valid: true };
  }

  if (!codeChallenge || codeChallenge.trim() === "") {
    return {
      valid: false,
      error: "invalid_request",
      description: "code_challenge is required for authorization code flow",
    };
  }

  if (!codeChallengeMethod || codeChallengeMethod.toUpperCase() !== "S256") {
    return {
      valid: false,
      error: "invalid_request",
      description: "Invalid code_challenge_method: only S256 is supported",
    };
  }

  if (!PKCE_S256_CHALLENGE_REGEX.test(codeChallenge)) {
    return {
      valid: false,
      error: "invalid_request",
      description: "Invalid code_challenge syntax: must be 43 base64url characters for S256",
    };
  }

  return {
    valid: true,
    challenge: codeChallenge,
    method: "S256",
  };
}

/**
 * Validates PKCE verifier syntax on token exchange.
 */
export function validatePkceVerifier(verifier?: string | null): {
  valid: boolean;
  error?: string;
  description?: string;
} {
  if (!verifier || verifier.trim() === "") {
    return {
      valid: false,
      error: "invalid_request",
      description: "code_verifier is required",
    };
  }

  if (!PKCE_VERIFIER_REGEX.test(verifier)) {
    return {
      valid: false,
      error: "invalid_request",
      description: "Invalid code_verifier syntax: must be 43-128 unreserved characters",
    };
  }

  return { valid: true };
}

/**
 * Computes S256 challenge for a given code verifier.
 */
export function computeS256Challenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Verifies that a code verifier matches a stored code challenge.
 */
export function verifyPkce(verifier: string, storedChallenge: string): boolean {
  const computed = computeS256Challenge(verifier);
  try {
    const computedBuf = Buffer.from(computed);
    const storedBuf = Buffer.from(storedChallenge);
    if (computedBuf.length !== storedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(computedBuf, storedBuf);
  } catch {
    return false;
  }
}

export interface BindAuthorizationCodeParams {
  code: string; clientId: string; redirectUri: string;
  codeChallenge?: string | null; codeChallengeMethod?: string | null;
  userId?: string | null; tokenVersion?: number | null;
  transactionId?: string | null; ttlSeconds?: number;
  clientType?: string; clientCredentialVersion?: number;
}

/**
 * Binds an issued authorization code with its PKCE challenge and transaction context.
 */
export async function bindAuthorizationCode(
  db: Db,
  params: BindAuthorizationCodeParams
): Promise<void> {
  const ttl = params.ttlSeconds ?? 600;
  const expiresAt = new Date(Date.now() + ttl * 1000);
  const updateDoc: any = {
    code: params.code,
    clientId: params.clientId,
    redirectUri: params.redirectUri,
    codeChallenge: params.codeChallenge || undefined,
    codeChallengeMethod: params.codeChallengeMethod || "S256",
    userId: params.userId || undefined,
    tokenVersion: typeof params.tokenVersion === "number" ? params.tokenVersion : 1,
    transactionId: params.transactionId || undefined,
    clientType: params.clientType || undefined,
    clientCredentialVersion: typeof params.clientCredentialVersion === "number" ? params.clientCredentialVersion : undefined,
    status: "pending",
    updatedAt: new Date(),
  };

  await db.collection("oauthAuthorizationCode").updateOne(
    { code: params.code },
    {
      $set: updateDoc,
      $setOnInsert: { createdAt: new Date(), expiresAt },
    },
    { upsert: true }
  );
}

export interface CodeConsumptionResult {
  success: boolean; status: number; error?: string;
  description?: string; codeDoc?: any; replayFamilyId?: string | null;
}

async function burnCode(db: Db, code: string): Promise<void> {
  await db.collection("oauthAuthorizationCode").updateOne(
    { code },
    { $set: { status: "consumed", consumedAt: new Date() } }
  );
  await db.collection("verification").deleteOne({
    $or: [{ identifier: code }, { value: new RegExp(code) }],
  }).catch(() => {});
}

/**
 * Verifies PKCE verifier, bindings, and atomically consumes authorization code.
 */
export async function verifyAndConsumeAuthorizationCode(
  db: Db,
  params: {
    code: string; clientId: string;
    redirectUri?: string | null; codeVerifier?: string | null;
  }
): Promise<CodeConsumptionResult> {
  const { code, clientId, redirectUri, codeVerifier } = params;

  // 1. Validate code_verifier presence and syntax
  const verifierCheck = validatePkceVerifier(codeVerifier);
  if (!verifierCheck.valid) {
    return {
      success: false,
      status: 400,
      error: verifierCheck.error!,
      description: verifierCheck.description!,
    };
  }

  // 2. Locate authorization code
  const existing = await db.collection("oauthAuthorizationCode").findOne({ code });
  if (!existing) {
    return { success: true, status: 200 };
  }

  // 3. Replay detection: check if already consumed
  if (existing.status === "consumed" || existing.consumedAt) {
    if (existing.familyId) {
      await db.collection("oauth_token_families").updateOne(
        { familyId: existing.familyId },
        {
          $set: {
            status: "revoked",
            revokedAt: new Date(),
            revokedReason: "code_replayed",
          },
        }
      );
    }
    return {
      success: false,
      status: 400,
      error: "invalid_grant",
      description: "Authorization code has already been consumed",
      replayFamilyId: existing.familyId || null,
    };
  }

  // 4. Expiration check
  if (existing.expiresAt && new Date(existing.expiresAt).getTime() < Date.now()) {
    return {
      success: false,
      status: 400,
      error: "invalid_grant",
      description: "Authorization code has expired",
    };
  }

  // 5. Client binding check (RFC 6749 Section 4.1.3)
  if (existing.clientId && existing.clientId !== clientId) {
    await burnCode(db, code);
    return {
      success: false,
      status: 400,
      error: "invalid_grant",
      description: "Authorization code was issued to a different client",
    };
  }

  // 6. Redirect URI binding check (RFC 6749 Section 4.1.3)
  if (existing.redirectUri && redirectUri && existing.redirectUri !== redirectUri) {
    await burnCode(db, code);
    return {
      success: false,
      status: 400,
      error: "invalid_grant",
      description: "redirect_uri mismatch with authorization request",
    };
  }

  // 7. PKCE verifier match check (OAuth 2.1 Section 4.1.1 & RFC 7636)
  if (existing.codeChallenge) {
    const isMatch = verifyPkce(codeVerifier!, existing.codeChallenge);
    if (!isMatch) {
      await burnCode(db, code);
      return {
        success: false,
        status: 400,
        error: "invalid_grant",
        description: "Invalid code_verifier: PKCE verification failed",
      };
    }
  }

  // 8. Atomic single-use consumption
  const consumed: any = await db.collection("oauthAuthorizationCode").findOneAndUpdate(
    { code, status: { $ne: "consumed" } },
    {
      $set: {
        status: "consumed",
        consumedAt: new Date(),
      },
    },
    { returnDocument: "after" }
  );

  const updatedDoc = consumed && (consumed.value !== undefined ? consumed.value : consumed);
  if (!updatedDoc) {
    return {
      success: false,
      status: 400,
      error: "invalid_grant",
      description: "Authorization code has already been consumed",
    };
  }

  return {
    success: true,
    status: 200,
    codeDoc: updatedDoc,
  };
}
