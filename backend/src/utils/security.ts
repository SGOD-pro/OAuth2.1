import crypto from "node:crypto";

export * from "./network-security";
export * from "./client-resolver";
export * from "./client-config-validator";
export * from "./app-access";

export function isStrongPassword(password: string): boolean {
  // Minimum 12 chars - must match emailAndPassword.minPasswordLength in auth.ts
  if (password.length < 12 || password.length > 128) return false;
  return (
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

/** Constant-time string compare for CSRF tokens (equal length required). */
export function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Detects whether an object or array contains dangerous MongoDB operator keys
 * (keys starting with '$'), dotted path keys (containing '.'), or prototype pollution keys.
 */
export function hasDangerousMongoKeys(input: any): boolean {
  if (!input || typeof input !== "object") return false;

  if (Array.isArray(input)) {
    for (const item of input) {
      if (hasDangerousMongoKeys(item)) return true;
    }
    return false;
  }

  for (const key of Object.keys(input)) {
    if (
      key.startsWith("$") ||
      key.includes(".") ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    ) {
      return true;
    }
    if (typeof input[key] === "object" && input[key] !== null) {
      if (hasDangerousMongoKeys(input[key])) return true;
    }
  }

  return false;
}

/**
 * Validates that an input is a safe non-empty primitive string without operator characters.
 */
export function validateSafePrimitiveString(
  val: any,
  fieldName: string = "parameter",
  options: { minLength?: number; maxLength?: number; allowEmpty?: boolean } = {}
): string | null {
  if (typeof val !== "string") {
    return null;
  }
  const trimmed = val.trim();
  if (!options.allowEmpty && trimmed.length === 0) {
    return null;
  }
  if (options.minLength && trimmed.length < options.minLength) {
    return null;
  }
  if (options.maxLength && trimmed.length > options.maxLength) {
    return null;
  }
  if (trimmed.startsWith("$") || trimmed.includes("\0")) {
    return null;
  }
  return trimmed;
}

/**
 * Computes a SHA-256 hash formatted as base64url or hex.
 * Centralizes token hash generation for OAuth credentials.
 */
export function hashToken(
  token: string,
  encoding: "base64url" | "hex" = "base64url",
): string {
  return crypto.createHash("sha256").update(token).digest(encoding);
}

/**
 * Detects whether a string is formatted like an email address.
 * Prevents email disclosure through user-provided name or display fields.
 */
export function isEmailShaped(val?: string | null): boolean {
  if (!val || typeof val !== "string") return false;
  const trimmed = val.trim();
  return trimmed.includes("@") && trimmed.includes(".") && !trimmed.includes(" ");
}

/**
 * Server-side privacy projection helper (Slice 2).
 * Formats user identifiers into approved privacy-preserving display labels.
 * Masks full email addresses and email-shaped name fields to prevent disclosure
 * in ordinary admin lists, search, export, and logs.
 */
export function toApprovedDisplayLabel(email?: string | null, name?: string | null): string {
  // If a legitimate human name is present (non-empty, not "user", and not email-shaped), return it
  if (name && name.trim().length > 0 && name.trim().toLowerCase() !== "user" && !isEmailShaped(name)) {
    return name.trim();
  }

  // If name was email-shaped, treat it as candidate email to mask
  const targetEmail = (email && isEmailShaped(email))
    ? email.trim()
    : (name && isEmailShaped(name) ? name.trim() : (email ? email.trim() : null));

  if (!targetEmail || !targetEmail.includes("@")) {
    return "User";
  }

  const [local, domain] = targetEmail.split("@");
  if (local.length <= 2) {
    return `${local[0] || "*"}***@${domain || ""}`;
  }
  return `${local.slice(0, 2)}***@${domain || ""}`;
}

/**
 * Escapes special regular expression characters to prevent injection and catastrophic backtracking.
 */
export function escapeRegex(val: string): string {
  return val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
