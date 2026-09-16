import crypto from "crypto";
import { config } from "../config";

// RFC 4648 Base32 alphabet
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Encode a buffer to a Base32 string (unpadded, RFC 4648)
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decode a Base32 string to a Buffer
 */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/[\s-]/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) {
      throw new Error(`Invalid base32 character: ${clean[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generate a random 160-bit (20 bytes) Base32 secret for TOTP (RFC 6238)
 */
export function generateTotpSecret(bytes = 20): string {
  return base32Encode(crypto.randomBytes(bytes));
}

/**
 * Generate an RFC 6238 TOTP code (HMAC-SHA1, 6 digits, 30-sec step)
 */
export function generateTotpCode(secretBase32: string, timeStep = 30, time = Date.now()): string {
  const counter = Math.floor(time / 1000 / timeStep);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter), 0);

  const key = base32Decode(secretBase32);
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

/**
 * Verify a 6-digit TOTP code with time-drift window (default +/- 1 step = 30s)
 */
export function verifyTotpCode(code: string, secretBase32: string, window = 1): boolean {
  if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }

  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    const expected = generateTotpCode(secretBase32, 30, now + i * 30000);
    const bufCode = Buffer.from(code);
    const bufExpected = Buffer.from(expected);
    if (bufCode.length === bufExpected.length && crypto.timingSafeEqual(bufCode, bufExpected)) {
      return true;
    }
  }

  return false;
}

/**
 * Generate an otpauth:// URI for authenticator apps (Google / Microsoft Authenticator)
 */
export function generateOtpAuthUri(email: string, appName: string, secretBase32: string): string {
  const issuer = encodeURIComponent(appName || "OAuth 2.1");
  const account = encodeURIComponent(email);
  return `otpauth://totp/${issuer}:${account}?secret=${secretBase32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Generate 8 random backup codes (10 hex characters each)
 */
export function generateBackupCodes(count = 8): { raw: string[]; hashed: string[] } {
  const raw: string[] = [];
  const hashed: string[] = [];

  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(5).toString("hex").toUpperCase();
    const formatted = `${code.slice(0, 5)}-${code.slice(5)}`;
    raw.push(formatted);
    const hash = crypto.createHash("sha256").update(formatted).digest("hex");
    hashed.push(hash);
  }

  return { raw, hashed };
}

/**
 * Check if a code matches an unused backup code hash
 */
export function verifyBackupCode(rawCode: string, hashedCodes: string[]): { valid: boolean; remaining: string[] } {
  if (!rawCode || !hashedCodes || hashedCodes.length === 0) {
    return { valid: false, remaining: hashedCodes || [] };
  }

  const normalized = rawCode.trim().toUpperCase();
  const targetHash = crypto.createHash("sha256").update(normalized).digest("hex");

  const matchIdx = hashedCodes.findIndex((h) => {
    const bufA = Buffer.from(h);
    const bufB = Buffer.from(targetHash);
    return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
  });

  if (matchIdx !== -1) {
    const remaining = [...hashedCodes];
    remaining.splice(matchIdx, 1);
    return { valid: true, remaining };
  }

  return { valid: false, remaining: hashedCodes };
}

// Derive a 256-bit AES-GCM encryption key. In production, APP_ADMIN_TOTP_KEY is required.
function getEncryptionKey(): Buffer {
  const explicit = process.env.APP_ADMIN_TOTP_KEY;
  if (explicit && explicit.length >= 32) {
    return crypto.createHash("sha256").update(explicit).digest();
  }
  if (config.env === "production") {
    throw new Error("APP_ADMIN_TOTP_KEY must be explicitly configured in production (minimum 32 characters)");
  }
  const source = config.appAdminTotpKey;
  return crypto.createHash("sha256").update(source).digest();
}

/**
 * Encrypt sensitive TOTP secret at rest using AES-256-GCM
 */
export function encryptTotpSecret(plainSecret: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(plainSecret, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");

  // Format: iv:authTag:cipherHex
  return `${iv.toString("hex")}:${authTag}:${encrypted}`;
}

/**
 * Decrypt sensitive TOTP secret using AES-256-GCM
 */
export function decryptTotpSecret(encryptedString: string): string {
  const parts = encryptedString.split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted TOTP secret payload");
  }

  const [ivHex, authTagHex, cipherHex] = parts;
  const key = getEncryptionKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

  let decrypted = decipher.update(cipherHex, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}
