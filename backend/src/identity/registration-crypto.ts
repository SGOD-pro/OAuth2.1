import crypto from "node:crypto";
import { config } from "../config";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$/;

function deriveKey(secretRef: string, domain: string, lengthBytes = 32): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", Buffer.from(secretRef, "utf8"), Buffer.from("swyra-p2a-v2", "utf8"), Buffer.from(domain, "utf8"), lengthBytes));
}

export function normalizeRegistrationEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  if (/[\r\n\0\t]/.test(raw)) return null;
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed || trimmed.length > 254 || !EMAIL_RE.test(trimmed)) return null;
  return trimmed;
}

export function computeEmailLookup(normalizedEmail: string): string {
  const key = deriveKey(config.identity.lookupKeyRef, "email-lookup-v1");
  return crypto.createHmac("sha256", key).update(`lookup:${normalizedEmail}`).digest("hex");
}

export function normalizeUsername(raw: unknown): { display: string; normalized: string } | null {
  if (typeof raw !== "string") return null;
  if (/[\r\n\0\t]/.test(raw)) return null;
  const display = raw.trim();
  if (!display || display.includes("@") || display.includes("..") || display.endsWith(".") || !USERNAME_RE.test(display)) {
    return null;
  }
  return { display, normalized: display.toLowerCase() };
}

export function computeUsernameLookup(normalizedUsername: string): string {
  const key = deriveKey(config.identity.lookupKeyRef, "username-lookup-v1");
  return crypto.createHmac("sha256", key).update(`username:${normalizedUsername}`).digest("hex");
}

export function computeBrowserBindingHash(rawCookie: string): string {
  return crypto.createHash("sha256").update(`reg-browser:${rawCookie}`).digest("hex");
}

export function generateOtpCode(): string {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
}

export function computeOtpVerifier(params: {
  purpose: string;
  intentId: string;
  generation: number;
  emailLookup: string;
  code: string;
}): string {
  const key = deriveKey(config.identity.otpVerifierKeyRef, "otp-verifier-v1");
  const framing = JSON.stringify([params.purpose, params.intentId, params.generation, params.emailLookup, params.code]);
  return crypto.createHmac("sha256", key).update(framing).digest("hex");
}

export function verifyOtpVerifier(
  expectedHex: string,
  params: { purpose: string; intentId: string; generation: number; emailLookup: string; code: string }
): boolean {
  const candidate = computeOtpVerifier(params);
  const a = Buffer.from(expectedHex, "hex");
  const b = Buffer.from(candidate, "hex");
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

export function digestToken(rawToken: string, domain = "proof"): string {
  const key = deriveKey(config.identity.otpVerifierKeyRef, `token-digest-${domain}`);
  return crypto.createHmac("sha256", key).update(rawToken).digest("hex");
}

export function verifyTokenDigest(rawToken: string, expectedHex: string, domain = "proof"): boolean {
  const candidate = digestToken(rawToken, domain);
  const a = Buffer.from(expectedHex, "hex");
  const b = Buffer.from(candidate, "hex");
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

export interface EncryptedMailEnvelope {
  v: 1;
  iv: string;
  tag: string;
  ct: string;
}

export interface OutboxMailPlaintext {
  email: string;
  code: string;
  purpose: string;
  templateVersion: string;
  requestContext: string;
  expiresMinutes: number;
}

export function encryptMailPayload(
  payload: OutboxMailPlaintext,
  aadContext: { jobId: string; generation: number; purpose: string }
): EncryptedMailEnvelope {
  const key = deriveKey(config.identity.mailPayloadKeyRef, "mail-outbox-aead-v1");
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(JSON.stringify([aadContext.purpose, aadContext.jobId, aadContext.generation]));
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ct: ct.toString("base64url"),
  };
}

export function decryptMailPayload(
  envelope: EncryptedMailEnvelope,
  aadContext: { jobId: string; generation: number; purpose: string }
): OutboxMailPlaintext {
  const key = deriveKey(config.identity.mailPayloadKeyRef, "mail-outbox-aead-v1");
  const aad = Buffer.from(JSON.stringify([aadContext.purpose, aadContext.jobId, aadContext.generation]));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const pt = Buffer.concat([decipher.update(Buffer.from(envelope.ct, "base64url")), decipher.final()]);
  return JSON.parse(pt.toString("utf8")) as OutboxMailPlaintext;
}

export function encryptContactEmail(email: string, ctx: { intentId: string; emailLookup: string }): EncryptedMailEnvelope {
  const key = deriveKey(config.identity.mailPayloadKeyRef, "intent-contact-aead-v1");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify([ctx.intentId, ctx.emailLookup])));
  const ct = Buffer.concat([cipher.update(email, "utf8"), cipher.final()]);
  return { v: 1, iv: iv.toString("base64url"), tag: cipher.getAuthTag().toString("base64url"), ct: ct.toString("base64url") };
}

export function decryptContactEmail(envelope: EncryptedMailEnvelope, ctx: { intentId: string; emailLookup: string }): string {
  const key = deriveKey(config.identity.mailPayloadKeyRef, "intent-contact-aead-v1");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
  decipher.setAAD(Buffer.from(JSON.stringify([ctx.intentId, ctx.emailLookup])));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const pt = Buffer.concat([decipher.update(Buffer.from(envelope.ct, "base64url")), decipher.final()]);
  return pt.toString("utf8");
}
