import crypto from "node:crypto";
import type { Context } from "hono";
import { getDb } from "../db/mongo";
import { ensureTtlIndexes } from "../db/indexes";
import { config } from "../config";
import { timingSafeEqualStr } from "../utils/security";

const MAX_SKEW_SECONDS = 300;
const ALLOWED_PURPOSES = new Set(["registration", "contact_change", "password_reset"]);

/**
 * Verifies authenticated mail provider delivery/bounce/complaint callbacks
 * and durably records hard bounces and complaints into mail_suppressions.
 */
export async function handleMailCallback(c: Context): Promise<Response> {
  const requestId = (c.get("requestId" as never) as string) || crypto.randomUUID();
  const tsHeader = c.req.header("x-mail-timestamp");
  const nonceHeader = c.req.header("x-mail-nonce");
  const sigHeader = c.req.header("x-mail-signature");

  if (!tsHeader || !nonceHeader || !sigHeader) {
    return c.json({ error: "unauthorized", code: "ERR_MISSING_SIGNATURE", requestId }, 401);
  }

  const tsSec = Number(tsHeader);
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(tsSec) || Math.abs(nowSec - tsSec) > MAX_SKEW_SECONDS) {
    return c.json({ error: "unauthorized", code: "ERR_TIMESTAMP_SKEW", requestId }, 401);
  }

  const rawBody = await c.req.raw.clone().text().catch(() => "");
  const bodyHash = crypto.createHash("sha256").update(rawBody).digest("hex");
  const expectedSig = crypto
    .createHmac("sha256", config.identity.mailWebhookKeyRef)
    .update(`${tsHeader}.${nonceHeader}.${bodyHash}`)
    .digest("hex");

  if (!timingSafeEqualStr(sigHeader, expectedSig)) {
    return c.json({ error: "unauthorized", code: "ERR_INVALID_SIGNATURE", requestId }, 401);
  }

  let parsed: any;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return c.json({ error: "invalid_request", code: "ERR_MALFORMED_JSON", requestId }, 400);
  }

  const eventId = typeof parsed?.eventId === "string" ? parsed.eventId.trim() : "";
  const type = typeof parsed?.type === "string" ? parsed.type : "";
  const providerMessageId = typeof parsed?.providerMessageId === "string" ? parsed.providerMessageId.trim() : "";
  const purpose = typeof parsed?.purpose === "string" ? parsed.purpose : "";

  if (!eventId || !providerMessageId || !ALLOWED_PURPOSES.has(purpose)) {
    return c.json({ error: "invalid_request", code: "ERR_INVALID_EVENT", requestId }, 400);
  }

  await ensureTtlIndexes();
  const database = await getDb();

  try {
    await database.collection("mail_callback_events").insertOne({
      eventId,
      receivedAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });
  } catch (err: any) {
    if (err?.code === 11000) {
      return c.json({ error: "conflict", code: "ERR_EVENT_REPLAY", requestId }, 409);
    }
    throw err;
  }

  const outboxDoc = await database.collection("mail_outbox").findOne({
    providerMessageId,
    purpose,
  });
  if (!outboxDoc) {
    return c.json({ received: true, recorded: false, requestId }, 200);
  }

  const isHardBounce = type === "bounce" && parsed?.bounceType !== "transient";
  const isComplaint = type === "complaint";
  if (isHardBounce || isComplaint) {
    await database.collection("mail_suppressions").updateOne(
      { emailLookup: outboxDoc.emailLookup },
      {
        $set: {
          emailLookup: outboxDoc.emailLookup,
          active: true,
          reason: isComplaint ? "complaint" : "hard_bounce",
          updatedAt: new Date(),
        },
        $setOnInsert: { createdAt: new Date() },
      },
      { upsert: true }
    );
  }

  return c.json({ received: true, recorded: true, suppressed: isHardBounce || isComplaint, requestId }, 200);
}
