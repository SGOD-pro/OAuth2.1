import crypto from "node:crypto";
import { ObjectId, type Db } from "mongodb";
import { ensureIdentityCollectionIndexes } from "../db/indexes";
import { digestToken } from "./registration-crypto";

export interface AppInvitationDoc {
  inviteId: string;
  tokenDigest: string;
  clientId: string;
  targetEmail: string;
  inviterUserId: string;
  inviterRole: string;
  roleCeiling: "user" | "app-admin";
  status: "pending" | "claimed" | "revoked";
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date | null;
  claimedAt?: Date | null;
  claimedByUserId?: string | null;
}

export class InvitationError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) {
    super(message);
  }
}

export interface LocalMailSinkMessage {
  to: string;
  clientId: string;
  inviteId: string;
  rawToken: string;
  roleCeiling: "user" | "app-admin";
}

const localInviteMailSink: LocalMailSinkMessage[] = [];

export function getLocalInviteMailSink(): LocalMailSinkMessage[] {
  return localInviteMailSink;
}

export function clearLocalInviteMailSink(): void {
  localInviteMailSink.length = 0;
}

export async function issuePrivateAppInvitation(params: {
  database: Db;
  clientId: string;
  targetEmail: string;
  roleCeiling?: string;
  inviterUserId: string;
  inviterRole: string;
  ttlSeconds?: number;
}): Promise<{ inviteId: string; rawToken: string; clientId: string; targetEmail: string; roleCeiling: "user" | "app-admin"; expiresAt: Date }> {
  const { database, clientId, inviterUserId, inviterRole } = params;
  await ensureIdentityCollectionIndexes(database);

  const roleCeiling = (params.roleCeiling || "user").trim();
  if (roleCeiling !== "user" && roleCeiling !== "app-admin") {
    throw new InvitationError("ERR_INVALID_ROLE_CEILING", 400, "Invitations only support user or app-admin role ceilings");
  }
  if (inviterRole === "app-admin" && roleCeiling !== "user") {
    throw new InvitationError("ERR_ROLE_CEILING_EXCEEDED", 403, "App admins can only issue ordinary user invitations");
  }

  const clientDoc = await database.collection("oauthClient").findOne({ $or: [{ clientId }, { id: clientId }] });
  if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
    throw new InvitationError("ERR_INVALID_CLIENT", 404, "Client application not found or disabled");
  }
  const isPrivate = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
  if (!isPrivate) {
    throw new InvitationError("ERR_CLIENT_NOT_PRIVATE", 400, "Invitations are only supported for private applications");
  }

  const targetEmail = params.targetEmail.trim().toLowerCase();
  if (!targetEmail || !targetEmail.includes("@")) {
    throw new InvitationError("ERR_INVALID_EMAIL", 400, "Valid target email is required");
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + (params.ttlSeconds ?? 7 * 24 * 3600) * 1000);
  const inviteId = crypto.randomUUID();
  const rawToken = crypto.randomBytes(32).toString("base64url");

  const doc: AppInvitationDoc = {
    inviteId,
    tokenDigest: digestToken(rawToken),
    clientId: clientDoc.clientId,
    targetEmail,
    inviterUserId,
    inviterRole,
    roleCeiling,
    status: "pending",
    createdAt: now,
    expiresAt,
    revokedAt: null,
    claimedAt: null,
    claimedByUserId: null,
  };
  await database.collection<AppInvitationDoc>("app_invitations").insertOne(doc);

  localInviteMailSink.push({
    to: targetEmail,
    clientId: clientDoc.clientId,
    inviteId,
    rawToken,
    roleCeiling,
  });

  return { inviteId, rawToken, clientId: clientDoc.clientId, targetEmail, roleCeiling, expiresAt };
}

export async function revokePrivateAppInvitation(params: {
  database: Db;
  clientId: string;
  inviteId: string;
}): Promise<{ revoked: boolean }> {
  const res = await params.database.collection<AppInvitationDoc>("app_invitations").findOneAndUpdate(
    { inviteId: params.inviteId, clientId: params.clientId, status: "pending" },
    { $set: { status: "revoked", revokedAt: new Date() } },
    { returnDocument: "after" }
  );
  return { revoked: Boolean(res) };
}

export async function claimPrivateAppInvitation(params: {
  database: Db;
  rawToken: string;
  userId: string;
  userEmail: string;
  emailVerified: boolean;
}): Promise<{ clientId: string; roleCeiling: "user" | "app-admin"; userId: string }> {
  const { database, rawToken, userId, userEmail, emailVerified } = params;
  if (!emailVerified) {
    throw new InvitationError("ERR_MAILBOX_PROOF_REQUIRED", 403, "Verified mailbox proof is required before claiming an invitation");
  }
  const normalizedEmail = userEmail.trim().toLowerCase();
  const tokenDigest = digestToken(rawToken.trim());
  const now = new Date();

  const claimed = await database.collection<AppInvitationDoc>("app_invitations").findOneAndUpdate(
    {
      tokenDigest,
      status: "pending",
      expiresAt: { $gt: now },
      targetEmail: normalizedEmail,
    },
    {
      $set: {
        status: "claimed",
        claimedAt: now,
        claimedByUserId: userId,
      },
    },
    { returnDocument: "after" }
  );

  if (!claimed) {
    const existing = await database.collection<AppInvitationDoc>("app_invitations").findOne({ tokenDigest });
    if (existing && existing.targetEmail !== normalizedEmail) {
      throw new InvitationError("ERR_INVITE_MAILBOX_MISMATCH", 403, "Invitation is bound to a different mailbox");
    }
    throw new InvitationError("ERR_INVITE_INVALID_OR_EXPIRED", 409, "Invitation is invalid, expired, revoked, or already claimed");
  }

  if (claimed.roleCeiling === "user") {
    await database.collection("user_app_registrations").updateOne(
      { userId, clientId: claimed.clientId },
      { $setOnInsert: { userId, clientId: claimed.clientId, registeredAt: now, invitedBy: claimed.inviterUserId } },
      { upsert: true }
    );
  } else if (claimed.roleCeiling === "app-admin") {
    const userFilters: any[] = [{ id: userId }, { _id: userId }];
    if (ObjectId.isValid(userId)) userFilters.push({ _id: new ObjectId(userId) });
    await database.collection("user").updateOne(
      { $or: userFilters },
      { $set: { role: "app-admin", scopedClientId: claimed.clientId } }
    );
  }

  return { clientId: claimed.clientId, roleCeiling: claimed.roleCeiling, userId };
}
