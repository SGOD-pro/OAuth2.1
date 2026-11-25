import type { Db } from "mongodb";
import { authProvider } from "../utils/auth";
import { config } from "../config";
import { checkAccountEligibility } from "../utils/account-eligibility";
import { checkUserHasAppAccess, resolveOAuthClient } from "../utils/security";
import { bindOAuthTransactionSelection, getOAuthTransaction, type OAuthTransactionDoc } from "../db/oauth-transactions";
import { findActiveBrowserSet, getBrowserSessionCookieName, listBrowserSetEntriesWithLiveStatus } from "./browser-session-registry";
import { dispatchRequestWithBrowserEntry, resolveVerifiedBrowserEntry } from "./session-adapter";
import { finalizeAuthorizeCodeWithFence, purgeAuthorizationCodeOnCommitFailure } from "../routes/auth-token-linearize";

export async function evaluateAuthorizeChooserRedirect(params: {
  database: Db;
  rawBrowserProof: string | undefined;
  transactionId: string;
  client: any;
  redirectUri: string;
  state: string;
  promptTokens: string[];
  query: Record<string, string | undefined>;
  hasAmbientSession: boolean;
}): Promise<string | null> {
  const { database, rawBrowserProof, transactionId, client, redirectUri, state, promptTokens, query, hasAmbientSession } = params;
  if (promptTokens.includes("none")) {
    if (promptTokens.length > 1) {
      const u = new URL(redirectUri);
      u.searchParams.set("error", "invalid_request");
      u.searchParams.set("error_description", "prompt=none cannot be combined with other prompt values");
      u.searchParams.set("state", state);
      return u.toString();
    }
    const set = await listBrowserSetEntriesWithLiveStatus(database, rawBrowserProof);
    const activeCount = set?.accounts.filter((a) => a.status === "active").length ?? 0;
    if (activeCount > 1) {
      const u = new URL(redirectUri);
      u.searchParams.set("error", "account_selection_required");
      u.searchParams.set("state", state);
      return u.toString();
    }
    if (activeCount === 0 && !hasAmbientSession) {
      const u = new URL(redirectUri);
      u.searchParams.set("error", "login_required");
      u.searchParams.set("state", state);
      return u.toString();
    }
    return null;
  }

  const set = await listBrowserSetEntriesWithLiveStatus(database, rawBrowserProof);
  const activeCount = set?.accounts.filter((a) => a.status === "active").length ?? 0;
  if (promptTokens.includes("select_account") || (activeCount >= 2 && !promptTokens.includes("login"))) {
    const u = new URL(`${config.frontendUrl}/auth`);
    for (const k of ["client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "nonce", "prompt"]) {
      if (query[k]) u.searchParams.set(k, query[k]!);
    }
    u.searchParams.set("transaction_id", transactionId);
    u.searchParams.set("selection_revision", "0");
    if (!client.isPublic) u.searchParams.set("is_public", "false");
    return u.toString();
  }
  return null;
}

export async function verifySelectedTransactionStillActive(database: Db, rawBrowserProof: string | undefined, tx: OAuthTransactionDoc): Promise<boolean> {
  if (!tx.browserSetId || !tx.selectedEntryId || !tx.selectedUserId || !tx.selectedSessionId) return false;
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc || setDoc.setId !== tx.browserSetId) return false;
  try {
    const resolved = await resolveVerifiedBrowserEntry(authProvider as any, database, rawBrowserProof, tx.selectedEntryId);
    return resolved.userId === tx.selectedUserId && resolved.sessionId === tx.selectedSessionId;
  } catch {
    return false;
  }
}

export async function selectAccountForOAuthTransaction(params: {
  database: Db;
  rawBrowserProof: string | undefined;
  transactionId: string;
  entryId: string;
  expectedRevision: number;
  requestId: string;
}) {
  const { database, rawBrowserProof, transactionId, entryId, expectedRevision, requestId } = params;
  const setDoc = await findActiveBrowserSet(database, rawBrowserProof);
  if (!setDoc) {
    return { status: 401, body: { error: "unauthorized", code: "ERR_BROWSER_PROOF_INVALID", requestId } };
  }

  let verified;
  try {
    verified = await resolveVerifiedBrowserEntry(authProvider as any, database, rawBrowserProof, entryId);
  } catch (err: any) {
    return { status: 401, body: { error: "unauthorized", code: err?.code || "ERR_SESSION_INVALID", requestId } };
  }

  const tx = await getOAuthTransaction({ transactionId });
  if (!tx) {
    return { status: 404, body: { error: "not_found", code: "ERR_TX_NOT_FOUND", requestId } };
  }
  if ((tx.selectionRevision ?? 0) !== expectedRevision) {
    return { status: 409, body: { error: "conflict", code: "ERR_REVISION_CONFLICT", currentRevision: tx.selectionRevision ?? 0, requestId } };
  }

  const clientDoc = await resolveOAuthClient(database, tx.clientId);
  if (!clientDoc || clientDoc.disabled || clientDoc.isAmbiguous) {
    return { status: 400, body: { error: "invalid_client", code: "ERR_INVALID_CLIENT", requestId } };
  }

  const userDoc = await database.collection("user").findOne({ id: verified.userId }).catch(() => null)
    ?? await database.collection("user").findOne({ username: verified.label }).catch(() => null);
  const sessDoc = await database.collection("session").findOne({ token: { $exists: true }, userId: userDoc?._id ?? verified.userId })
    ?? await database.collection("session").find({}).toArray().then((all) => all.find((s) => String(s._id || s.id) === verified.sessionId));
  const authTimeSec = sessDoc?.createdAt ? Math.floor(new Date(sessDoc.createdAt).getTime() / 1000) : Math.floor(Date.now() / 1000);

  if (userDoc) {
    const elig = checkAccountEligibility(userDoc, {
      tokenIssuedAtMs: authTimeSec * 1000,
      tokenIssuedAtSec: authTimeSec,
      tokenVersion: userDoc.tokenVersion,
    });
    if (!elig.eligible) {
      return { status: 403, body: { error: "access_denied", code: "ERR_ACCOUNT_INELIGIBLE", requestId } };
    }
  }

  const isPrivate = clientDoc.accessPolicy === "private" || (clientDoc.accessPolicy !== "open" && clientDoc.isPublic === false);
  if (isPrivate) {
    const hasAccess = await checkUserHasAppAccess(database, { id: verified.userId, _id: verified.userId, role: verified.role }, clientDoc.clientId);
    if (!hasAccess) {
      return { status: 403, body: { error: "access_denied", code: "ERR_PRIVATE_APP_ACCESS_DENIED", requestId } };
    }
  }

  const promptTokens = (tx.prompt || "").split(/\s+/).filter(Boolean);
  if (tx.maxAge != null && Math.floor(Date.now() / 1000) - authTimeSec > tx.maxAge) {
    return { status: 403, body: { error: "login_required", code: "ERR_MAX_AGE_EXCEEDED", requiresReauth: true, requestId } };
  }
  if (promptTokens.includes("login") && sessDoc?.createdAt && new Date(sessDoc.createdAt).getTime() < new Date(tx.createdAt).getTime()) {
    return { status: 403, body: { error: "login_required", code: "ERR_PROMPT_LOGIN_REQUIRED", requiresReauth: true, requestId } };
  }

  const bound = await bindOAuthTransactionSelection({
    transactionId: tx.transactionId,
    expectedRevision,
    browserSetId: setDoc.setId,
    entryId: verified.entryId,
    userId: verified.userId,
    sessionId: verified.sessionId,
    sessionVersion: typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1,
    tokenVersion: typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1,
    authTime: authTimeSec,
    mfaTime: sessDoc?.mfaVerifiedAt ? Math.floor(new Date(sessDoc.mfaVerifiedAt).getTime() / 1000) : null,
  });
  if (!bound) {
    return { status: 409, body: { error: "conflict", code: "ERR_REVISION_CONFLICT", requestId } };
  }

  const authQuery = new URLSearchParams({
    client_id: tx.clientId,
    redirect_uri: tx.redirectUri,
    response_type: "code",
    scope: tx.scope || "openid profile email",
    state: tx.state,
    code_challenge_method: tx.codeChallengeMethod || "S256",
  });
  if (tx.codeChallenge) authQuery.set("code_challenge", tx.codeChallenge);
  if (tx.nonce) authQuery.set("nonce", tx.nonce);
  if (promptTokens.includes("consent")) authQuery.set("prompt", "consent");

  const authRes = await dispatchRequestWithBrowserEntry(
    authProvider as any,
    database,
    rawBrowserProof,
    entryId,
    new Request(`${config.auth.baseURL}/api/auth/oauth2/authorize?${authQuery.toString()}`, {
      headers: { origin: config.frontendUrl },
    })
  );

  let location = authRes.headers.get("location");
  if (!location && authRes.status === 200) {
    const j = await authRes.clone().json().catch(() => null);
    if (j?.redirect === true && typeof j.url === "string") location = j.url;
  }
  if (!location) {
    return { status: 500, body: { error: "server_error", code: "ERR_AUTHORIZE_DISPATCH_FAILED", requestId } };
  }

  const locUrl = new URL(location, config.auth.baseURL);
  if (locUrl.pathname.includes("/consent")) {
    const signedOauthQuery = locUrl.search.slice(1);
    locUrl.searchParams.set("oauth_query", signedOauthQuery);
    locUrl.searchParams.set("transaction_id", bound.transactionId);
    locUrl.searchParams.set("selection_revision", String(bound.selectionRevision));
    return {
      status: 200,
      body: { selected: true, requiresConsent: true, redirectTo: `${locUrl.pathname}${locUrl.search}`, selectionRevision: bound.selectionRevision, requestId },
    };
  }

  const code = locUrl.searchParams.get("code");
  if (code) {
    const stillActive = await verifySelectedTransactionStillActive(database, rawBrowserProof, bound);
    const fenced = stillActive && await finalizeAuthorizeCodeWithFence(database, {
      clientId: clientDoc.clientId,
      expectedClientType: clientDoc.clientType,
      expectedCredentialVersion: typeof clientDoc.credentialVersion === "number" ? clientDoc.credentialVersion : 1,
    }, {
      code, clientId: clientDoc.clientId, redirectUri: tx.redirectUri, codeChallenge: tx.codeChallenge,
      codeChallengeMethod: tx.codeChallengeMethod || "S256", userId: verified.userId,
      tokenVersion: typeof userDoc?.tokenVersion === "number" ? userDoc.tokenVersion : 1,
      transactionId: bound.transactionId,
    });
    if (!fenced) {
      await purgeAuthorizationCodeOnCommitFailure(database, code).catch(() => {});
      return { status: 401, body: { error: "unauthorized", code: "ERR_SESSION_REVOKED", requestId } };
    }
  }

  return {
    status: 200,
    body: { selected: true, requiresConsent: false, redirectTo: location, selectionRevision: bound.selectionRevision, requestId },
  };
}
