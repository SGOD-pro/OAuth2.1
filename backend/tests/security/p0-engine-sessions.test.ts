import assert from "node:assert/strict";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createHash, randomBytes } from "node:crypto";
import { dispatchSelectedEngineSession, type SelectedEngineSession } from "../../src/identity/selected-engine-session";
import { p0Fixture } from "../fixtures/p0-engine";

const fixture = await p0Fixture();
const { engine, db, context } = fixture;
const issuer = "http://localhost:3000";
const callback = "http://localhost:5174/callback";
let passed = 0;
async function check(name: string, work: () => Promise<void>) {
  await work(); passed++; console.log(`[PASS] ${name}`);
}
function request(path: string, body?: unknown, cookie = "") {
  return new Request(`${issuer}/api/auth${path}`, {
    method: body ? "POST" : "GET",
    headers: { origin: "http://localhost:5174", "content-type": "application/json", cookie },
    body: body ? JSON.stringify(body) : undefined,
  });
}
async function location(response: Response) {
  if (response.headers.has("location")) return response.headers.get("location")!;
  const json = await response.json();
  assert.equal(json.redirect, true, "Expected engine redirect");
  assert.equal(typeof json.url, "string");
  return json.url as string;
}
try {
  const selected: SelectedEngineSession[] = [];
  for (const account of ["alice", "bob"]) {
    await fixture.proof(account, `${account}@example.test`);
    const user = await fixture.complete(account, account);
    const login = await engine.api.signInEmail({ body: {
      email: user.email, password: "P0-Disposable-Password!123",
    }, asResponse: true });
    assert.equal(login.status, 200);
    assert.match(login.headers.get("set-cookie") ?? "", /HttpOnly/i);
    const session = await db.collection("session").findOne({ userId: new (await import("mongodb")).ObjectId(user.id) });
    assert.ok(session);
    selected.push({ userId: user.id, sessionId: session._id.toString(), token: session.token });
  }
  await context.adapter.create({ model: "oauthClient", data: {
    clientId: "p0-client", name: "P0 disposable client", redirectUris: [callback],
    tokenEndpointAuthMethod: "none", grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"], scopes: ["openid", "profile", "offline_access"],
    skipConsent: false, requirePKCE: true, disabled: false,
  } });
  const attempts = selected.map((session, i) => {
    const verifier = randomBytes(32).toString("base64url");
    const query = new URLSearchParams({
      client_id: "p0-client", redirect_uri: callback, response_type: "code",
      scope: "openid profile offline_access", state: `p0-tab-${i}`,
      nonce: `p0-nonce-${i}`, code_challenge_method: "S256",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    });
    return { session, query, verifier, consentQuery: "", code: "" };
  });
  await check("overlapping A/B authorize requests ignore ambient cookie and reach consent independently", async () => {
    const hold = fixture.holdAuthorize();
    const first = request(`/oauth2/authorize?${attempts[0].query}`, undefined,
      "better-auth.session_token=ambient-b; better-auth.session_data=untrusted");
    first.headers.set("x-p0-hold", "yes");
    const pendingA = dispatchSelectedEngineSession(engine, first, attempts[0].session);
    const timeout = setTimeout(() => hold.release(), 5_000);
    timeout.unref();
    let responseB: Response;
    try {
      await Promise.race([hold.reached, new Promise<never>((_, reject) => {
        const timer = setTimeout(() => reject(new Error("Authorize barrier timed out")), 5_000);
        timer.unref();
        hold.reached.then(() => clearTimeout(timer));
      })]);
      responseB = await dispatchSelectedEngineSession(engine,
        request(`/oauth2/authorize?${attempts[1].query}`, undefined,
          "better-auth.session_token=ambient-a"), attempts[1].session);
    } finally {
      hold.release(); clearTimeout(timeout);
    }
    const responses = [await pendingA, responseB!];
    assert.equal(first.headers.get("cookie"),
      "better-auth.session_token=ambient-b; better-auth.session_data=untrusted");
    for (let i = 0; i < responses.length; i++) {
      assert.equal(responses[i].headers.get("set-cookie"), null);
      for (const session of selected) {
        assert.ok(!(await responses[i].clone().text()).includes(session.token));
        assert.ok(!JSON.stringify([...responses[i].headers]).includes(session.token));
      }
      const redirect = new URL(await location(responses[i]));
      assert.equal(redirect.pathname, "/consent");
      assert.equal(redirect.searchParams.get("state"), `p0-tab-${i}`);
      attempts[i].consentQuery = redirect.search.slice(1);
    }
  });
  await check("interleaved B then A consent creates codes bound to each selected subject/session", async () => {
    for (const attempt of [...attempts].reverse()) {
      const response = await dispatchSelectedEngineSession(engine,
        request("/oauth2/consent", { accept: true, oauth_query: attempt.consentQuery }), attempt.session);
      assert.equal(response.headers.get("set-cookie"), null);
      const redirect = new URL(await location(response));
      assert.equal(redirect.origin + redirect.pathname, callback);
      assert.equal(redirect.searchParams.get("state"), attempt.query.get("state"));
      attempt.code = redirect.searchParams.get("code")!;
      assert.ok(attempt.code);
      const records = await db.collection("verification").find({}).toArray();
      const bound = records.map(row => JSON.parse(row.value)).find(value =>
        value.type === "authorization_code" && value.query.state === attempt.query.get("state"));
      assert.ok(bound);
      assert.equal(bound.userId, attempt.session.userId);
      assert.equal(bound.sessionId, attempt.session.sessionId);
      assert.ok(!JSON.stringify(bound).includes(attempt.session.token));
    }
  });
  await check("real code exchange and refresh retain A/B subjects with exact PKCE", async () => {
    for (const attempt of attempts) {
      const tokenRequest = (params: URLSearchParams) => engine.handler(new Request(`${issuer}/api/auth/oauth2/token`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: params,
      }));
      const response = await tokenRequest(new URLSearchParams({
        grant_type: "authorization_code", client_id: "p0-client", redirect_uri: callback,
        code: attempt.code, code_verifier: attempt.verifier,
      }));
      assert.equal(response.status, 200);
      const tokens = await response.json();
      const jwks = await (await engine.handler(new Request(`${issuer}/api/auth/jwks`))).json();
      const { payload: claims } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
        algorithms: ["RS256"], issuer, audience: "p0-client",
      });
      assert.equal(claims.sub, attempt.session.userId);
      assert.equal(claims.nonce, attempt.query.get("nonce"));
      assert.ok(tokens.refresh_token);
      const refreshed = await tokenRequest(new URLSearchParams({
        grant_type: "refresh_token", client_id: "p0-client", refresh_token: tokens.refresh_token,
      }));
      assert.equal(refreshed.status, 200);
      const refreshTokens = await refreshed.json();
      const info = await engine.handler(new Request(`${issuer}/api/auth/oauth2/userinfo`, {
        headers: { authorization: `Bearer ${refreshTokens.access_token}` },
      }));
      assert.equal(info.status, 200);
      assert.equal((await info.json()).sub, attempt.session.userId);
      assert.equal((await tokenRequest(new URLSearchParams({
        grant_type: "authorization_code", client_id: "p0-client", redirect_uri: callback,
        code: attempt.code, code_verifier: attempt.verifier,
      }))).status, 400);
    }
  });
  await check("invalid selection never falls back to ambient session or non-OAuth token endpoint", async () => {
    await assert.rejects(dispatchSelectedEngineSession(engine, request(`/oauth2/authorize?${attempts[0].query}`),
      { ...selected[0], userId: selected[1].userId }), /invalid/);
    await assert.rejects(dispatchSelectedEngineSession(engine, request("/get-session"), selected[0]), /only supports/);
    await assert.rejects(dispatchSelectedEngineSession(engine, request(`/oauth2/authorize?${attempts[0].query}`),
      { ...selected[0], token: "invalid-token" }), /invalid/);
  });
  await check("engine denies cross-origin consent without returning a session token", async () => {
    const consent = request("/oauth2/consent", { accept: true, oauth_query: attempts[0].consentQuery });
    consent.headers.set("origin", "https://untrusted.example");
    const response = await dispatchSelectedEngineSession(engine, consent, selected[0]);
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("set-cookie"), null);
    const body = await response.text();
    for (const session of selected) assert.ok(!body.includes(session.token));
  });
  await check("revoked and expired A are denied while B remains usable", async () => {
    const { ObjectId } = await import("mongodb");
    await db.collection("session").updateOne({ _id: new ObjectId(selected[0].sessionId) }, { $set: { expiresAt: new Date(0) } });
    await assert.rejects(dispatchSelectedEngineSession(engine, request(`/oauth2/authorize?${attempts[0].query}`), selected[0]), /invalid/);
    await db.collection("session").deleteOne({ _id: new ObjectId(selected[0].sessionId) });
    await assert.rejects(dispatchSelectedEngineSession(engine, request(`/oauth2/authorize?${attempts[0].query}`), selected[0]), /invalid/);
    const response = await dispatchSelectedEngineSession(engine, request(`/oauth2/authorize?${attempts[1].query}`), selected[1]);
    const output = await location(response);
    assert.ok(!output.includes(selected[1].token));
    assert.equal(response.headers.get("set-cookie"), null);
  });
  console.log(`P0 sessions: ${passed} passed, 0 failed, 0 skipped (in-process engine HTTP harness, real Mongo replica set)`);
} finally {
  await fixture.close();
}
