import type { betterAuth } from "better-auth";
import { makeSignature } from "better-auth/crypto";

type BaseEngine = ReturnType<typeof betterAuth>;
type SessionEngine = {
  handler: BaseEngine["handler"];
  api: Pick<BaseEngine["api"], "getSession">;
  $context: Promise<Pick<Awaited<BaseEngine["$context"]>, "secret" | "authCookies">>;
};

/** Resolved server-side after browser/transaction ownership checks, never from a JS token list. */
export type SelectedEngineSession = Readonly<{
  userId: string;
  sessionId: string;
  token: string;
}>;

/** P0 engine-only proof. Production policy/chooser wiring belongs to P3. */
export async function dispatchSelectedEngineSession(
  engine: SessionEngine,
  request: Request,
  selected: SelectedEngineSession,
): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (!((request.method === "GET" && path === "/api/auth/oauth2/authorize") ||
        (request.method === "POST" && path === "/api/auth/oauth2/consent") ||
        (request.method === "POST" && path === "/api/auth/oauth2/continue"))) {
    throw new Error("Selected-session dispatch only supports authorize, consent, and continue");
  }
  const context = await engine.$context;
  const headers = new Headers(request.headers);
  // Replace all ambient identity/cache cookies and bearer credentials in this request only.
  headers.delete("authorization");
  const signature = await makeSignature(selected.token, context.secret);
  headers.set("cookie", `${context.authCookies.sessionToken.name}=${encodeURIComponent(`${selected.token}.${signature}`)}`);
  const session = await engine.api.getSession({
    headers,
    query: { disableCookieCache: true, disableRefresh: true },
  });
  if (!session || session.user.id !== selected.userId ||
      session.session.id !== selected.sessionId) {
    throw new Error("Selected engine session is invalid");
  }
  const response = await engine.handler(new Request(request, { headers }));
  const responseHeaders = new Headers(response.headers);
  // This internal dispatch must never change the browser's ambient account.
  responseHeaders.delete("set-cookie");
  responseHeaders.set("cache-control", "no-store");
  return new Response(response.body, { status: response.status, headers: responseHeaders });
}
