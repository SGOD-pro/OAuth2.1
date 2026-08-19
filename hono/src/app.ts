import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";

import admin from "./routes/admin";
import auth from "./routes/auth";
import { dynamicCors } from "./middleware/cors";
import { requireAdmin } from "./middleware/admin-auth";
import { authRateLimit } from "./middleware/rate-limit";
import { csrfProtection } from "./middleware/csrf";
import { config } from "./config";

const app = new Hono();
export const appBootTime = Date.now();

// P0-4: Fail fast at boot in production if TRUSTED_PROXY_CIDRS is empty.
// Without a trusted CIDR, all clients resolve to "unknown" and share a single
// rate-limit bucket — defeating per-IP throttling entirely.
if (config.env === "production" && config.trustedProxyCidrs.length === 0) {
	const msg =
		"FATAL: TRUSTED_PROXY_CIDRS must be set in production. " +
		"Without it, all requests collapse into a single 'unknown' rate-limit bucket. " +
		"Set it to your load-balancer/proxy CIDR (e.g. '10.0.0.0/8') in the environment.";
	console.error(msg);
	process.exit(1);
}

if (config.env !== "production" && config.trustedProxyCidrs.length === 0) {
	console.warn(
		"[WARN] TRUSTED_PROXY_CIDRS is not set. Per-IP rate limiting is disabled — " +
		"all requests share a single 'unknown' bucket. Set this before going to production.",
	);
}

app.use("*", dynamicCors);
app.use("*", async (c, next) => {
	c.header(
		"Strict-Transport-Security",
		"max-age=31536000; includeSubDomains; preload",
	);
	c.header("X-Frame-Options", "DENY");
	c.header("X-Content-Type-Options", "nosniff");
	c.header("Referrer-Policy", "strict-origin-when-cross-origin");
	c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
	c.header(
		"Content-Security-Policy",
		[
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self'",
			"img-src 'self' data: https:",
			"font-src 'self' https://fonts.gstatic.com",
			"connect-src 'self' https://accounts.google.com",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		].join("; "),
	);

	await next();
});
app.use("*", async (c, next) => {
	const start = Date.now();
	await next();
	const durationMs = Date.now() - start;
	const status = c.res?.status ?? 0;
	console.log(
		`${c.req.method} ${c.req.path} ${status} ${durationMs}ms`,
	);
});

// P1-9: Global body size limit (100 KB). This is an auth service — no endpoint
// legitimately needs a large body. Prevents memory-exhaustion DoS.
app.use("*", bodyLimit({ maxSize: 100 * 1024 }));

// P0-3: CSRF protection on admin routes (existing).
app.use("/api/admin/*", csrfProtection);

// P0-3: CSRF protection on auth POST routes.
// EXCLUDED from CSRF (legitimate cross-origin or server-to-server access):
//   - /api/auth/oauth2/token        — confidential clients POST from their own server
//   - /api/auth/oauth2/callback/*   — social login redirect (cross-origin GET)
//   - /api/auth/callback/*          — OAuth callback (cross-origin GET)
//   - /api/auth/sign-in/social      — social sign-in redirect (cross-origin)
// GET/HEAD/OPTIONS are already exempted inside csrfProtection itself.
app.use("/api/auth/*", async (c, next) => {
	const path = c.req.path;
	const isCrossOriginOk =
		path.startsWith("/api/auth/oauth2/token") ||
		path.startsWith("/api/auth/oauth2/revoke") ||
		path.startsWith("/api/auth/oauth2/introspect") ||
		path.startsWith("/api/auth/oauth2/callback") ||
		path.startsWith("/api/auth/callback") ||
		path.startsWith("/api/auth/sign-in/social") ||
		path.includes("/callback/");

	if (!isCrossOriginOk) {
		return csrfProtection(c, next);
	}
	return next();
});

app.use("/api/auth/*", authRateLimit);
app.use("/api/admin/*", requireAdmin);

// P0-5: Global error handler — prevents unhandled exceptions from leaking stack
// traces or internal state. Preserves standard HTTPExceptions (like 413 from bodyLimit)
// and ensures proper RFC 6750 401 response for token errors.
app.onError((err, c) => {
	if (err instanceof HTTPException) {
		return c.json(
			{ error: err.message || "HTTP error", status: err.status },
			err.status,
		);
	}

	console.error({
		event: "unhandled_error",
		path: c.req.path,
		method: c.req.method,
		err: err.message,
	});

	// If the crash was on the userinfo endpoint, RFC 6750 requires 401 not 500
	if (c.req.path.includes("/oauth2/userinfo")) {
		return c.json(
			{ error: "invalid_token", error_description: "Token validation failed" },
			401,
		);
	}
	return c.json({ error: "server_error" }, 500);
});

app.get("/", (c) => c.json({ message: "Health check", status: "ok" }));
app.route("/api/admin", admin);  // all /api/admin/* routes
app.route("/api/auth", auth);    // all /api/auth/* routes
app.route("/.well-known", auth); // all /.well-known/* routes (JWKS, OIDC Discovery)

export default app;
