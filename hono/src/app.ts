import { Hono } from "hono";

import admin from "./routes/admin";
import auth from "./routes/auth";
import { dynamicCors } from "./middleware/cors";
import { requireAdmin } from "./middleware/admin-auth";
import { adminRateLimit } from "./middleware/rate-limit";
import { csrfProtection } from "./middleware/csrf";

const app = new Hono();
export const appBootTime = Date.now();

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
			"style-src 'self' 'unsafe-inline'",
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

admin.use("/*", csrfProtection);
admin.use("/*", adminRateLimit);
admin.use("/*", requireAdmin);

app.get("/", (c) => c.json({ message: "Health check", status: "ok" }));
app.route("/api/admin", admin);  // all /api/admin/* routes
app.route("/api/auth", auth);    // all /api/auth/* routes

export default app;
