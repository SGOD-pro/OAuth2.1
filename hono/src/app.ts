import { Hono } from "hono";

import admin from "./routes/admin";
import auth from "./routes/auth";
import { dynamicCors } from "./middleware/cors";
import { requireAdmin } from "./middleware/admin-auth";

const app = new Hono();
export const appBootTime = Date.now();

app.use("*", dynamicCors);
app.use("*", async (c, next) => {
	c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
	c.header(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://accounts.google.com",
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

admin.use("/api/admin", requireAdmin);

app.get("/", (c) => c.json({ message: "Health check", status: "ok" }));
app.route("/api/admin", admin);  // all /api/admin/* routes
app.route("/api/auth", auth);    // all /api/auth/* routes

export default app;
