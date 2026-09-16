import { Hono } from "hono";
import crypto from "crypto";
import { SignJWT, jwtVerify } from "jose";
import { verifyPassword } from "better-auth/crypto";
import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { incrementRateLimit } from "../db/state";
import { redis, redisEnabled } from "../cache/redis";

const appAdminAuth = new Hono();

// Helper: Timing-safe dummy scrypt hash to prevent timing attacks when user does not exist
async function executeDummyHash(): Promise<void> {
	return new Promise((resolve, reject) => {
		crypto.scrypt(
			"DummyPassword@123!".normalize("NFKC"),
			"dummy_salt_constant_time_98234",
			64,
			{ N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 },
			(err) => {
				if (err) reject(err);
				else resolve();
			}
		);
	});
}

// Helper: Get JWT secret key for signing app admin tokens
function getAdminJwtSecret(): Uint8Array {
	const secret = config.auth?.secret || (config as any).betterAuthSecret || process.env.BETTER_AUTH_SECRET;
	if (!secret) {
		throw new Error("BETTER_AUTH_SECRET is not configured");
	}
	return new TextEncoder().encode(secret);
}

// Helper: Verify client secret (supports Better-Auth SHA-256 base64url, scrypt/bcrypt, and plaintext)
async function verifyClientSecret(providedSecret: string, storedSecret: string): Promise<boolean> {
	if (!providedSecret || !storedSecret) return false;

	// 1. Better Auth SHA-256 base64url hash (standard OAuth client secret storage method)
	try {
		const hashedProvided = crypto.createHash("sha256").update(providedSecret).digest("base64url");
		const bufHashed = Buffer.from(hashedProvided);
		const bufStored = Buffer.from(storedSecret);
		if (bufHashed.length === bufStored.length && crypto.timingSafeEqual(bufHashed, bufStored)) {
			return true;
		}
	} catch {
		// continue
	}

	// 2. Scrypt or standard hash format (if stored with ':' or '$')
	if (storedSecret.includes(":") || storedSecret.startsWith("$")) {
		try {
			if (await verifyPassword({ password: providedSecret, hash: storedSecret })) {
				return true;
			}
		} catch {
			// continue
		}
	}

	// 3. Plaintext secret match (fallback for unhashed or testing clients)
	try {
		const bufA = Buffer.from(providedSecret);
		const bufB = Buffer.from(storedSecret);
		if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
			return true;
		}
	} catch {
		return false;
	}

	return false;
}

// Helper: Rate limiting for app admin login
async function checkLoginRateLimit(ip: string, email: string): Promise<boolean> {
	const redisClient = redisEnabled ? redis : null;
	const normalizedEmail = email.toLowerCase().trim();
	const emailHash = crypto.createHash("sha256").update(normalizedEmail).digest("hex").slice(0, 16);

	if (redisClient) {
		try {
			const ipKey = `ratelimit:app_admin_login:ip:${ip}`;
			const emailKey = `ratelimit:app_admin_login:email:${emailHash}`;

			const [ipCount, emailCount] = await Promise.all([
				redisClient.incr(ipKey),
				redisClient.incr(emailKey),
			]);

			if (ipCount === 1) await redisClient.expire(ipKey, 60);
			if (emailCount === 1) await redisClient.expire(emailKey, 300);

			if (ipCount > 30 || emailCount > 10) return false;
			return true;
		} catch (e) {
			console.warn("[APP_ADMIN_AUTH] Redis rate limit error, falling back to MongoDB:", e);
		}
	}

	// MongoDB sliding-window rate limit fallback
	const ipKey = `APP_ADMIN_IP#${ip}`;
	const emailKey = `APP_ADMIN_TARGET#${emailHash}`;

	const [ipEntry, emailEntry] = await Promise.all([
		incrementRateLimit(ipKey, Date.now(), 60 * 1000),
		incrementRateLimit(emailKey, Date.now(), 300 * 1000),
	]);

	if (ipEntry.count > 30 || emailEntry.count > 10) return false;
	return true;
}

/**
 * POST /api/auth/app-admin/login
 * High-security authentication endpoint for consumer application admins.
 * Requires client_id and client_secret to authenticate the requesting application,
 * and email and password to authenticate the app administrator.
 */
appAdminAuth.post("/login", async (c) => {
	const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "127.0.0.1";
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	const email = typeof body.email === "string" ? body.email.toLowerCase().trim() : "";
	const password = typeof body.password === "string" ? body.password : "";

	if (!clientId || !clientSecret || !email || !password) {
		return c.json(
			{
				error: "invalid_request",
				message: "client_id, client_secret, email, and password are all required",
			},
			400
		);
	}

	// 1. Rate limiting check
	const allowed = await checkLoginRateLimit(ip, email);
	if (!allowed) {
		return c.json(
			{
				error: "too_many_requests",
				message: "Too many login attempts. Please try again in a few minutes.",
			},
			429
		);
	}

	const db = await getDb();

	// 2. Validate client credentials
	const client = await db.collection("oauthClient").findOne({
		$or: [{ clientId }, { client_id: clientId }, { id: clientId }],
	});

	if (!client || client.disabled === true) {
		await executeDummyHash();
		return c.json(
			{
				error: "invalid_client",
				message: "Client authentication failed or application is suspended",
			},
			401
		);
	}

	const storedSecret = client.clientSecret || client.client_secret;
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret);
	if (!isSecretValid) {
		await executeDummyHash();
		return c.json(
			{
				error: "invalid_client",
				message: "Invalid client credentials",
			},
			401
		);
	}

	// 3. Authenticate App Administrator
	const admin = await db.collection("app_admins").findOne({
		clientId: client.clientId || client.client_id || clientId,
		email,
	});

	if (!admin) {
		await executeDummyHash();
		return c.json(
			{
				error: "invalid_credentials",
				message: "Invalid email or password",
			},
			401
		);
	}

	if (admin.isActive === false) {
		await executeDummyHash();
		return c.json(
			{
				error: "account_disabled",
				message: "This administrator account is currently deactivated",
			},
			403
		);
	}

	const isPasswordValid = await verifyPassword({
		password,
		hash: admin.password,
	});

	if (!isPasswordValid) {
		return c.json(
			{
				error: "invalid_credentials",
				message: "Invalid email or password",
			},
			401
		);
	}

	// 4. Update login telemetry
	const now = new Date();
	await db.collection("app_admins").updateOne(
		{ _id: admin._id },
		{
			$inc: { loginCount: 1 },
			$set: { lastLoginAt: now, updatedAt: now },
		}
	);

	// 5. Generate secure HS256 JWT
	const secretKey = getAdminJwtSecret();
	const adminId = admin._id.toString();
	const jti = crypto.randomUUID();

	const token = await new SignJWT({
		sub: adminId,
		email: admin.email,
		name: admin.name || admin.email.split("@")[0],
		clientId: admin.clientId,
		role: "app_admin",
		redirectUrl: admin.redirectUrl,
	})
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.setJti(jti)
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(secretKey);

	return c.json({
		success: true,
		token,
		tokenType: "Bearer",
		expiresIn: 3600,
		redirectUrl: admin.redirectUrl,
		admin: {
			id: adminId,
			email: admin.email,
			name: admin.name || admin.email.split("@")[0],
			clientId: admin.clientId,
			role: "app_admin",
			redirectUrl: admin.redirectUrl,
		},
	});
});

/**
 * POST /api/auth/app-admin/verify
 * Verifies an App Admin JWT token.
 * Can be called by consumer application backend to validate admin sessions.
 */
appAdminAuth.post("/verify", async (c) => {
	const authHeader = c.req.header("authorization");
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	let token = body.token;

	if (!token && authHeader?.startsWith("Bearer ")) {
		token = authHeader.slice(7).trim();
	}

	if (!clientId || !clientSecret || !token) {
		return c.json(
			{
				valid: false,
				error: "invalid_request",
				message: "client_id, client_secret, and token are required",
			},
			400
		);
	}

	const db = await getDb();

	// 1. Validate client credentials
	const client = await db.collection("oauthClient").findOne({
		$or: [{ clientId }, { client_id: clientId }, { id: clientId }],
	});

	if (!client || client.disabled === true) {
		return c.json(
			{
				valid: false,
				error: "invalid_client",
				message: "Client authentication failed or application is suspended",
			},
			401
		);
	}

	const storedSecret = client.clientSecret || client.client_secret;
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret);
	if (!isSecretValid) {
		return c.json(
			{
				valid: false,
				error: "invalid_client",
				message: "Invalid client credentials",
			},
			401
		);
	}

	// 2. Verify token signature and claims
	try {
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
		});

		// 3. Check token revocation list
		if (payload.jti) {
			const revoked = await db.collection("app_admin_revoked_tokens").findOne({
				jti: payload.jti,
			});
			if (revoked) {
				return c.json(
					{
						valid: false,
						error: "token_revoked",
						message: "Administrator session token has been revoked",
					},
					401
				);
			}
		}

		// 4. Ensure token was issued for the requesting application
		const canonicalClientId = client.clientId || client.client_id || clientId;
		if (payload.clientId !== canonicalClientId) {
			return c.json(
				{
					valid: false,
					error: "client_mismatch",
					message: "Token was not issued for this application",
				},
				403
			);
		}

		// 5. Verify the admin account is still active in database
		let adminObjId: ObjectId | null = null;
		try {
			adminObjId = new ObjectId(payload.sub as string);
		} catch {
			return c.json({ valid: false, error: "invalid_token" }, 401);
		}

		const admin = await db.collection("app_admins").findOne({
			_id: adminObjId,
			clientId: canonicalClientId,
		});

		if (!admin || admin.isActive === false) {
			return c.json(
				{
					valid: false,
					error: "account_inactive",
					message: "Administrator account no longer exists or is inactive",
				},
				403
			);
		}

		return c.json({
			valid: true,
			admin: {
				id: admin._id.toString(),
				email: admin.email,
				name: admin.name || admin.email.split("@")[0],
				clientId: admin.clientId,
				role: "app_admin",
			},
			redirectUrl: admin.redirectUrl,
		});
	} catch (err: any) {
		return c.json(
			{
				valid: false,
				error: "invalid_token",
				message: err?.message || "Token validation failed",
			},
			401
		);
	}
});

/**
 * POST /api/auth/app-admin/logout
 * Revokes an App Admin JWT token by storing its JTI in the revocation list.
 */
appAdminAuth.post("/logout", async (c) => {
	const authHeader = c.req.header("authorization");
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	let token = body.token;

	if (!token && authHeader?.startsWith("Bearer ")) {
		token = authHeader.slice(7).trim();
	}

	if (!clientId || !clientSecret || !token) {
		return c.json(
			{
				error: "invalid_request",
				message: "client_id, client_secret, and token are required",
			},
			400
		);
	}

	const db = await getDb();

	// Validate client
	const client = await db.collection("oauthClient").findOne({
		$or: [{ clientId }, { client_id: clientId }, { id: clientId }],
	});

	if (!client) {
		return c.json({ error: "invalid_client" }, 401);
	}

	const storedSecret = client.clientSecret || client.client_secret;
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret);
	if (!isSecretValid) {
		return c.json({ error: "invalid_client" }, 401);
	}

	try {
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
		});

		if (payload.jti) {
			const expiresAt = payload.exp ? new Date(payload.exp * 1000) : new Date(Date.now() + 3600 * 1000);
			await db.collection("app_admin_revoked_tokens").updateOne(
				{ jti: payload.jti },
				{
					$set: {
						jti: payload.jti,
						clientId: client.clientId || client.client_id || clientId,
						revokedAt: new Date(),
						expiresAt,
					},
				},
				{ upsert: true }
			);
		}

		return c.json({
			success: true,
			message: "Administrator session revoked successfully",
		});
	} catch {
		// Even if token was expired or invalid, acknowledge logout
		return c.json({
			success: true,
			message: "Session terminated",
		});
	}
});

export default appAdminAuth;
