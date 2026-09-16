import { Hono } from "hono";
import crypto from "crypto";
import { SignJWT, jwtVerify } from "jose";
import { verifyPassword } from "better-auth/crypto";
import { ObjectId } from "mongodb";
import { getDb } from "../db/mongo";
import { config } from "../config";
import { incrementRateLimit } from "../db/state";
import { redis, redisEnabled } from "../cache/redis";
import { getTrustedClientIp, resolveOAuthClient } from "../utils/security";
import {
	generateTotpSecret,
	verifyTotpCode,
	generateOtpAuthUri,
	generateBackupCodes,
	verifyBackupCode,
	encryptTotpSecret,
	decryptTotpSecret,
} from "../utils/totp";

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

// Helper: Get dedicated JWT secret key for signing app admin tokens.
// Uses config.appAdminJwtSecret which is either APP_ADMIN_JWT_SECRET env var
// or a HMAC-SHA256 sub-key derived from BETTER_AUTH_SECRET — never the raw secret itself.
function getAdminJwtSecret(): Uint8Array {
	return new TextEncoder().encode(config.appAdminJwtSecret);
}

// Helper: Verify client secret (supports Better-Auth SHA-256 base64url, scrypt/bcrypt, and migration-safe plaintext)
async function verifyClientSecret(providedSecret: string, storedSecret: string, client?: any, db?: any): Promise<boolean> {
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

	// 3. Plaintext secret match (fallback with transparent on-the-fly migration to SHA-256 base64url)
	try {
		const bufA = Buffer.from(providedSecret);
		const bufB = Buffer.from(storedSecret);
		if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
			// Transparently re-hash and remove plaintext representation
			if (db && client?._id) {
				const migrated = crypto.createHash("sha256").update(providedSecret).digest("base64url");
				db.collection("oauthClient").updateOne(
					{ _id: client._id },
					{ $set: { clientSecret: migrated, client_secret: migrated, updatedAt: new Date() } }
				).catch((err: any) => console.warn("[CLIENT_SECRET_MIGRATION] Migration warning:", err?.message || err));
			}
			return true;
		}
	} catch {
		return false;
	}

	return false;
}

// Helper: Anti-abuse rate limiting for all app admin operations (IP and target account/client aware)
async function checkAppAdminRateLimit(
	action: string,
	ip: string,
	targetId?: string,
	options: { ipLimit: number; ipWindowSec: number; targetLimit?: number; targetWindowSec?: number } = { ipLimit: 60, ipWindowSec: 60 }
): Promise<boolean> {
	const redisClient = redisEnabled ? redis : null;
	const targetHash = targetId ? crypto.createHash("sha256").update(targetId.toLowerCase().trim()).digest("hex").slice(0, 16) : null;

	if (redisClient) {
		try {
			const ipKey = `ratelimit:app_admin_${action}:ip:${ip}`;
			const ipCount = await redisClient.incr(ipKey);
			if (ipCount === 1) await redisClient.expire(ipKey, options.ipWindowSec);
			if (ipCount > options.ipLimit) return false;

			if (targetHash && options.targetLimit && options.targetWindowSec) {
				const targetKey = `ratelimit:app_admin_${action}:target:${targetHash}`;
				const targetCount = await redisClient.incr(targetKey);
				if (targetCount === 1) await redisClient.expire(targetKey, options.targetWindowSec);
				if (targetCount > options.targetLimit) return false;
			}
			return true;
		} catch (e) {
			console.warn(`[APP_ADMIN_AUTH] Redis rate limit error on ${action}, falling back to MongoDB:`, e);
		}
	}

	// MongoDB sliding-window rate limit fallback
	const ipKey = `APP_ADMIN_${action.toUpperCase()}_IP#${ip}`;
	const ipEntry = await incrementRateLimit(ipKey, Date.now(), options.ipWindowSec * 1000);
	if (ipEntry.count > options.ipLimit) return false;

	if (targetHash && options.targetLimit && options.targetWindowSec) {
		const targetKey = `APP_ADMIN_${action.toUpperCase()}_TARGET#${targetHash}`;
		const targetEntry = await incrementRateLimit(targetKey, Date.now(), options.targetWindowSec * 1000);
		if (targetEntry.count > options.targetLimit) return false;
	}

	return true;
}

/**
 * POST /api/auth/app-admin/login
 * High-security authentication endpoint for consumer application admins.
 * Requires client_id and client_secret to authenticate the requesting application,
 * and email and password to authenticate the app administrator.
 */
appAdminAuth.post("/login", async (c) => {
	const ip = getTrustedClientIp(c);
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
	const allowed = await checkAppAdminRateLimit("login", ip, email, { ipLimit: 30, ipWindowSec: 60, targetLimit: 10, targetWindowSec: 300 });
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
	const client = await resolveOAuthClient(db, clientId);

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
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret, client, db);
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
	const canonicalClientId = client.clientId;
	const admin = await db.collection("app_admins").findOne({
		clientId: canonicalClientId,
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

	const secretKey = getAdminJwtSecret();
	const adminId = admin._id.toString();

	// 4. Check if Two-Factor Authentication (TOTP) is enabled
	if (admin.totpEnabled === true) {
		const mfaToken = await new SignJWT({
			sub: adminId,
			email: admin.email,
			clientId: canonicalClientId,
			role: "app_admin_mfa_pending",
			token_use: "app_admin_mfa_pending",
		})
			.setProtectedHeader({ alg: "HS256", typ: "JWT" })
			.setIssuedAt()
			.setIssuer(config.auth.baseURL ?? "")
			.setAudience(canonicalClientId)
			.setExpirationTime("5m")
			.sign(secretKey);

		return c.json({
			mfa_required: true,
			mfa_token: mfaToken,
			message: "Two-factor authentication code required",
		});
	}

	// 5. Update login telemetry
	const now = new Date();
	await db.collection("app_admins").updateOne(
		{ _id: admin._id },
		{
			$inc: { loginCount: 1 },
			$set: { lastLoginAt: now, updatedAt: now },
		}
	);

	// 6. Generate secure HS256 JWT
	const jti = crypto.randomUUID();

	const token = await new SignJWT({
		sub: adminId,
		email: admin.email,
		name: admin.name || admin.email.split("@")[0],
		clientId: canonicalClientId,
		role: "app_admin",
		token_use: "app_admin",
		redirectUrl: admin.redirectUrl,
	})
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.setJti(jti)
		.setIssuedAt()
		.setIssuer(config.auth.baseURL ?? "")
		.setAudience(canonicalClientId)
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
			clientId: canonicalClientId,
			role: "app_admin",
			redirectUrl: admin.redirectUrl,
			mfa_enabled: false,
		},
	});
});

/**
 * POST /api/auth/app-admin/verify
 * Verifies an App Admin JWT token.
 * Can be called by consumer application backend to validate admin sessions.
 */
appAdminAuth.post("/verify", async (c) => {
	const ip = getTrustedClientIp(c);
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

	// 1. Rate limiting check
	const allowed = await checkAppAdminRateLimit("verify", ip, clientId, { ipLimit: 120, ipWindowSec: 60, targetLimit: 60, targetWindowSec: 60 });
	if (!allowed) {
		return c.json(
			{
				valid: false,
				error: "too_many_requests",
				message: "Too many verification attempts. Please try again later.",
			},
			429
		);
	}

	const db = await getDb();

	// 2. Validate client credentials
	const client = await resolveOAuthClient(db, clientId);

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
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret, client, db);
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

	// 3. Verify token signature and claims
	try {
		const canonicalClientId = client.clientId;
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});

		// 4. Verify explicit token purpose
		if (payload.token_use !== "app_admin") {
			return c.json(
				{
					valid: false,
					error: "invalid_token_purpose",
					message: "Token purpose mismatch: expected app_admin session token",
				},
				401
			);
		}

		// 5. Check token revocation list
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

		// 6. Ensure token's clientId claim matches the authenticated application
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

		// 7. Verify the admin account is still active in database
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
				mfa_enabled: admin.totpEnabled === true,
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
	const ip = getTrustedClientIp(c);
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

	// 1. Rate limiting check
	const allowed = await checkAppAdminRateLimit("logout", ip, undefined, { ipLimit: 60, ipWindowSec: 60 });
	if (!allowed) {
		return c.json(
			{
				error: "too_many_requests",
				message: "Too many requests. Please try again later.",
			},
			429
		);
	}

	const db = await getDb();

	// 2. Validate client
	const client = await resolveOAuthClient(db, clientId);

	if (!client) {
		return c.json({ error: "invalid_client" }, 401);
	}

	const storedSecret = client.clientSecret || client.client_secret;
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret, client, db);
	if (!isSecretValid) {
		return c.json({ error: "invalid_client" }, 401);
	}

	try {
		const canonicalClientId = client.clientId;
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});

		// Check token purpose
		if (payload.token_use !== "app_admin") {
			return c.json(
				{
					error: "invalid_token_purpose",
					message: "Token purpose mismatch: expected app_admin session token",
				},
				401
			);
		}

		if (payload.jti) {
			const expiresAt = payload.exp ? new Date(payload.exp * 1000) : new Date(Date.now() + 3600 * 1000);
			await db.collection("app_admin_revoked_tokens").updateOne(
				{ jti: payload.jti },
				{
					$set: {
						jti: payload.jti,
						clientId: canonicalClientId,
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

/**
 * POST /api/auth/app-admin/mfa/verify-login
 * Completes the two-factor authentication login challenge.
 * Requires client credentials, the short-lived mfa_token, and a 6-digit TOTP code or backup code.
 */
appAdminAuth.post("/mfa/verify-login", async (c) => {
	const ip = getTrustedClientIp(c);
	const body = await c.req.json().catch(() => ({}));
	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	const mfaToken = body.mfa_token || body.mfaToken;
	const code = typeof body.code === "string" ? body.code.trim() : "";

	if (!clientId || !clientSecret || !mfaToken || !code) {
		return c.json(
			{
				error: "invalid_request",
				message: "client_id, client_secret, mfa_token, and code are all required",
			},
			400
		);
	}

	// 1. Anti-brute-force rate limiting check
	const allowed = await checkAppAdminRateLimit("mfa_verify", ip, clientId, { ipLimit: 30, ipWindowSec: 60, targetLimit: 10, targetWindowSec: 300 });
	if (!allowed) {
		return c.json(
			{
				error: "too_many_requests",
				message: "Too many verification attempts. Please try again in a few minutes.",
			},
			429
		);
	}

	const db = await getDb();

	// 2. Validate client credentials
	const client = await resolveOAuthClient(db, clientId);

	if (!client || client.disabled === true) {
		return c.json(
			{
				error: "invalid_client",
				message: "Client authentication failed or application is suspended",
			},
			401
		);
	}

	const storedSecret = client.clientSecret || client.client_secret;
	const isSecretValid = await verifyClientSecret(clientSecret, storedSecret, client, db);
	if (!isSecretValid) {
		return c.json(
			{
				error: "invalid_client",
				message: "Invalid client credentials",
			},
			401
		);
	}

	const canonicalClientId = client.clientId;
	const secretKey = getAdminJwtSecret();

	// 3. Verify mfa_token signature and claims
	let payload: any;
	try {
		const verified = await jwtVerify(mfaToken, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});
		payload = verified.payload;
	} catch (err: any) {
		return c.json(
			{
				error: "invalid_mfa_token",
				message: "The two-factor authentication challenge token is invalid or has expired. Please sign in again.",
			},
			401
		);
	}

	// Strict token purpose verification
	if (payload.token_use !== "app_admin_mfa_pending" || payload.role !== "app_admin_mfa_pending") {
		return c.json(
			{
				error: "invalid_token_purpose",
				message: "Invalid challenge token: expected app_admin_mfa_pending token",
			},
			401
		);
	}

	// 4. Load administrator
	let adminObjId: ObjectId;
	try {
		adminObjId = new ObjectId(payload.sub as string);
	} catch {
		return c.json({ error: "invalid_admin_id" }, 400);
	}

	const admin = await db.collection("app_admins").findOne({
		_id: adminObjId,
		clientId: canonicalClientId,
	});

	if (!admin || admin.isActive === false) {
		return c.json(
			{
				error: "account_disabled",
				message: "This administrator account is currently deactivated",
			},
			403
		);
	}

	if (!admin.totpSecret) {
		return c.json(
			{
				error: "mfa_not_configured",
				message: "Two-factor authentication is not configured for this account",
			},
			400
		);
	}

	// 5. Verify TOTP code or atomically consume Backup code
	let plainSecret: string;
	try {
		plainSecret = decryptTotpSecret(admin.totpSecret);
	} catch {
		return c.json({ error: "mfa_decrypt_error", message: "Failed to decrypt two-factor secret" }, 500);
	}

	const isTotpValid = verifyTotpCode(code, plainSecret);
	let usedBackupCode = false;

	if (!isTotpValid) {
		// Atomic check and one-time consumption of backup code (race-condition proof)
		const normalized = code.trim().toUpperCase();
		const targetHash = crypto.createHash("sha256").update(normalized).digest("hex");

		const backupRes = await db.collection("app_admins").updateOne(
			{ _id: admin._id, totpBackupCodes: targetHash },
			{
				$pull: { totpBackupCodes: targetHash },
				$set: { updatedAt: new Date() },
			}
		);

		if (backupRes.modifiedCount > 0) {
			usedBackupCode = true;
		} else {
			return c.json(
				{
					error: "invalid_code",
					message: "Invalid or already consumed two-factor authentication code. Please check your authenticator app or backup codes.",
				},
				401
			);
		}
	}

	// 6. Update login telemetry
	const now = new Date();
	await db.collection("app_admins").updateOne(
		{ _id: admin._id },
		{
			$inc: { loginCount: 1 },
			$set: { lastLoginAt: now, updatedAt: now },
		}
	);

	// 7. Issue full session JWT
	const adminId = admin._id.toString();
	const jti = crypto.randomUUID();

	const token = await new SignJWT({
		sub: adminId,
		email: admin.email,
		name: admin.name || admin.email.split("@")[0],
		clientId: canonicalClientId,
		role: "app_admin",
		token_use: "app_admin",
		redirectUrl: admin.redirectUrl,
	})
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.setJti(jti)
		.setIssuedAt()
		.setIssuer(config.auth.baseURL ?? "")
		.setAudience(canonicalClientId)
		.setExpirationTime("1h")
		.sign(secretKey);

	return c.json({
		success: true,
		token,
		tokenType: "Bearer",
		expiresIn: 3600,
		redirectUrl: admin.redirectUrl,
		usedBackupCode,
		admin: {
			id: adminId,
			email: admin.email,
			name: admin.name || admin.email.split("@")[0],
			clientId: canonicalClientId,
			role: "app_admin",
			redirectUrl: admin.redirectUrl,
			mfa_enabled: true,
		},
	});
});

/**
 * POST /api/auth/app-admin/mfa/setup
 * Initiates TOTP two-factor setup for an authenticated app administrator.
 * Generates a new Base32 secret, QR otpauth URL, and emergency backup codes.
 */
appAdminAuth.post("/mfa/setup", async (c) => {
	const ip = getTrustedClientIp(c);
	const authHeader = c.req.header("authorization");
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	let token = body.token;
	if (!token && authHeader?.startsWith("Bearer ")) {
		token = authHeader.slice(7).trim();
	}

	if (!clientId || !clientSecret || !token) {
		return c.json({ error: "invalid_request", message: "client_id, client_secret, and token are required" }, 400);
	}

	// 1. Rate limiting check
	const allowed = await checkAppAdminRateLimit("mfa_setup", ip, clientId, { ipLimit: 20, ipWindowSec: 60, targetLimit: 5, targetWindowSec: 300 });
	if (!allowed) {
		return c.json({ error: "too_many_requests", message: "Too many setup attempts. Please try again later." }, 429);
	}

	const db = await getDb();

	// 2. Validate client
	const client = await resolveOAuthClient(db, clientId);
	if (!client || client.disabled === true) return c.json({ error: "invalid_client" }, 401);

	const storedSecret = client.clientSecret || client.client_secret;
	if (!(await verifyClientSecret(clientSecret, storedSecret, client, db))) {
		return c.json({ error: "invalid_client" }, 401);
	}

	const canonicalClientId = client.clientId;

	// 3. Verify token
	try {
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});

		// Verify explicit token purpose
		if (payload.token_use !== "app_admin") {
			return c.json({ error: "invalid_token_purpose", message: "Token purpose mismatch: expected app_admin session token" }, 401);
		}

		// Check revoked
		if (payload.jti) {
			const revoked = await db.collection("app_admin_revoked_tokens").findOne({ jti: payload.jti });
			if (revoked) return c.json({ error: "token_revoked" }, 401);
		}

		const admin = await db.collection("app_admins").findOne({
			_id: new ObjectId(payload.sub as string),
			clientId: canonicalClientId,
		});
		if (!admin || admin.isActive === false) return c.json({ error: "account_inactive" }, 403);

		// Generate new TOTP secret & backup codes
		const secret = generateTotpSecret();
		const encryptedSecret = encryptTotpSecret(secret);
		const { raw: rawBackupCodes, hashed: hashedBackupCodes } = generateBackupCodes();

		// Save as pending until confirmed
		await db.collection("app_admins").updateOne(
			{ _id: admin._id },
			{
				$set: {
					pendingTotpSecret: encryptedSecret,
					pendingTotpBackupCodes: hashedBackupCodes,
					updatedAt: new Date(),
				},
			}
		);

		const otpauthUrl = generateOtpAuthUri(
			admin.email,
			client.name || "Application Admin",
			secret
		);

		return c.json({
			success: true,
			secret,
			otpauth_url: otpauthUrl,
			backup_codes: rawBackupCodes,
			message: "Scan the otpauth_url QR code in your authenticator app and call /mfa/confirm with a 6-digit code.",
		});
	} catch (err: any) {
		return c.json({ error: "invalid_token", message: err?.message || "Token validation failed" }, 401);
	}
});

/**
 * POST /api/auth/app-admin/mfa/confirm
 * Confirms a pending TOTP setup by verifying the first code from the authenticator app.
 */
appAdminAuth.post("/mfa/confirm", async (c) => {
	const ip = getTrustedClientIp(c);
	const authHeader = c.req.header("authorization");
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	const code = typeof body.code === "string" ? body.code.trim() : "";
	let token = body.token;
	if (!token && authHeader?.startsWith("Bearer ")) {
		token = authHeader.slice(7).trim();
	}

	if (!clientId || !clientSecret || !token || !code) {
		return c.json({ error: "invalid_request", message: "client_id, client_secret, token, and code are required" }, 400);
	}

	// 1. Rate limiting check
	const allowed = await checkAppAdminRateLimit("mfa_confirm", ip, clientId, { ipLimit: 20, ipWindowSec: 60, targetLimit: 10, targetWindowSec: 300 });
	if (!allowed) {
		return c.json({ error: "too_many_requests", message: "Too many confirmation attempts. Please try again later." }, 429);
	}

	const db = await getDb();

	const client = await resolveOAuthClient(db, clientId);
	if (!client || client.disabled === true) return c.json({ error: "invalid_client" }, 401);

	const storedSecret = client.clientSecret || client.client_secret;
	if (!(await verifyClientSecret(clientSecret, storedSecret, client, db))) {
		return c.json({ error: "invalid_client" }, 401);
	}

	const canonicalClientId = client.clientId;

	try {
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});

		// Verify explicit token purpose
		if (payload.token_use !== "app_admin") {
			return c.json({ error: "invalid_token_purpose", message: "Token purpose mismatch: expected app_admin session token" }, 401);
		}

		const admin = await db.collection("app_admins").findOne({
			_id: new ObjectId(payload.sub as string),
			clientId: canonicalClientId,
		});
		if (!admin || admin.isActive === false) return c.json({ error: "account_inactive" }, 403);

		if (!admin.pendingTotpSecret) {
			return c.json({ error: "no_pending_setup", message: "No pending MFA setup found. Please call /mfa/setup first." }, 400);
		}

		const plainSecret = decryptTotpSecret(admin.pendingTotpSecret);
		const isValid = verifyTotpCode(code, plainSecret);

		if (!isValid) {
			return c.json({ error: "invalid_code", message: "Verification code does not match the authenticator setup. Please try again." }, 400);
		}

		// Activate MFA
		await db.collection("app_admins").updateOne(
			{ _id: admin._id },
			{
				$set: {
					totpEnabled: true,
					totpSecret: admin.pendingTotpSecret,
					totpBackupCodes: admin.pendingTotpBackupCodes || [],
					updatedAt: new Date(),
				},
				$unset: {
					pendingTotpSecret: "",
					pendingTotpBackupCodes: "",
				},
			}
		);

		return c.json({
			success: true,
			message: "Two-factor authentication has been successfully enabled for this account.",
		});
	} catch (err: any) {
		return c.json({ error: "invalid_token", message: err?.message || "Token validation failed" }, 401);
	}
});

/**
 * POST /api/auth/app-admin/mfa/disable
 * Disables TOTP two-factor authentication.
 * Requires administrator password and a current TOTP code or backup code for verification.
 */
appAdminAuth.post("/mfa/disable", async (c) => {
	const ip = getTrustedClientIp(c);
	const authHeader = c.req.header("authorization");
	const body = await c.req.json().catch(() => ({}));

	const clientId = body.client_id || body.clientId;
	const clientSecret = body.client_secret || body.clientSecret;
	const password = typeof body.password === "string" ? body.password : "";
	const code = typeof body.code === "string" ? body.code.trim() : "";
	let token = body.token;
	if (!token && authHeader?.startsWith("Bearer ")) {
		token = authHeader.slice(7).trim();
	}

	if (!clientId || !clientSecret || !token || !password || !code) {
		return c.json(
			{
				error: "invalid_request",
				message: "client_id, client_secret, token, password, and code are all required to disable MFA",
			},
			400
		);
	}

	// 1. Rate limiting check
	const allowed = await checkAppAdminRateLimit("mfa_disable", ip, clientId, { ipLimit: 15, ipWindowSec: 60, targetLimit: 5, targetWindowSec: 300 });
	if (!allowed) {
		return c.json({ error: "too_many_requests", message: "Too many attempts. Please try again later." }, 429);
	}

	const db = await getDb();

	const client = await resolveOAuthClient(db, clientId);
	if (!client || client.disabled === true) return c.json({ error: "invalid_client" }, 401);

	const storedSecret = client.clientSecret || client.client_secret;
	if (!(await verifyClientSecret(clientSecret, storedSecret, client, db))) {
		return c.json({ error: "invalid_client" }, 401);
	}

	const canonicalClientId = client.clientId;

	try {
		const secretKey = getAdminJwtSecret();
		const { payload } = await jwtVerify(token, secretKey, {
			algorithms: ["HS256"],
			issuer: config.auth.baseURL ?? undefined,
			audience: canonicalClientId,
		});

		// Verify explicit token purpose
		if (payload.token_use !== "app_admin") {
			return c.json({ error: "invalid_token_purpose", message: "Token purpose mismatch: expected app_admin session token" }, 401);
		}

		const admin = await db.collection("app_admins").findOne({
			_id: new ObjectId(payload.sub as string),
			clientId: canonicalClientId,
		});
		if (!admin || admin.isActive === false) return c.json({ error: "account_inactive" }, 403);

		if (admin.totpEnabled !== true || !admin.totpSecret) {
			return c.json({ error: "mfa_not_enabled", message: "Two-factor authentication is not currently enabled" }, 400);
		}

		// Verify password
		const isPasswordValid = await verifyPassword({ password, hash: admin.password });
		if (!isPasswordValid) {
			return c.json({ error: "invalid_credentials", message: "Invalid administrator password" }, 401);
		}

		// Verify TOTP or backup code
		const plainSecret = decryptTotpSecret(admin.totpSecret);
		const isTotpValid = verifyTotpCode(code, plainSecret);
		const isBackupValid = !isTotpValid && verifyBackupCode(code, admin.totpBackupCodes || []).valid;

		if (!isTotpValid && !isBackupValid) {
			return c.json({ error: "invalid_code", message: "Invalid two-factor code or backup code" }, 401);
		}

		// Disable MFA
		await db.collection("app_admins").updateOne(
			{ _id: admin._id },
			{
				$set: {
					totpEnabled: false,
					updatedAt: new Date(),
				},
				$unset: {
					totpSecret: "",
					totpBackupCodes: "",
					pendingTotpSecret: "",
					pendingTotpBackupCodes: "",
				},
			}
		);

		return c.json({
			success: true,
			message: "Two-factor authentication disabled successfully",
		});
	} catch (err: any) {
		return c.json({ error: "invalid_token", message: err?.message || "Token validation failed" }, 401);
	}
});

export default appAdminAuth;
