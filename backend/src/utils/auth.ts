import { config } from "../config"
import { betterAuth } from "better-auth";
import { admin, jwt, twoFactor } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client, database } from "../db/mongo";
import { isLoopbackHost, isStrongPassword, normalizeOrigin } from "./security";
import { isOriginAllowed } from "../middleware/cors";

const accessControl = createAccessControl({
    user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'impersonate-admins', 'delete', 'set-password', 'set-email', 'get', 'update'],
    session: ['list', 'revoke', 'delete']
});

const superAdminRole = accessControl.newRole({
    user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'impersonate-admins', 'delete', 'set-password', 'set-email', 'get', 'update'],
    session: ['list', 'revoke', 'delete'],
});

const legacyAdminRole = accessControl.newRole({
    user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'delete', 'set-password', 'set-email', 'get', 'update'],
    session: ['list', 'revoke', 'delete'],
});

const appAdminRole = accessControl.newRole({
    user: [],
    session: [],
});

const userRole = accessControl.newRole({
    user: [],
    session: [],
});


export function isSuperAdminUser(user: any): boolean {
    if (!user) return false;
    if (user.role === "super-admin") {
        return user.scopedClientId === null || user.scopedClientId === undefined;
    }
    if (user.role === "admin" && user.scopedClientId === null) {
        return true;
    }
    return false;
}

export const AUTH_INSTANCE = Symbol("AUTH_INSTANCE");
export type AuthInstance = ReturnType<typeof betterAuth>;

export const authProvider = betterAuth({
    appName: "SWYRA Auth", // TOTP issuer label shown in authenticator apps
    baseURL: config.auth.baseURL,
    trustedOrigins: async (request?: Request) => {
        const isProduction = config.env === "production";
        const allowDevInProd = config.allowDevClientsInProduction;

        const origins = new Set<string>();
        if (config.frontendUrl) {
            const normFrontend = normalizeOrigin(config.frontendUrl);
            if (normFrontend) origins.add(normFrontend);
        }

        // Only in development do we populate default local dev loopback origins
        if (!isProduction) {
            origins.add("http://localhost:5174");
            origins.add("http://localhost:5173");
            origins.add("http://localhost:3000");
            origins.add("http://localhost:5175");
            origins.add("http://localhost:3001");
            origins.add("http://127.0.0.1:5174");
            origins.add("http://127.0.0.1:3000");
        }

        if (request) {
            const reqOrigin = request.headers.get("origin");
            if (reqOrigin) {
                const normalized = normalizeOrigin(reqOrigin);
                if (normalized) {
                    let isLoopback = false;
                    try {
                        isLoopback = isLoopbackHost(new URL(normalized).hostname);
                    } catch {}

                    if (!isProduction) {
                        if (isLoopback) {
                            origins.add(normalized);
                        } else {
                            try {
                                const allowed = await isOriginAllowed(normalized);
                                if (allowed) origins.add(normalized);
                            } catch {}
                        }
                    } else {
                        // In production: loopback is strictly prohibited unless explicitly configured dev mode
                        if (isLoopback && !allowDevInProd) {
                            // Do not trust loopback origin in production
                        } else {
                            try {
                                const allowed = await isOriginAllowed(normalized);
                                if (allowed) origins.add(normalized);
                            } catch {}
                        }
                    }
                }
            }
        }
        return Array.from(origins);
    },
    secret: config.auth.secret,

    emailAndPassword: {
        enabled: true,
        disableSignUp:
            !config.auth.publicSignupEnabled,
        minPasswordLength: 12,
        maxPasswordLength: 128,
        requireEmailVerification:
            config.auth.emailVerificationEnabled,
        autoSignIn: config.env !== "production",
        revokeSessionsOnPasswordReset: true,
    },

    emailVerification: {
        sendOnSignUp:
            config.auth.emailVerificationEnabled,
        sendOnSignIn:
            config.auth.emailVerificationEnabled,
        expiresIn: 3600,
    },

    advanced: {
        useSecureCookies: config.env === "production",
        disableCSRFCheck: false,
        disableOriginCheck: false,
        defaultCookieAttributes: {
            httpOnly: true,
            secure: config.env === "production",
            sameSite: config.env === "production" ? "none" : "lax",
            partitioned: false,
        },
        ipAddress: {
            trustedProxies: config.trustedProxyCidrs,
            ipAddressHeaders: ["x-forwarded-for", "x-real-ip"],
        },
    },

    // Rate limiting is handled upstream by Hono Redis + Mongo TTL middleware
    // (authRateLimit for IP-level + credentialStuffingTarget for email-level).
    rateLimit: {
        enabled: false,
    },

    socialProviders: {
        google: {
            clientId: config.google.clientId,
            clientSecret: config.google.clientSecret,
            disableSignUp:
                !config.auth.publicSignupEnabled,
            disableImplicitSignUp:
                !config.auth.publicSignupEnabled,
        },
    },

    user: {
        additionalFields: {
            scopedClientId: {
                type: "string",
                required: false,
                defaultValue: null,
                input: false,
            },
            mustChangePassword: {
                type: "boolean",
                required: false,
                defaultValue: false,
                input: false,
            },
        },
    },

    database: mongodbAdapter(
        database,
        { client, transaction: false }
    ),

    plugins: [

        admin({
            defaultRole: "user",
            adminRoles: ["super-admin", "admin"],
            roles: {
                "super-admin": superAdminRole,
                admin: legacyAdminRole,
                "app-admin": appAdminRole,
                user: userRole,
            },
        }),

        // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
        // TOTP 2FA â€” RFC 6238, Google/Microsoft Authenticator
        // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
        //
        // Owns: secret generation, QR URI, TOTP verify, backup codes.
        // TOTP secret is encrypted at rest by the plugin.
        // No custom TOTP code anywhere in this repo (ADR 011).
        twoFactor({
            issuer: "SWYRA Auth",
            totpOptions: {
                period: 30,
                digits: 6,
            },
        }),
        jwt({
            jwks: {
                keyPairConfig: { alg: "RS256" },
            },
            jwt: {
                issuer: config.auth.baseURL,
                expirationTime: "15m",
                definePayload: ({ user }) => ({
                    sub: user.id,
                    role: user.role,
                    scoped_client_id: (user as any).scopedClientId || null,
                }),
            },
        }),

        // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
        // OAuth 2.1 Provider â€” full OIDC provider
        // â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”
        //
        // Turns this service into a complete OAuth 2.1 / OIDC provider.
        // Handles: client registration, PKCE, consent, token exchange,
        // refresh tokens, introspection, revocation, UserInfo.
        //
        // Endpoints auto-registered under /api/auth/oauth2/*:
        //   POST /oauth2/authorize  â€” authorization endpoint
        //   POST /oauth2/token      â€” token exchange
        //   POST /oauth2/revoke     â€” token revocation
        //   POST /oauth2/introspect â€” token introspection
        //   GET  /oauth2/userinfo   â€” OIDC user info
        //   POST /oauth2/register   â€” dynamic client registration
        oauthProvider({
            loginPage: `${config.frontendUrl}/auth`,
            consentPage: `${config.frontendUrl}/consent`,

            // Supported OIDC scopes
            scopes: ["openid", "profile", "email", "offline_access"],

            // Token expiration (in seconds)
            accessTokenExpiresIn: 900,       // 15 minutes
            refreshTokenExpiresIn: 604800,   // 7 days

            // Security: Strictly disable dynamic client registration and enforce Super-Admin only privileges
            allowDynamicClientRegistration: false,
            clientPrivileges: async ({ user }: any) => {
                return isSuperAdminUser(user);
            },

            accessToken: {
                format: "jwt"
            },

            // Per-endpoint rate limiting (per-IP)
            rateLimit: {
                token: { window: 60, max: 20 },
                authorize: { window: 60, max: 30 },
                register: { window: 60, max: 5 },
                introspect: { window: 60, max: 100 },
                revoke: { window: 60, max: 30 },
                userinfo: { window: 60, max: 60 },
            },

            client: {
                fields: {
                    adminUserId: { type: "string", required: false },
                    adminEmail: { type: "string", required: false },
                    isDev: { type: "boolean", required: false },
                    is_dev: { type: "boolean", required: false },
                    createdAt: { type: "date", required: false },
                    updatedAt: { type: "date", required: false }
                }
            }
        }),
    ],
});

export function validateAuthPasswordBoundary(path: string, body: unknown): string | null {
    if (!body || typeof body !== "object") return null;

    const candidate =
        path.endsWith("/sign-up/email")
            ? (body as { password?: unknown }).password
            : path.endsWith("/reset-password")
                ? (body as { newPassword?: unknown }).newPassword
                : null;

    if (candidate === null) return null;
    if (typeof candidate !== "string" || !isStrongPassword(candidate)) {
        return "Password must be 12-128 characters and include uppercase, lowercase, number, and symbol.";
    }

    return null;
}
