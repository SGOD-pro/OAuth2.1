import { config } from "../config"
import { betterAuth } from "better-auth";
import { admin, jwt, twoFactor } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client, database } from "../db/mongo";
import { isStrongPassword } from "./security";


export const AUTH_INSTANCE = Symbol("AUTH_INSTANCE");
export type AuthInstance = ReturnType<typeof betterAuth>;

export const authProvider = betterAuth({
    appName: "SWYRA Auth", // TOTP issuer label shown in authenticator apps
    baseURL: config.auth.baseURL,
    trustedOrigins: [config.frontendUrl],
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
            partitioned: config.env === "production",
        },
        ipAddress: {
            trustedProxies: config.trustedProxyCidrs,
            ipAddressHeaders: ["x-forwarded-for", "x-real-ip"],
        },
    },

    rateLimit: {
        enabled: true,
        storage: "database",
        window: 60,
        max: 100,
        customRules: {
            "/sign-in/email": { window: 60, max: 10 },
            "/sign-up/email": { window: 60, max: 5 },
            "/request-password-reset": { window: 60, max: 5 },
            "/reset-password": { window: 60, max: 5 },
        },
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

    database: mongodbAdapter(
        database,
        { client, transaction: false }
    ),

    plugins: [

        admin({
            defaultRole: "user",
        }),

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TOTP 2FA — RFC 6238, Google/Microsoft Authenticator
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
                }),
            },
        }),

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // OAuth 2.1 Provider — full OIDC provider
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // Turns this service into a complete OAuth 2.1 / OIDC provider.
        // Handles: client registration, PKCE, consent, token exchange,
        // refresh tokens, introspection, revocation, UserInfo.
        //
        // Endpoints auto-registered under /api/auth/oauth2/*:
        //   POST /oauth2/authorize  — authorization endpoint
        //   POST /oauth2/token      — token exchange
        //   POST /oauth2/revoke     — token revocation
        //   POST /oauth2/introspect — token introspection
        //   GET  /oauth2/userinfo   — OIDC user info
        //   POST /oauth2/register   — dynamic client registration
        oauthProvider({
            loginPage: `${config.frontendUrl}/auth`,
            consentPage: `${config.frontendUrl}/consent`,

            // Supported OIDC scopes
            scopes: ["openid", "profile", "email", "offline_access"],

            // Token expiration (in seconds)
            accessTokenExpiresIn: 900,       // 15 minutes
            refreshTokenExpiresIn: 604800,   // 7 days

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
                    adminEmail: { type: "string", required: false }
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
