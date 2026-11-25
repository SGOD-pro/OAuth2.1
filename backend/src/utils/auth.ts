import { config } from "../config";
import { betterAuth, APIError } from "better-auth";
import { admin, jwt, twoFactor } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { client, database } from "../db/mongo";
import { isStrongPassword } from "./security";
import { isVerifiedCreationActive } from "../identity/registration-context";
import {
  superAdminRole,
  legacyAdminRole,
  appAdminRole,
  userRole,
  isSuperAdminUser,
} from "./auth-roles";
import { resolveTrustedOrigins } from "./auth-trusted-origins";
import { sendVerificationEmailHandler } from "./auth-verification-email";
import { recordPasswordResetMailForTesting } from "../identity/mail-service";
import { ObjectId } from "mongodb";

export { isSuperAdminUser };

export const AUTH_INSTANCE = Symbol("AUTH_INSTANCE");
export type AuthInstance = ReturnType<typeof betterAuth>;

export const authProvider = betterAuth({
    appName: "SWYRA Auth", // TOTP issuer label shown in authenticator apps
    baseURL: config.auth.baseURL,
    trustedOrigins: resolveTrustedOrigins,
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
        sendResetPassword: async ({ user, url, token }: { user: any; url: string; token: string }) => {
            recordPasswordResetMailForTesting(user.email, url, token);
        },
        onPasswordReset: async ({ user }: { user: any }) => {
            if (!user?.id) return;
            const now = new Date();
            const uFilters: any[] = [{ userId: user.id }];
            if (ObjectId.isValid(user.id) && user.id.length === 24) {
                uFilters.push({ userId: new ObjectId(user.id) });
            }
            await Promise.all([
                database.collection("browser_session_sets").updateMany(
                    { entries: { $elemMatch: { userId: user.id, status: "active" } } },
                    {
                        $set: {
                            "entries.$[elem].status": "signed_out",
                            "entries.$[elem].sessionId": null,
                            "entries.$[elem].signedOutAt": now,
                        },
                        $inc: { version: 1 },
                    },
                    { arrayFilters: [{ "elem.userId": user.id, "elem.status": "active" }] }
                ),
                database.collection("identity_contexts").updateMany(
                    { userId: user.id, revokedAt: null },
                    { $set: { revokedAt: now } }
                ),
                database.collection("oauthRefreshToken").deleteMany({ $or: uFilters }),
                database.collection("oauthAccessToken").deleteMany({ $or: uFilters }),
                database.collection("oauth_token_families").updateMany(
                    { $or: uFilters, status: { $ne: "revoked" } },
                    { $set: { status: "revoked", revokedAt: now } }
                ),
            ]);
        },
    },

    emailVerification: {
        sendOnSignUp:
            config.auth.emailVerificationEnabled,
        sendOnSignIn:
            config.auth.emailVerificationEnabled,
        expiresIn: 3600,
        sendVerificationEmail: sendVerificationEmailHandler,
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
            tokenVersion: {
                type: "number",
                required: false,
                defaultValue: 1,
                input: false,
            },
            username: {
                type: "string",
                required: false,
                defaultValue: null,
                input: false,
            },
            usernameLookup: {
                type: "string",
                required: false,
                defaultValue: null,
                input: false,
            },
            emailLookup: {
                type: "string",
                required: false,
                defaultValue: null,
                input: false,
            },
            acceptedTermsVersion: {
                type: "string",
                required: false,
                defaultValue: null,
                input: false,
            },
        },
    },

    databaseHooks: {
        user: {
            create: {
                before: async (user: any) => {
                    if (config.identity.registrationMode === "verified" && !isVerifiedCreationActive()) {
                        throw new APIError("FORBIDDEN", {
                            message: "Verified email proof is required before creating an identity.",
                        });
                    }
                    return {
                        data: {
                            ...user,
                            tokenVersion: typeof user.tokenVersion === "number" ? user.tokenVersion : 1,
                        },
                    };
                },
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


        // OAuth 2.1 Provider â€” full OIDC provider
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
            scopes: ["openid", "profile", "email", "offline_access"],
            accessTokenExpiresIn: 900,
            refreshTokenExpiresIn: 604800,
            allowDynamicClientRegistration: false,
            clientPrivileges: async ({ user }: any) => {
                return isSuperAdminUser(user);
            },
            accessToken: {
                format: "jwt"
            },
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
        }) as any,
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
