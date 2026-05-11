import { config } from "../config"
import { betterAuth } from "better-auth";
import { admin, jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { db, client } from "../db/mongo";


export const AUTH_INSTANCE = Symbol("AUTH_INSTANCE");
export type AuthInstance = ReturnType<typeof betterAuth>;

export const authProvider = betterAuth({
    baseURL: config.auth.baseURL,
    trustedOrigins: [config.frontendUrl],
    secret: config.auth.secret,

    emailAndPassword: {
        enabled: true,
    },

    socialProviders: {
        google: {
            clientId: config.google.clientId,
            clientSecret: config.google.clientSecret,
        },
    },

    database: mongodbAdapter(
        db,
        { client }
    ),

    plugins: [

        admin({
            defaultRole: "user",
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
                    email: user.email,
                    name: user.name,
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
            // Pages the OAuth flow redirects to
            loginPage: "/sign-in",
            consentPage: "/consent",

            // Supported OIDC scopes
            scopes: ["openid", "profile", "email", "offline_access"],

            // Token expiration (in seconds)
            accessTokenExpiresIn: 900,       // 15 minutes
            refreshTokenExpiresIn: 2592000,  // 30 days

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
        }),
    ],
});