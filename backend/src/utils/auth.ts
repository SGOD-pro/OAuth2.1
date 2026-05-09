import { ConfigService } from "@nestjs/config";
import { betterAuth } from "better-auth";
import { admin, jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { MongoClient } from "mongodb";

export const AUTH_INSTANCE = Symbol("AUTH_INSTANCE");
export type AuthInstance = ReturnType<typeof betterAuth>;

export const authProvider = {
  provide: AUTH_INSTANCE,
  inject: [ConfigService],
  useFactory: (config: ConfigService) => {
    const mongoUri = config.get<string>("MONGO_URI");
    if (!mongoUri) {
      throw new Error("MONGO_URI is not set");
    }

    const baseURL = config.get<string>("BETTER_AUTH_URL");
    if (!baseURL) {
      throw new Error("BETTER_AUTH_URL is not set");
    }

    const secret = config.get<string>("BETTER_AUTH_SECRET");
    if (!secret) {
      throw new Error("BETTER_AUTH_SECRET is not set");
    }

    const frontendUrl = config.get<string>("FRONTEND_URL");
    if (!frontendUrl) {
      throw new Error("FRONTEND_URL is not set");
    }

    const googleClientId = config.get<string>("GOOGLE_CLIENT_ID");
    const googleClientSecret = config.get<string>("GOOGLE_CLIENT_SECRET");

    const client = new MongoClient(mongoUri);
    const db = client.db();

    void client.connect().catch((error) => {
      console.error("Failed to connect to MongoDB:", error);
      process.exit(1);
    });

    return betterAuth({
      baseURL,
      trustedOrigins: [frontendUrl],
      secret,

      emailAndPassword: {
        enabled: true,
      },

      socialProviders: {
        google: {
          clientId: googleClientId as string,
          clientSecret: googleClientSecret as string,
        },
      },

      database: mongodbAdapter(db, { client }),

      plugins: [
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // Admin Plugin — role-based admin access
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // Admins = regular users with role === 'admin'.
        // First admin: sign up normally, then in MongoDB:
        //   db.user.updateOne(
        //     { email: "your@email.com" },
        //     { $set: { role: "admin" } }
        //   )
        admin({
          defaultRole: "user",
        }),

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // JWT Plugin — RS256 asymmetric signing + JWKS
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        //
        // - Generates RS256 key pair automatically (stored in MongoDB)
        // - Serves JWKS at /api/auth/.well-known/jwks.json
        //   (proxied to /.well-known/jwks.json via Nginx)
        // - Automatic key rotation every 30 days with 30-day grace
        // - Consuming apps verify via jose + JWKS_URL — never hardcode keys
        //
        // HS256 is FORBIDDEN. RS256 only.
        jwt({
          jwks: {
            keyPairConfig: { alg: "RS256" },
          },
          jwt: {
            issuer: baseURL,
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
  },
};