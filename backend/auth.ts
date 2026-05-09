/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Better Auth CLI Configuration
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * This file exists ONLY for the Better Auth CLI (`npx @better-auth/cli`).
 * The runtime auth config lives in src/utils/auth.ts inside the NestJS
 * provider factory.
 *
 * The CLI requires a default-exported auth instance to run migrations
 * and generate schemas. This file mirrors the runtime config but reads
 * env vars directly (no ConfigService).
 *
 * Usage:
 *   npx @better-auth/cli migrate
 *   npx @better-auth/cli generate
 */

import { betterAuth } from "better-auth";
import { admin, jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { MongoClient } from "mongodb";
import * as dotenv from "dotenv";

dotenv.config();

const mongoUri = process.env.MONGO_URI!;
const baseURL = process.env.BETTER_AUTH_URL!;
const secret = process.env.BETTER_AUTH_SECRET!;

const client = new MongoClient(mongoUri);
const db = client.db();

export const auth = betterAuth({
  baseURL,
  secret,

  emailAndPassword: {
    enabled: true,
  },

  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    },
  },

  database: mongodbAdapter(db, { client }),

  plugins: [
    admin({
      defaultRole: "user",
    }),
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
    oauthProvider({
      loginPage: "/sign-in",
      consentPage: "/consent",
      scopes: ["openid", "profile", "email", "offline_access"],
      accessTokenExpiresIn: 900,
      refreshTokenExpiresIn: 2592000,
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
