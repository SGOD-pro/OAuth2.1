import { createAuthClient } from "better-auth/react";
import { jwtClient } from "better-auth/client/plugins";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Better Auth Client SDK
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Configured ONCE. Used across all pages.
 * Provides: signIn, signUp, signOut, useSession, oauth2.*
 */
export const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_AUTH_URL || "http://localhost:3000",
  plugins: [
    jwtClient(),
    oauthProviderClient(),
  ],
});

// Export individual hooks for convenience
export const { useSession, signIn, signUp, signOut } = authClient;
