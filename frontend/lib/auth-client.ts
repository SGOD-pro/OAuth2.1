import { createAuthClient } from "better-auth/react";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { twoFactorClient } from "better-auth/client/plugins";

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Better Auth Client SDK
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Configured ONCE. Used across all pages.
 * Provides: signIn, signUp, signOut, useSession, oauth2.*, twoFactor.*
 */
export const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_AUTH_URL || "http://localhost:3000",
  plugins: [
    oauthProviderClient(),
    // Intercepts sign-in when 2FA is required; redirects to the TOTP page.
    twoFactorClient({
      onTwoFactorRedirect() {
        window.location.href = "/admin/two-factor";
      },
    }),
  ],
});

// Export individual hooks for convenience
export const { useSession, signIn, signUp, signOut } = authClient;
