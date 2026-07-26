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
  // In dev: requests go through Vite proxy (/api → localhost:3000), same-origin.
  // In prod: set VITE_AUTH_URL to the deployed API base (e.g. https://api.yourdomain.com).
  baseURL: import.meta.env.VITE_AUTH_URL || `${window.location.origin}`,
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
