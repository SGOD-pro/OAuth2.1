import { Hono } from "hono";
import { authProvider } from "../utils/auth";
import { requireSuperAdmin, requireRecentMfa } from "../middleware/admin-auth";
import { handleOAuthInitiate, handleSignInEmail, handleSignUpEmail } from "./auth-credentials";
import { handleOAuthAuthorize } from "./auth-authorize";
import { handleOAuthToken } from "./auth-token";
import { handleOAuthUserInfo } from "./auth-userinfo";
import { handleOAuthIntrospect } from "./auth-introspect";
import { handleOAuthConsent, handleOAuthContinue } from "./auth-consent";
import { handleOAuthRevoke } from "./auth-revoke";
import {
    handleDisabledEndpoint,
    handleAdminListUsers,
    handleAdminRevocationRoute,
    handleSocialCallback,
} from "./auth-interceptors";
import { handleGetJwks } from "./auth-jwks";
import { handleVerifyTotp, handleVerifyBackupCode } from "./auth-two-factor";

export const auth = new Hono();

// 1. Credentials and pre-login initiation
auth.post("/oauth/initiate", handleOAuthInitiate);
auth.post("/sign-in/email", handleSignInEmail);
auth.post("/sign-up/email", handleSignUpEmail);

// 2. OAuth 2.1 Core Protocol Endpoints
auth.get("/oauth2/authorize", handleOAuthAuthorize);
auth.post("/oauth2/token", handleOAuthToken);
auth.get("/oauth2/userinfo", handleOAuthUserInfo);
auth.post("/oauth2/introspect", handleOAuthIntrospect);

// 3. User Consent and Continuation
auth.post("/oauth2/consent", handleOAuthConsent);
auth.post("/oauth2/continue", handleOAuthContinue);

// 4. Disabled Dynamic Client Registration & Management Endpoints
const disabledClientEndpoints = [
    { path: "/oauth2/register", description: "Dynamic client registration is disabled" },
    { path: "/oauth2/register/*", description: "Dynamic client registration is disabled" },
    { path: "/oauth2/create-client", description: "Direct client creation is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/update-client", description: "Direct client update is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/delete-client", description: "Direct client deletion is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/get-client", description: "Direct client lookup is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/get-clients", description: "Direct client lookup is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/public-client", description: "Direct public client lookup is forbidden." },
    { path: "/oauth2/public-client-prelogin", description: "Direct public client lookup is forbidden." },
    { path: "/oauth2/client/rotate-secret", description: "Direct secret rotation is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/client/*", description: "Direct client management is forbidden. Use /api/admin/clients." },
    { path: "/oauth2/clients/*", description: "Direct client management is forbidden. Use /api/admin/clients." },
];

for (const { path, description } of disabledClientEndpoints) {
    auth.all(path, handleDisabledEndpoint(description));
}

// 5. Authoritative Super-Admin Gate for Better-Auth Internal Admin Routes
auth.use("/admin", requireSuperAdmin);
auth.use("/admin/*", requireSuperAdmin);
auth.use("/admin/*", async (c, next) => {
    const method = c.req.method.toUpperCase();
    if (method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE") {
        return requireRecentMfa(c, next);
    }
    return next();
});
auth.all("/admin/list-users", handleAdminListUsers);

// 6. OAuth 2.1 Token Revocation (RFC 7009)
auth.post("/oauth2/revoke", handleOAuthRevoke);

// 7. Durable Token Revocation on Admin Mutations
const adminRevocationRoutes = [
    "/admin/ban-user",
    "/admin/revoke-user-sessions",
    "/admin/set-password",
    "/admin/remove-user",
];

for (const routePath of adminRevocationRoutes) {
    auth.post(routePath, handleAdminRevocationRoute(routePath));
}

// 8. Social Login Callbacks
auth.all("/callback/:provider", handleSocialCallback);
auth.all("/oauth2/callback/:provider", handleSocialCallback);

// 9. Standard OIDC JWKS Aliases (RFC 7517 / RFC 8414)
auth.get("/jwks.json", handleGetJwks);
auth.get("/jwks", handleGetJwks);

// 10. Validated Two-Factor Verification & Telemetry
auth.post("/two-factor/verify-totp", handleVerifyTotp);
auth.post("/two-factor/verify-backup-code", handleVerifyBackupCode);

// 11. Catch-all delegate to Better Auth
auth.all("/*", async (c) => {
    return authProvider.handler(c.req.raw);
});

export default auth;

// Re-exports for public module API and testing compatibility
export * from "./auth-keys";
export * from "./auth-jwt";
export * from "./auth-client-context";
export * from "./auth-rate-limit";
export * from "./auth-credentials";
export * from "./auth-authorize";
export * from "./auth-token-auth";
export * from "./auth-token-claim";
export * from "./auth-token-linearize";
export * from "./auth-token-refresh-validate";
export * from "./auth-token-refresh";
export * from "./auth-token-code";
export * from "./auth-token";
export * from "./auth-userinfo";
export * from "./auth-introspect";
export * from "./auth-consent";
export * from "./auth-revoke";
export * from "./auth-interceptors";
export * from "./auth-jwks";
export * from "./auth-two-factor";
