import { Hono } from "hono";

/**
 * Legacy Application Admin Authentication Subsystem
 *
 * PERMANENTLY RETIRED:
 * All consumer applications and client administrators authenticate exclusively
 * via the centralized OAuth 2.1 Authorization Code Flow with PKCE (S256).
 *
 * Direct credential relay (sending client_id, client_secret, email, password)
 * and legacy admin_token issuance/verification are permanently retired.
 *
 * In accordance with RFC 9110 §15.5.11, all legacy endpoints return HTTP 410 Gone.
 */
const appAdminAuth = new Hono();

const RETIRED_RESPONSE = {
	error: "endpoint_retired",
	error_description: "Legacy credential-relay app-admin authentication is permanently retired. All client administrators must authenticate via centralized OAuth 2.1 Authorization Code Flow with PKCE.",
};

function handleRetiredEndpoint(c: any) {
	c.header("Cache-Control", "no-store");
	c.header("Pragma", "no-cache");
	return c.json(RETIRED_RESPONSE, 410);
}

// Explicit handlers for retired endpoints
appAdminAuth.all("/login", handleRetiredEndpoint);
appAdminAuth.all("/verify", handleRetiredEndpoint);
appAdminAuth.all("/logout", handleRetiredEndpoint);
appAdminAuth.all("/mfa/verify-login", handleRetiredEndpoint);
appAdminAuth.all("/mfa/setup", handleRetiredEndpoint);
appAdminAuth.all("/mfa/confirm", handleRetiredEndpoint);
appAdminAuth.all("/mfa/disable", handleRetiredEndpoint);
appAdminAuth.all("/mfa/*", handleRetiredEndpoint);
appAdminAuth.all("/*", handleRetiredEndpoint);

export default appAdminAuth;
