# SWYRA Auth -- Troubleshooting Guide (TROUBLESHOOTING.md)

**Authority:** Authoritative Triage, Error Catalog & Debugging Guide for SWYRA Auth  
**Target:** Integrating Developers, AI Coding Agents, and Operations Teams  

---

## 1. Standard OAuth 2.1 Error Code Reference

SWYRA Auth emits standard, machine-readable OAuth 2.1 / RFC 6749 error codes. Below is the normative reference:

| Error Code | HTTP Status | RFC Definition | Common Cause in SWYRA Auth |
|---|---|---|---|
| `invalid_request` | 400 | Request is missing a required parameter, includes an unsupported parameter, or is malformed. | Missing `code_challenge`, missing `state`, redirect URI mismatch, or malformed body. |
| `invalid_client` | 400 / 401 | Client authentication failed. | Invalid `CLIENT_SECRET`, unknown `CLIENT_ID`, or client document has `disabled: true`. |
| `unauthorized_client` | 403 | The client is not authorized to request an authorization code using this method. | Attempting dynamic client registration or using an unauthorized grant type. |
| `access_denied` | 302 / 403 | The resource owner or authorization server denied the request. | User is unassigned on a private application (`isPublic: false`), or user denied consent. |
| `invalid_grant` | 400 / 401 | The authorization code or refresh token is invalid, expired, revoked, or replayed. | Replayed authorization code, incorrect `code_verifier`, or replayed refresh token. |
| `unsupported_grant_type` | 400 | The authorization grant type is not supported by the authorization server. | Using `grant_type=password` (strictly disabled in OAuth 2.1). |
| `invalid_token` | 401 | The access token provided is expired, revoked, malformed, or invalid. | Expired access token, untrusted signature, or cross-client access attempt. |
| `registration_disabled` | 403 | Self-registration is forbidden for this application. | Calling `POST /api/auth/sign-up/email` with a private application `client_id`. |

---

## 2. Common Symptoms, Causes, and Safe Resolutions

### 2.1 "The redirect_uri is not registered for this application" (`invalid_request`)

- **Symptom:** The `/api/auth/oauth2/authorize` endpoint returns HTTP 400 with `error: "invalid_request"`.
- **Root Cause:**
  1. **Trailing Slash Mismatch:** The client configuration has `https://app.com/callback/` (with slash) while the IdP record has `https://app.com/callback` (without slash).
  2. **Scheme Mismatch:** Attempting `http://` instead of `https://` in production.
  3. **Localhost in Production:** Providing `http://localhost:3000/callback` when the registered client has `isDev: false`.
- **Safe Resolution:**
  - Verify the registered redirect URIs: `GET /api/admin/clients` (or check the admin dashboard).
  - Update consumer configuration to match the registered URI character-for-character.
  - **FORBIDDEN:** Do NOT add wildcard or regex redirect URIs.

---

### 2.2 "Access restricted: Your account is not authorized for this private application" (`access_denied`)

- **Symptom:** User logs in at the IdP, but is redirected to the consumer callback with `error=access_denied`.
- **Root Cause:** The application has `isPublic = false`, and this authenticated user has not been provisioned in the `user_app_registrations` table.
- **Safe Resolution:**
  - An administrator must provision the user for this client:
    ```bash
    POST /api/admin/clients/:clientId/users
    Authorization: Bearer <admin_session>
    Content-Type: application/json

    { "userId": "<user_id>" }
    ```
  - **FORBIDDEN:** Do NOT switch `isPublic` to `true` unless the application is intentionally becoming a public platform app.

---

### 2.3 "Self-registration is disabled for this private application" (`registration_disabled`)

- **Symptom:** Direct API call to `POST /api/auth/sign-up/email?client_id=...` returns HTTP 403.
- **Root Cause:** By design, private applications (`isPublic: false`) do not permit public self-registration.
- **Safe Resolution:**
  - Accounts must be pre-provisioned by administrators using the Admin API or Super-Admin portal.
  - In the consumer UI, do not provide a "Sign Up" button; direct users to "Log In with Corporate ID".

---

### 2.4 "Direct access to management endpoints forbidden; gateway authentication required"

- **Symptom:** API calls to `/api/admin/*` return HTTP 403 `forbidden`.
- **Root Cause:** The request was sent directly to the AWS Lambda Function URL instead of through the Vercel edge reverse proxy, or the `x-gateway-secret` header is missing/incorrect.
- **Safe Resolution:**
  - Direct all API traffic through the canonical domain (`https://oauth21.vercel.app/api/...`).
  - Verify that `INTERNAL_GATEWAY_SECRET` is set in Vercel environment variables and matches the Lambda configuration.

---

### 2.5 "Refresh token has been revoked due to replay detection" (`invalid_grant`)

- **Symptom:** Subsequent refresh attempts fail with HTTP 401 and `error: "invalid_grant"`.
- **Root Cause:** Two concurrent requests attempted to refresh using the same refresh token, or an old token was re-sent after rotation. The IdP's CAS state machine detected a replay and revoked the entire token family.
- **Safe Resolution:**
  - Clear local tokens on the consumer backend.
  - Redirect the user to log in again via `/api/auth/oauth2/authorize` with a fresh PKCE flow.
  - In consumer code, implement client-side queuing or mutex locks during token refresh to avoid concurrent refresh calls.

---

## 3. Safe Debugging Protocols

When diagnosing authentication issues:

1. **Inspect Tokens Without Exposing Secrets:**
   - Decode JWT payloads using `jwt.decode(token, { complete: true })` to inspect `sub`, `iss`, `aud`, `exp`, and `role`.
   - Never print `CLIENT_SECRET` or user passwords into console logs.
2. **Verify Public Keys with cURL:**
   ```bash
   curl -s https://oauth21.vercel.app/.well-known/jwks.json | jq .
   ```
   Ensure the `keys` array contains valid RS256 RSA keys.
3. **Verify OIDC Discovery with cURL:**
   ```bash
   curl -s https://oauth21.vercel.app/.well-known/openid-configuration | jq .
   ```
   Verify that `issuer` matches your `AUTH_ISSUER` exactly.
4. **Forbidden "Fixes":**
   - NEVER bypass PKCE (`code_challenge`) to "test if PKCE is the problem".
   - NEVER disable `state` verification.
   - NEVER change `isDev` to `true` on production clients.
   - NEVER add localhost fallback literals in configuration files.
