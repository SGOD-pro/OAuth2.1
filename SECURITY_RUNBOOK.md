# Security Runbook: Incident Response, Key Rotation & Operations

**Target System:** [SGOD-pro/OAuth2.1 Identity Provider](file:///home/swyra/projects/OAuth2.1)  
**Audience:** Site Reliability Engineers, Security Operations, Identity Engineers  
**Classification:** Operational Security Runbook  

---

## 1. Incident Response Procedures

### 1.1 Suspected User Account Compromise
**Trigger:** User reports unauthorized access or anomalous login telemetry detected.
1. **Disable the user account:**
   ```bash
   mongosh "$MONGO_URI" --eval '
     db.user.updateOne(
       { email: "victim@example.com" },
       { $set: { disabled: true, isActive: false, updatedAt: new Date() } }
     );
   '
   ```
2. **Purge all active sessions for the user:**
   ```bash
   mongosh "$MONGO_URI" --eval '
     const u = db.user.findOne({ email: "victim@example.com" });
     if (u) {
       db.session.deleteMany({ userId: u.id || u._id.toString() });
     }
   '
   ```
3. **Revoke all active token families (Refresh Tokens) for the user:**
   ```bash
   mongosh "$MONGO_URI" --eval '
     const u = db.user.findOne({ email: "victim@example.com" });
     if (u) {
       db.oauth_token_families.updateMany(
         { userId: u.id || u._id.toString() },
         { $set: { activeTokenHash: null, revoked: true, revokedReason: "incident_response_manual", updatedAt: new Date() } }
       );
     }
   '
   ```

---

### 1.2 Suspected Application Admin Compromise
**Trigger:** An App Admin account password or JWT has been exfiltrated.
1. **Immediate Invalidation via Admin API or Direct DB:**
   ```bash
   mongosh "$MONGO_URI" --eval '
     db.app_admins.updateOne(
       { email: "admin@app.example.com" },
       { $set: { isActive: false, tokensRevokedBefore: new Date(), updatedAt: new Date() } }
     );
   '
   ```
   *Note: Updating `tokensRevokedBefore` immediately invalidates all previously issued JWTs even if the account is later reactivated.*
2. **Rotate Admin Password:**
   Instruct the legitimate administrator to change their password via the self-service flow, or update their password hash and set `passwordChangedAt = new Date()`.

---

### 1.3 Suspected Client Secret Compromise
**Trigger:** An OAuth confidential client secret has leaked in public repositories or logs.
1. **Rotate the client secret immediately via Admin API:**
   ```bash
   curl -X POST https://oauth21.vercel.app/api/admin/clients/{clientId}/rotate-secret \
     -H "Cookie: better-auth.session_token=SUPER_ADMIN_SESSION" \
     -H "x-gateway-secret: $INTERNAL_GATEWAY_SECRET"
   ```
2. **Update Consumer Application Backend:**
   Update the `CLIENT_SECRET` environment variable in the consumer deployment (e.g. AWS Lambda / ECS).
3. **If immediate shutdown is needed:**
   Disable the client to halt all authorization and token issuance:
   ```bash
   mongosh "$MONGO_URI" --eval '
     db.oauthClient.updateOne(
       { clientId: "{clientId}" },
       { $set: { disabled: true, updatedAt: new Date() } }
     );
   '
   ```

---

## 2. Cryptographic Key & Secret Rotation

### 2.1 Better Auth Secret Rotation (`BETTER_AUTH_SECRET`)
- **Impact:** Rotates the signing and encryption key for Better Auth user session cookies.
- **Downtime / Session Impact:** Existing sessions signed with the old secret will become invalid and require users to re-login.
- **Procedure:**
  1. Generate high-entropy 256-bit secret: `openssl rand -base64 32`.
  2. Update secret in AWS Secrets Manager / Parameter Store.
  3. Deploy updated environment variable to the AWS Lambda backend.
  4. Verify health check: `curl https://oauth21.vercel.app/health`.

### 2.2 App Admin JWT Secret Rotation (`APP_ADMIN_JWT_SECRET`)
- **Impact:** All active App Admin dashboard sessions will expire and require re-authentication.
- **Procedure:**
  1. Generate new secret: `openssl rand -hex 32`.
  2. Update AWS Lambda environment variable `APP_ADMIN_JWT_SECRET`.
  3. All subsequent calls to `/api/auth/app-admin/verify` will use the new key.

### 2.3 Internal Gateway Secret Rotation (`INTERNAL_GATEWAY_SECRET`)
- **Zero-Downtime Migration Pattern:**
  1. Temporarily configure IdP to accept either the old or new secret via comma-separated list or secondary header `x-internal-secret`.
  2. Update Edge Gateway (Vercel / CloudFront) to inject the new secret.
  3. Deploy new single secret to AWS Lambda once edge propagation completes.

---

## 3. Consumer Onboarding & Security Checklist

When registering a new OAuth 2.1 consumer application in production:

1. **Client Identification:**
   - Assign unique, immutable `clientId` (e.g., `client_prod_<unique_id>`).
2. **Confidential vs Public Client:**
   - Server-side applications (Node.js, Express, Next.js Server Components): `isPublic: false` (Must require client secret).
   - Single-Page Applications (SPA) / Mobile Apps: `isPublic: true` (Must use PKCE without client secret).
3. **Redirect URIs:**
   - Must use explicit, strict `https://` URIs.
   - **Never permit loopback (`localhost`, `127.0.0.1`) in production environments.**
   - Wildcards and path traversals (`*`, `..`) are strictly rejected by the IdP.
4. **Allowed Origins:**
   - Restrict CORS `allowedOrigins` to the exact consumer frontend domain.
5. **Private vs Public Tenant Access:**
   - If the application is internal enterprise software, set `isPublic: false`.
   - Explicitly enroll allowed users in `user_applications` before authorizing logins.
6. **Consumer Callback Verification:**
   - Ensure the consumer application defines `AUTH_CALLBACK_URL` in its deployment environment to prevent dev-mode fallbacks.

---

## 4. Verification & Diagnostic Commands

Run these automated verification commands to confirm the healthy state of the security boundary:

```bash
# Run the complete adversarial test gate (85 security tests)
npm run test:all-security

# Run individual targeted attack suites:
npm run test:full-adversarial      # Master gate: token-race, grace, admin lifecycle
npm run test:direct-backend         # Bypass attempts via direct Lambda URL
npm run test:session-hijack         # Session replay and fixation tests
npm run test:oauth-tx               # Parallel-tab and state transaction binding
npm run test:credential-comp        # Blast-radius of leaked secrets & tokens
npm run test:cross-tenant           # Strict cross-app boundary isolation
npm run test:prod-vs-dev            # Production configuration & loopback denial
npm run test:deployed-consumer      # Live consumer integration tests

# Validate SAM deployment configuration
sam validate --lint
```
