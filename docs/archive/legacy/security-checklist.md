Authentication Security Checklist
1. JWT Token Theft (Bearer Token Leak)

Risk: Attacker steals an access token and impersonates the user.

Keep access tokens short-lived (5–15 minutes).
Store refresh tokens separately.
Use refresh token rotation.
Include exp, iat, jti, and sid claims.
Validate signature and expiration on every request.
Revoke sessions immediately after password changes or suspicious activity.
2. Refresh Token Theft

Risk: Attacker keeps generating new access tokens.

Store only hashed refresh tokens in the database.
Rotate refresh tokens after every use.
Detect refresh token reuse.
Revoke the entire session if reuse is detected.
Set expiration (7–30 days).
3. Session Hijacking

Risk: Attacker takes over an active logged-in session.

Assign every login a unique session_id.
Store session state in Redis or a database.
Allow logout from individual devices.
Support "Logout from all devices."
Expire inactive sessions automatically.
4. Cookie Security

Risk: Browser exposes authentication cookies.

Use HttpOnly.
Use Secure.
Use SameSite=Lax or Strict.
Never expose refresh tokens to JavaScript.
5. XSS (Cross-Site Scripting)

Risk: Malicious JavaScript steals data.
does the server have xml scripting protection..??
Never store sensitive tokens in LocalStorage.
Escape user-generated content.
Enable Content Security Policy (CSP).
Sanitize HTML inputs.
Avoid innerHTML when possible.
6. CSRF (Cross-Site Request Forgery)

Risk: Another website performs actions on behalf of the user.

Use SameSite cookies.
Add CSRF tokens for cookie-based authentication.
Validate Origin and Referer headers.
Require POST/PUT/DELETE for state-changing operations.
7. Replay Attack

Risk: Captured requests are replayed later.

Include expiration timestamps.
Use jti for unique token IDs.
Reject reused refresh tokens.
Consider DPoP or request signing for high-security APIs.
8. Credential Stuffing

Risk: Attackers try leaked passwords.

Rate-limit login attempts.
Add exponential backoff.
Require MFA after suspicious attempts.
Notify users about unusual login attempts.
9. Brute Force Attack

Risk: Password guessing.

Limit attempts per IP.
Limit attempts per account.
Temporarily lock accounts after repeated failures.
Log failed attempts.
10. Device Security

Risk: Login from unknown devices.

Track trusted devices.
Notify users of new device logins.
Require MFA for new devices.
Allow users to remove devices.
11. Suspicious Login Detection

Risk: Stolen credentials used elsewhere.

Detect impossible travel.
Detect country changes.
Detect ASN or ISP changes.
Detect unusual login times.
Trigger step-up authentication.
12. Password Security

Risk: Weak password storage.

Hash passwords with Argon2id (preferred), bcrypt, or scrypt.
Never store plaintext passwords.
Use unique salts.
Enforce reasonable password strength.
13. MFA (Multi-Factor Authentication)

Risk: Password alone gets compromised.

Support TOTP apps.
Support backup recovery codes.
Require MFA for sensitive actions.
Require MFA after suspicious logins.
14. API Security

Risk: Unauthorized API access.

Validate JWT on every request.
Check user permissions.
Implement RBAC or ABAC.
Never trust client-provided roles.
15. Secrets Management

Risk: Signing keys get leaked.

Store secrets in AWS Secrets Manager or Vault.
Rotate signing keys.
Use kid for key rotation.
Never commit secrets to Git.
16. Logging & Monitoring

Risk: Attacks go unnoticed.

Log successful logins.
Log failed logins.
Log refresh token reuse.
Log session revocations.
Monitor unusual activity.
Never log passwords or tokens.
17. Rate Limiting

Risk: Abuse and DoS.

Limit login endpoints.
Limit OTP requests.
Limit password reset requests.
Limit API requests per user and IP.
18. Logout Security

Risk: Old tokens remain usable.

Revoke the session.
Delete refresh tokens.
Clear authentication cookies.
Support global logout.
19. Password Reset Security

Risk: Account takeover through reset flow.

Use one-time reset tokens.
Set short expiration (10–15 minutes).
Invalidate after use.
Revoke existing sessions after reset.
20. Email Verification

Risk: Fake or mistyped accounts.

Verify email before sensitive actions.
Use one-time verification links.
Expire verification tokens.