# Deployment Checklist

## Pre-Deploy
- Confirm environment variables are present and pass schema validation.
- Confirm Better Auth secret material is set for the target environment.
- Confirm MongoDB connectivity.
- Confirm Google OAuth client credentials are present.
- Confirm frontend URL and auth base URL are aligned.

## Security Checks
- Confirm redirect URI validation is active.
- Confirm dynamic CORS only allows registered origins.
- Confirm admin routes require a valid session and admin role.
- Confirm CSRF protection is enabled for admin mutations.
- Confirm security headers are present at the API edge.

## Build Checks
- Build the Hono Lambda bundle.
- Build the frontend production bundle.
- Confirm the frontend can talk to the API through the intended public origin.
- Confirm the health check endpoint responds successfully.

## Local Release Checks
- Confirm Docker Compose starts API, frontend, and Nginx cleanly.
- Confirm sign-in, consent, callback, and admin login routes load.
- Confirm admin client CRUD works with cache invalidation.
- Confirm logs and stats endpoints return expected data.

## Production Release Checks
- Confirm Lambda deployment package is ready.
- Confirm S3 + CloudFront assets are published.
- Confirm TLS and reverse proxy configuration is correct if Nginx is still in path.
- Confirm monitoring and rollback notes exist.

## Post-Deploy
- Re-run auth flows.
- Re-run admin access checks.
- Re-check CORS behavior from an allowed and a disallowed origin.
- Re-check token issuance and introspection paths.