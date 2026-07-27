# SWYRA Auth - OAuth 2.1 Provider

A self-hosted, single-tenant OAuth 2.1 and OIDC provider built with Hono and Better Auth. This is a portfolio artifact designed for maximum portability and security.

## Security Posture & Accepted Risks

During our security auditing, several items were remediated (e.g., client secret hashing, Admin TOTP MFA). However, one item remains documented as an accepted risk for this deployment model:

### Accepted Risk: L2 (Missing Web Application Firewall)
**Description:** The application currently runs without a dedicated Web Application Firewall (WAF) in front of it.
**Status:** Accepted Risk (Timebox limitation).
**Production Upgrade Path:** For production deployments, it is highly recommended to place this service behind CloudFront with AWS WAF enabled, or an API Gateway HTTP API with WAF integrations, to protect against application-layer attacks (e.g., SQLi/NoSQLi, XSS, rate-limit evasion). We do not build this within the current timebox as it is an infrastructure concern rather than application code.

### Centralized MFA for Client Applications
Because this service acts as a centralized OIDC provider, Multi-Factor Authentication (MFA) is tied directly to the user identity, rather than being managed by individual client applications.

If a user enables Two-Factor Authentication (TOTP) on their account (via the `/security` page), they will automatically be prompted for their 6-digit TOTP code when logging into *any* registered OAuth client application.

**Client app developers do not need to write any MFA logic.** They simply redirect to the auth server's authorize endpoint (`/api/auth/oauth2/authorize`). The auth server handles the entire login and 2FA challenge workflow centrally before redirecting back to the client application with the appropriate authorization code or tokens.

*Note on Client App Admins:* Client apps do not configure their own admins. The Auth Server admin promotes a user to the 'admin' role via the Users dashboard. When that user authenticates via OIDC, the 'admin' role is included in their JWT token. The client app reads this claim to grant admin panel access.

## Setup & Deployment

1. **Clone the repository** and install dependencies in both `hono` and `frontend` folders (e.g. `npm install`).
2. **Copy `.env.example`** to `.env` and fill in your values (MongoDB URI, etc.).
3. **Run database migrations**: `cd hono && npx @better-auth/cli migrate` (Note: the MongoDB adapter manages schema dynamically, so this primarily verifies connection and initializes core structures).
4. **Start locally**: `cd hono && npm run dev` (Runs the API on port 3000) and `cd frontend && npm run dev` (Runs the Vite UI).
5. **Deploy** to your chosen platform using the specific deployment notes below.

### Platform-Specific Deploy Notes

Because this service relies on a MongoDB database, connection pooling and execution context constraints vary by platform.

#### AWS Lambda (`lambda.ts`)
- **Reserved Concurrency**: You must configure reserved concurrency to cap the maximum number of simultaneous Lambda executions. If left uncapped, a traffic spike will exhaust MongoDB's connection limit and crash the database.
- **SAM Template**: See `hono/template.yaml` for an example deployment configuration using AWS SAM.

#### Google Cloud Run (`node-server.ts` or Docker)
- **Min Instances**: If using Cloud Run, consider setting `min-instances=1` to keep the database connection pool warm and reduce cold starts.
- **Connection Limits**: Ensure the maximum instances parameter is capped so that concurrent containers do not exceed your MongoDB tier's connection limit.

#### Cloudflare Workers (`cloudflare.ts` / Not officially supported)
- **Known Limitations**: Cloudflare Workers uses V8 isolates and has non-standard TCP/Socket limitations for direct database connections. While Hono works perfectly, connecting directly to MongoDB without a Data API proxy may fail. This is a documented limitation for this project's current architecture.

#### Vercel & Netlify (`vercel.ts`, `netlify.ts`)
- Works out of the box using their respective serverless functions.
- Ensure the region matches your MongoDB cluster region to minimize latency.
