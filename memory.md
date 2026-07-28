
# Memory

## Who this is for
Future sessions picking this project back up. Read this before re-deriving decisions.

## Builder context
- Final-year MSc CS student, KIIT, India. Needs to earn ASAP — job applications run in parallel.
- Portfolio artifact, not a startup. No monetization path.

## Settled decisions — do not re-litigate
- Self-hosted, single-tenant-per-deployment model.
- MongoDB stays. DynamoDB completely replaced by MongoDB TTL collections for portability.
- **Identity Engine**: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- Multi-platform deploy via Hono adapters (`lambda.ts`, `vercel.ts`, `node-server.ts`).
- Admin MFA uses the Better Auth TOTP plugin. QR codes generated locally via `qrcode.react` to prevent secret leakage.
- App Admin Provisioning uses OIDC roles (user is created with `role: "admin"` and tied to `oauthClient` doc). No multi-tenancy.
- Data protection uses hashing, TLS, and infrastructure at-rest encryption. No hand-rolled encryption.
- Security scan remediation: M10 fixed, H4b resolved by TOTP, L2 documented, client-secret hashing verified.

## Stable facts about the existing system
- Admin access is server-side role-gated.
- CORS is dynamic, exact origin matching, cached in MongoDB TTL collection.
- Rate limiting targets `/api/auth/*` exclusively (10 req/min) to allow smooth `/api/admin/*` navigation.
- Frontend uses Zustand with a 30s TTL cache for admin dashboard data.
- Phase 0, 1, 2, and 3 are COMPLETED. E2E security tests (7 points) pass successfully.

## Working rules for future sessions
- Start from the nearest concrete file or runtime behavior.
- Prefer the smallest verified change over a broad refactor.
- Do not widen scope toward multi-tenancy, multi-DB support, or SaaS features.
- Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- Do not use external APIs for QR code generation.

## Open items (update as resolved)
- **Phase 4 In Progress**: Deployment documentation, public repo push, and public writeup.
  - 4a: Write detailed `README.md` deployment guides for MongoDB, Frontend, and 3 backend targets (Railway, Vercel, AWS Lambda).
  - 4b: Finalize markdown files and push to GitHub.
  - 4c: Write the public LinkedIn/Blog post.
  - 4d: Add to resume/LinkedIn.
- **Deferred**: Email verification at signup stays off until a real mailer is wired.
