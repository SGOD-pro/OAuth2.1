# Deployment & CI/CD Checklist

## 1. Pre-Deployment
- [ ] MongoDB Atlas cluster is created.
- [ ] MongoDB Atlas Network Access has `0.0.0.0/0` allowed (required for dynamic AWS Lambda egress IPs).
- [ ] `backend/.env` has `MONGO_URI` and 32+ character `BETTER_AUTH_SECRET`, `APP_ADMIN_JWT_SECRET`, and `APP_ADMIN_TOTP_KEY`.
- [ ] Run `cd backend && npm run db:setup` to initialize TTL indexes in MongoDB.
- [ ] Google Cloud Console OAuth 2.0 Client ID and Secret created (if Google Auth is desired).

## 2. Automated CI/CD Setup (GitHub Actions)
- [ ] In GitHub Repository Settings > **Secrets and variables > Actions**, configure:
  - **AWS Backend Secrets**:
    - `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (or `AWS_ROLE_ARN` for OIDC)
    - `AWS_REGION` (e.g. `ap-south-1`)
  - **Vercel Frontend Secrets**:
    - `VERCEL_TOKEN`
    - `VERCEL_ORG_ID`
    - `VERCEL_PROJECT_ID`
- [ ] Verify `.github/workflows/ci.yml` runs on pull requests and pushes.
- [ ] Verify `.github/workflows/deploy.yml` triggers automatically on push to `main`.
- [ ] See full setup instructions in [docs/CICD.md](docs/CICD.md).

## 3. Backend Deployment (AWS Lambda via SAM)
- [ ] Run `cd backend && ./deploy.sh` (or `sam deploy --guided --profile aws`).
- [ ] Confirm stack deployment succeeds.
- [ ] Copy the generated **Lambda Function URL** (e.g., `https://<id>.lambda-url.<region>.on.aws/`).
- [ ] Verify backend health check by calling `curl https://<id>.lambda-url.<region>.on.aws/` (should return `{"message": "Health check", "status": "ok"}`).

## 4. Frontend Deployment (Vercel)
- [ ] Connect repo to Vercel with Root Directory set to `frontend`.
- [ ] Set `VITE_AUTH_URL` environment variable in Vercel to the Lambda Function URL (`https://<id>.lambda-url.<region>.on.aws`).
- [ ] Ensure `vercel.json` rewrite rules are present in `frontend/vercel.json`.
- [ ] Deploy and copy the production frontend URL (e.g., `https://oauth21.vercel.app`).

## 5. Cloud & OAuth Configuration Alignment
- [ ] In Google Cloud Console:
  - **Authorized JavaScript origins**: `https://<frontend-domain>`
  - **Authorized redirect URIs**: `https://<lambda-url>/api/auth/callback/google`
- [ ] In `backend/samconfig.toml`:
  - `BetterAuthUrl` set to `https://<lambda-url>/api/auth`
  - `FrontendUrl` set to `https://<frontend-domain>` (strict origin, no trailing paths).
- [ ] Run `cd backend && ./deploy.sh` to apply parameter updates to AWS Lambda.

## 6. Admin Account Provisioning & Verification
- [ ] Run `cd backend && npm run admin:create -- "admin@example.com" "YourStrongPassword@123!" "Admin Name"`.
- [ ] Visit `https://<frontend-domain>/admin/login` and sign in.
- [ ] Verify Admin Dashboard loads overview stats and client tables without 401/404 errors.
- [ ] Test creating an OAuth 2.1 client in Admin Console.
- [ ] Test TOTP 2FA setup in Admin Security tab.