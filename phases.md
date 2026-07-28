# Implementation Phases

## Ground rule
This runs in **parallel** with job applications, not before them. Total project clock: **3 weeks**, part-time. A phase does not begin until the previous phase is verified against a concrete check.

## Phase 0: Triage (COMPLETED)
Status: Done. Evidence in `memory.md`.

## Phase 1: Portability & Security Hardening (COMPLETED)
Status: Done. 
- 1a: MongoDB TTL migration (replaced DynamoDB entirely).
- 1c: Security scan remediation (M10 fixed, client-secret hashing verified, L2 documented).
- 1d: Multi-platform deploy config (Vercel, Netlify, Node-server entry points added).
- 1e: Config-only self-host verification passed.

## Phase 2: Premium Frontend Redesign (COMPLETED)
Status: Done. 
- Integrated the "Cohere" design system (glassmorphism, mesh gradients, noise/grain).
- Implemented `next-themes` for dark/light mode.
- Added `zustand` state management with 30s TTL cache and optimistic UI updates.
- Refined backend rate limiting to target `/api/auth/*` exclusively.

## Phase 3: MFA & App Admin Provisioning (COMPLETED)
Status: Done. 
- Identity Engine: Better Auth v1.x via npm. Implements OAuth 2.1/OIDC, session management, and TOTP MFA.
- Admin TOTP MFA (fixed setup loop, client-side QR generation, login enforcement).
- Client App MFA Inheritance (verified OIDC flow halts for MFA).
- App Admin Provisioning (created `POST /api/admin/users`, tied to `oauthClient` schema).
- E2E Security Validation (7-point automated test suite passed).

## Phase 4: Deployment Documentation & Shipping (Current Phase)
Goal: The artifact is public, deployable by strangers on any platform, and legible to someone evaluating it in an interview. **Do not write more application code unless a critical bug is found.**

### 4a. Deployment Documentation (The README)
The `README.md` must be updated with explicit, copy-pasteable deployment guides for the self-hoster. It must cover database setup, frontend deployment, and the three primary backend deployment targets.
1. **Database Setup Guide**:
   - Instructions for creating a MongoDB Atlas free tier cluster.
   - Instructions for running the `npm run db:setup` script to initialize collections and TTL indexes.
2. **Frontend Deployment Guide**:
   - Instructions for building the React frontend (`npm run build`).
   - Instructions for deploying the static `dist/` folder to Vercel, Netlify, or S3+CloudFront.
   - Instructions for setting the `VITE_API_URL` environment variable.
3. **Backend Deployment Guides (Pick One)**:
   - **Option A: Railway / Render / Fly.io (Long-lived Container)**:
     - Instructions to run `npm run build:node` (targets `node-server.ts`).
     - Instructions to deploy the `dist/index.js` bundle.
     - Notes on setting environment variables (`MONGODB_URI`, `BETTER_AUTH_SECRET`, `FRONTEND_URL`).
   - **Option B: Vercel / Netlify (Serverless Functions)**:
     - Instructions to run `npm run build:vercel` or `npm run build:netlify`.
     - Notes on setting environment variables in the platform dashboard.
     - Warning about serverless connection pooling and ensuring the MongoDB tier can handle it.
   - **Option C: AWS Lambda (via SAM/CloudFormation)**:
     - Instructions to deploy via AWS SAM using the provided `hono/template.yaml`.
     - Instructions on setting `ReservedConcurrentExecutions` to match their MongoDB Atlas tier.
4. **Admin Promotion Guide**:
   - Instructions on how to register the first user and run `make-admin.ts` to gain dashboard access.

### 4b. Repository Finalization
- Ensure all 9 markdown files (`architecture.md`, `boundaries.md`, `decision.md`, `design.md`, `phases.md`, `projectrequirement.md`, `memory.md`, `ui-ux.md`, `rules.md`, `project.md`) are present, detailed, and current.
- Double-check that `.env` is in `.gitignore` and `.env.example` is visible.
- Push the repository to GitHub as public.

### 4c. Public Writeup (Blog or LinkedIn)
Write one public post narrating the real engineering decisions made under this scope:
- The `lambda-edge`/`aws-lambda` bug and why it mattered.
- Why MongoDB TTL collections replaced DynamoDB (portability without new infrastructure).
- The decision to vendor the identity engine (removing the `better-auth` dependency for complete code ownership).
- The App Admin Provisioning architecture (using OIDC roles instead of multi-tenancy).
- The Hono middleware ordering bug that almost bypassed the rate limiter.

### 4d. Resume & LinkedIn Update
- Add the project to your resume with a link to the repo and the writeup.
- Use bullet points like: "Architected a multi-platform OIDC identity provider using Hono and MongoDB, deployable to AWS Lambda, Vercel, and Node containers with zero always-on infrastructure."
- "Hardened admin APIs via Better Auth TOTP MFA, dynamic CORS, and atomic rate limiting backed by MongoDB TTL indexes."

**Gate**: Phase 4 is done when the README contains the deployment guides, the public repo is pushed, the public writeup exists, and both are linked from resume/LinkedIn. 

## Phase Gate Rule
- A phase may not begin until the previous one is verified against the concrete checks listed.
- If the 3-week clock runs out mid-phase, the project freezes at the last verified phase and ships in that state.
