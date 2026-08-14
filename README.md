# Self-Hosted OAuth 2.1 / OIDC Identity Provider

> A pre-written, config-only auth service you deploy once and own forever — with zero always-on infrastructure costs.

This is a complete, self-hosted OAuth 2.1 / OpenID Connect identity provider. Clone it, point it at a MongoDB database, and deploy it anywhere — from a serverless function to a long-lived container. Built with Hono, MongoDB, and the Better Auth identity engine. It includes a complete admin dashboard for managing OAuth clients, configuring dynamic CORS, and provisioning App Admin accounts for registered client applications.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Database Setup](#2-database-setup)
3. [Frontend Deployment (Scenario A — Use the Provided UI)](#3-frontend-deployment-scenario-a)
4. [Backend Deployment (Choose Your Platform)](#4-backend-deployment-choose-your-platform)
   - [Option A: Railway / Render / Fly.io (Long-Lived Container)](#option-a-railway--render--flyio-long-lived-container)
   - [Option B: Vercel / Netlify (Serverless Functions)](#option-b-vercel--netlify-serverless-functions)
   - [Option C: AWS Lambda via SAM](#option-c-aws-lambda-via-sam)
5. [Admin Setup & Provisioning](#5-admin-setup--provisioning)
6. [Building a Custom Frontend (Scenario B)](#6-building-a-custom-frontend-scenario-b)
7. [Documentation & Architecture](#7-documentation--architecture)

---

## 1. Prerequisites

Before you begin, ensure you have the following:

| Requirement | Version / Notes |
|---|---|
| **Node.js** | v18 or higher (v20 recommended) |
| **npm** | Bundled with Node.js |
| **MongoDB database** | Any connection string works; [MongoDB Atlas free tier](https://www.mongodb.com/atlas) is the easiest starting point |
| **Google OAuth credentials** | *(Optional)* Only required if you want "Sign in with Google" |

---

## 2. Database Setup

### 2.1 — Create a MongoDB Atlas Cluster (Free Tier)

1. Sign up at [mongodb.com/atlas](https://www.mongodb.com/atlas) and create a **free M0 cluster**.
2. In **Database Access**, create a database user with **Read and Write** privileges.
3. In **Network Access**, add your server's IP address (or `0.0.0.0/0` for development).
4. Click **Connect → Drivers** and copy your connection string. It will look like:
   ```
   mongodb+srv://<user>:<password>@cluster0.abc123.mongodb.net/oauth?retryWrites=true&w=majority
   ```
   Replace `<user>` and `<password>` with your database user credentials.

### 2.2 — Collections & TTL Indexes

Run the database setup script to create the required collections and apply the TTL indexes. From the `hono/` directory, run:

```bash
npm run db:setup
```

The following collections are managed:

| Collection | Purpose | TTL |
|---|---|---|
| `user` | User accounts and roles | Persistent |
| `session` | Active login sessions | Managed by auth engine |
| `oauthClient` | Registered OAuth 2.1 clients | Persistent |
| `rate_limits` | Per-IP request counters | 60 seconds |
| `origin_cache` | Dynamic CORS origin lookup cache | 300 seconds |

> **Tip:** On MongoDB Atlas free tier (M0), you are limited to **500 connections**. If you deploy to serverless (Vercel, Netlify, Lambda), each cold-start may open a new connection. Keep your concurrency settings aligned with this limit — see [Option C](#option-c-aws-lambda-via-sam) for Lambda-specific guidance.

---

## 3. Frontend Deployment (Scenario A)

> Use this if you want the full package: login/signup pages, OAuth consent screens, TOTP MFA setup, and the admin dashboard — all out of the box.

### Step 1 — Install dependencies

```bash
cd frontend
npm install
```

### Step 2 — Configure the environment

Copy the example file and edit it:

```bash
cp frontend/.env.example frontend/.env
```

Open `frontend/.env` and set the one required variable:

```dotenv
# The base URL where your backend API will be hosted
VITE_AUTH_URL=https://api.auth.yourdomain.com
```

> **Important:** `VITE_AUTH_URL` must be set to the **backend's** public URL, not the frontend's URL. This value is baked into the static bundle at build time.

### Step 3 — Build

```bash
cd frontend
npm run build
```

This produces a static bundle in `frontend/dist/`.

### Step 4 — Deploy the static bundle

Upload the contents of `frontend/dist/` to any static hosting provider:

| Provider | How to deploy |
|---|---|
| **Vercel** | Connect the repo in the Vercel dashboard; set the root directory to `frontend` and output directory to `dist` |
| **Netlify** | Drag and drop `frontend/dist/` into the Netlify dashboard, or use `netlify deploy --dir=frontend/dist` |
| **AWS S3 + CloudFront** | Sync to an S3 bucket with static website hosting enabled, then put CloudFront in front |
| **GitHub Pages** | Push `frontend/dist/` to the `gh-pages` branch |

---

## 4. Backend Deployment (Choose Your Platform)

### Step 1 — Install dependencies

```bash
cd hono
npm install
```

### Step 2 — Configure the environment

```bash
cp .env.example hono/.env
```

Open `hono/.env` and fill in the required values:

```dotenv
NODE_ENV=production

# Your MongoDB connection string from Step 2.1
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/oauth?retryWrites=true&w=majority

# A strong random secret — generate one with:  openssl rand -base64 32
BETTER_AUTH_SECRET=your_32_character_minimum_secret_here

# The public base URL of THIS backend service (the URL callers will use to reach it)
BETTER_AUTH_URL=https://api.auth.yourdomain.com

# The public URL of your deployed frontend (required for CORS)
FRONTEND_URL=https://auth.yourdomain.com

# --- Optional: Google Sign-In ---
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret

# --- Optional: Advanced ---
# Comma-separated CIDRs of trusted reverse proxies (for accurate client IP extraction)
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Set to "true" to allow anyone to register, "false" to require admin invitation
AUTH_PUBLIC_SIGNUP_ENABLED=false
```

> **NOTE:** `AUTH_PUBLIC_SIGNUP_ENABLED` and `AUTH_EMAIL_VERIFICATION_ENABLED` are strictly enforced based on their boolean value, regardless of `NODE_ENV`. Ensure these are set to `false` in any deployment where you do not want open public signups.

> **Caution:** Never commit your `.env` file. It is already in `.gitignore`. Treat `BETTER_AUTH_SECRET` and `MONGO_URI` as production secrets — use your platform's secret management (e.g., Railway Variables, AWS Secrets Manager, Vercel Environment Variables).

---

### Option A: Railway / Render / Fly.io (Long-Lived Container)

Best for: **predictable billing, persistent connections, simple ops.**

#### Build

```bash
cd hono
npm run build
```

This uses `esbuild` to bundle `src/node-server.ts` into a single self-contained Node.js server file at `dist/index.js`.

#### Deploy

1. Push the repository to GitHub.
2. Connect your repo to Railway, Render, or Fly.io.
3. Set the **build command** to `cd hono && npm install && npm run build`.
4. Set the **start command** to `node hono/dist/index.js`.
5. Add all environment variables from Step 2 above in the platform dashboard. Ensure you explicitly set `NODE_ENV=production`.
6. Deploy. The server listens on the `PORT` environment variable (default `3000`).

> **Tip:** Railway and Render will automatically assign a public URL. Use that URL as your `BETTER_AUTH_URL` and update `VITE_AUTH_URL` in your frontend's `.env` before rebuilding the frontend.

---

### Option B: Vercel / Netlify (Serverless Functions)

Best for: **zero cold-infrastructure cost, pay-per-request pricing.**

#### Build for Vercel

```bash
cd hono
npm run build:vercel
```

#### Build for Netlify

```bash
cd hono
npm run build:netlify
```

#### Deploy

- **Vercel**: Connect the repository, set the function entry point to `hono/dist/index.js`, and add all environment variables (including `NODE_ENV=production`) in the Vercel dashboard under Project Settings → Environment Variables.
- **Netlify**: Connect the repository, configure the functions directory to point at `hono/dist/`, and add environment variables (including `NODE_ENV=production`) in Site Settings → Environment Variables.

> **Warning — Serverless connection pooling caveat:** Each serverless invocation may open a new MongoDB connection. MongoDB Atlas **M0 free tier** caps connections at 500. If you expect traffic spikes, upgrade to M2+ or monitor your Atlas connection metrics closely after deployment. Exceeding the connection cap causes `MongoServerSelectionError` under load.

---

### Option C: AWS Lambda (via SAM)

Best for: **AWS-native deployments, fine-grained concurrency control.**

#### Prerequisites

- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate IAM permissions
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)

#### Build

```bash
cd hono
npm run build
```

This bundles `src/lambda.ts` into `dist/index.js`.

#### Deploy

```bash
cd hono
sam build
sam deploy --guided
```

During `sam deploy --guided`, you will be prompted to provide the parameters defined in `hono/template.yaml`:

| Parameter | Value |
|---|---|
| `NodeEnv` | Must be `production` |
| `MongoUri` | Your MongoDB connection string |
| `BetterAuthSecret` | Your 32+ character secret |
| `BetterAuthUrl` | The Lambda Function URL (available after first deploy; run `sam deploy` a second time to set it) |
| `FrontendUrl` | Your frontend's public URL |
| `GoogleClientId` / `GoogleClientSecret` | *(Optional)* Google OAuth credentials |
| `ReservedConcurrency` | **See note below** |

> **Important — Set `ReservedConcurrency` to match your MongoDB Atlas connection limit.**
>
> The `ReservedConcurrency` parameter caps the maximum number of simultaneous Lambda execution environments. Each environment holds one MongoDB connection. On Atlas M0 (free tier, ~500 connections), a value of `10`–`20` is safe. On M10+, you can raise this significantly. Exceeding your Atlas tier's connection limit will cause `MongoServerSelectionError` under load. See [`architecture.md`](./architecture.md) for the full connection-budget analysis.

**Step 1:** Deploy with a placeholder URL for `BetterAuthUrl`.\
**Step 2:** After the first deploy, SAM outputs the **Lambda Function URL**.\
**Step 3:** Update the `BetterAuthUrl` parameter in AWS (via a second `sam deploy` run) with this URL so token issuance uses the correct base URL.

---

## 5. Admin Setup & Provisioning

The first user to register on your auth server is a standard user with no elevated privileges. You must manually promote the *very first* user to `admin` using the provided script so they can access the dashboard.

### Step 1 — Register an account

Navigate to your deployed frontend and create an account with the email address you want to be the administrator.

### Step 2 — Promote the first admin

Run the following command locally, with your production `MONGO_URI` set in `hono/.env`:

```bash
cd hono
npx tsx scripts/make-admin.ts your-email@example.com
```

The script will:
1. Look up the user in MongoDB by email.
2. Ask for interactive confirmation (type `YES` to proceed).
3. Set `role: "admin"` on the user document.
4. Print a timestamped audit log line.

Example output:

```
Are you sure you want to promote your-email@example.com to admin? Type YES to confirm: YES
[2026-07-28T00:00:00.000Z] Promotion logged: User your-email@example.com promoted to admin by <your-os-username>.
```

Once promoted, log out and log back in. The admin dashboard will appear in the navigation.

> **Note:** This script reads `MONGO_URI` from `hono/.env`. Ensure that file points to your **production** database before running.



---

## 6. Building a Custom Frontend (Scenario B)

If you want to build your own login UI, mobile app, or integrate auth into an existing application, you do **not** need to use the provided React frontend at all.

Your custom client simply makes HTTP requests to the backend's standard endpoints:

| Endpoint group | Purpose |
|---|---|
| `/api/auth/*` | All auth operations: sign-up, sign-in, session management, TOTP, OAuth flows |
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/.well-known/jwks.json` | JSON Web Key Set for token verification |
| `/api/auth/oauth2/*` | OAuth 2.1 authorization, token exchange, introspection |

**CORS is handled automatically.** Register your custom frontend's origin as an OAuth client in the admin dashboard. The backend's dynamic CORS middleware will query MongoDB for that origin and allow it — no server redeploy or config change required.

There are no SDK requirements. Any HTTP client in any language can consume this API. The OIDC discovery document at `/.well-known/openid-configuration` describes all available endpoints and supported grant types.

---

## 7. Documentation & Architecture

The following documents describe the engineering decisions, boundaries, and design rationale for this project. Reading them is **not required to deploy**, but is recommended if you want to extend, audit, or contribute to the codebase.

| Document | Description |
|---|---|
| [`architecture.md`](./architecture.md) | System shape, identity engine overview, deployment topology, and MongoDB connection-budget analysis |
| [`boundaries.md`](./boundaries.md) | Hard constraints — what this project intentionally does and does not do |
| [`decision.md`](./decision.md) | Architectural Decision Records (ADRs) — the "why" behind key technical choices |
| [`design.md`](./design.md) | UI/UX design system and component architecture for the frontend |
| [`phases.md`](./phases.md) | Development phase log — what was built in each phase |

---

## Local Development

To run the full stack locally using Docker Compose:

```bash
# From the repository root
docker compose up
```

This starts a local MongoDB instance, the Hono API dev server on port `3000`, and the Vite frontend dev server on port `5174`.

To run services individually without Docker:

```bash
# Terminal 1 — Backend
cd hono && npm run dev

# Terminal 2 — Frontend
cd frontend && npm run dev
```

---

## Security Checklist

- [ ] `BETTER_AUTH_SECRET` is at least 32 characters and stored as a secret, not in source control
- [ ] `AUTH_PUBLIC_SIGNUP_ENABLED` is set to `false` (unless you explicitly want open signups)
- [ ] `TRUSTED_PROXY_CIDRS` matches your actual proxy/load-balancer CIDR ranges
- [ ] MongoDB network access is restricted to your server's IP (not `0.0.0.0/0`)
- [ ] `ReservedConcurrency` (Lambda) or connection pool size is within your Atlas tier's limit
- [ ] At least one account has been promoted to `admin` before locking down sign-ups


---

*Built with [Hono](https://hono.dev), [MongoDB](https://www.mongodb.com), and the Better Auth OAuth 2.1 / OIDC identity engine.*
