# CI/CD & Automated Deployment Guide

SWYRA Auth features an enterprise-grade, automated CI/CD pipeline implemented with **GitHub Actions**. It enforces automated security testing, linting, build verification, and zero-downtime deployments for both the **Hono Backend (AWS Lambda via SAM)** and the **React Frontend Gateway (Vercel)**.

---

## 1. Pipeline Architecture

```mermaid
flowchart TD
    subgraph Triggers["Pipeline Triggers"]
        PR["Pull Request to main"]
        Push["Push to main branch"]
        Manual["Manual Trigger (workflow_dispatch)"]
    end

    subgraph CI["1. Continuous Integration (ci.yml)"]
        FrontCI["Frontend Job<br/>• ESLint validation<br/>• TypeScript check & Vite build"]
        BackCI["Backend Job<br/>• MongoDB 6 Service Container<br/>• Automated Security Test Suite (11 suites)<br/>• Lambda + Node server bundling<br/>• SAM template linting & validation"]
    end

    subgraph CD["2. Continuous Deployment (deploy.yml)"]
        Filter["Change Detection Filter<br/>(backend/ vs frontend/ diff)"]
        DeployBack["Deploy Backend (AWS SAM)<br/>• MongoDB pre-flight test<br/>• SAM build & package<br/>• Deploy Lambda stack (ap-south-1)<br/>• Function URL health probe"]
        DeployFront["Deploy Frontend (Vercel)<br/>• Production build & assets<br/>• Vercel prebuilt deployment<br/>• Edge gateway smoke test"]
    end

    subgraph Targets["3. Production Infrastructure"]
        Lambda["AWS Lambda (ap-south-1)<br/>https://...lambda-url.ap-south-1.on.aws"]
        Vercel["Vercel Production Edge<br/>https://oauth21.vercel.app"]
    end

    PR --> CI
    Push --> Filter
    Manual --> Filter
    Filter -- "backend changed" --> DeployBack
    Filter -- "frontend changed" --> DeployFront
    DeployBack --> Lambda
    DeployFront --> Vercel
```

---

## 2. GitHub Repository Secrets Setup

Navigate to your GitHub repository: **Settings > Secrets and variables > Actions > New repository secret**.

### A. AWS Lambda Deployment Secrets (Backend)

| Secret Name | Required | Example | Description |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | Yes* | `AKIAIOSFODNN7EXAMPLE` | IAM access key with permissions to deploy CloudFormation and Lambda. |
| `AWS_SECRET_ACCESS_KEY` | Yes* | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | IAM secret access key. |
| `AWS_REGION` | No | `ap-south-1` | AWS region where the SAM stack is deployed (defaults to `ap-south-1`). |
| `AWS_ROLE_ARN` | Optional* | `arn:aws:iam::123456789012:role/GitHubDeployRole` | Recommended alternative for keyless OIDC authentication instead of static IAM keys. |

*\* Either `AWS_ROLE_ARN` (OIDC) or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` must be configured.*

#### Recommended AWS IAM Least-Privilege Policy
For the deployment IAM user or OIDC role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeChangeSet",
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:GetTemplate",
        "cloudformation:GetTemplateSummary"
      ],
      "Resource": "arn:aws:cloudformation:ap-south-1:*:stack/oauth/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunctionUrlConfig",
        "lambda:CreateFunctionUrlConfig",
        "lambda:UpdateFunctionUrlConfig"
      ],
      "Resource": "arn:aws:lambda:ap-south-1:*:function:oauth-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::aws-sam-cli-managed-default-*",
        "arn:aws:s3:::aws-sam-cli-managed-default-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "iam:GetRole",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "arn:aws:iam::*:role/oauth-*"
    }
  ]
}
```

---

### B. Vercel Deployment Secrets (Frontend)

| Secret Name | Required | Example | Description |
|---|---|---|---|
| `VERCEL_TOKEN` | **Yes** | `a1b2c3d4...` | Personal Access Token created in [Vercel Account Tokens](https://vercel.com/account/tokens). |
| `VERCEL_ORG_ID` | **Yes** | `team_abc123...` | Found in `.vercel/project.json` or Vercel Team Settings. |
| `VERCEL_PROJECT_ID` | **Yes** | `prj_xyz789...` | Found in Vercel Project Settings > General. |

#### How to Retrieve Vercel Org and Project IDs:
If you have deployed locally with Vercel CLI:
```bash
cd frontend
npx vercel link
cat .vercel/project.json
# Output:
# { "orgId": "team_...", "projectId": "prj_..." }
```

---

## 3. Workflow Details

### 1. Continuous Integration (`.github/workflows/ci.yml`)
- **Triggers**: Pull requests targeting `main`, or direct pushes to feature branches.
- **Frontend Job**:
  - Validates code with ESLint (`npm run lint`).
  - Runs type checking and builds the production bundle (`npm run build`).
- **Backend Job**:
  - Launches a live **MongoDB 6** service container on port 27017.
  - Runs the full automated security test suite (`npm run test:security`):
    - OAuth 2.1 authorization boundary & private app isolation.
    - Audience isolation across registered clients.
    - App-Admin JWT verification, token purpose enforcement, and atomic backup code consumption.
    - Production fail-fast environment schema checks.
  - Compiles both the Lambda entrypoint (`dist/index.cjs`) and standalone Node server.
  - Validates CloudFormation syntax with `sam validate --lint`.

### 2. Continuous Deployment (`.github/workflows/deploy.yml`)
- **Triggers**: Pushes to `main`, or manual execution via `workflow_dispatch`.
- **Change Detection Filter**:
  - Automatically identifies whether commits affected `backend/`, `frontend/`, or both.
  - Only triggers deployments for modified components, saving build minutes.
- **Backend Deployment**:
  - Runs pre-flight security tests in an isolated MongoDB container to ensure zero regressions reach production.
  - Configures the named AWS profile `aws` required by `samconfig.toml`.
  - Executes `sam build` and `sam deploy --no-confirm-changeset`.
  - Performs an automated health check probe against the deployed Lambda Function URL.
- **Frontend Deployment**:
  - Runs linter and builds optimized production bundles.
  - Pulls production environment configurations and deploys via Vercel CLI (`--prod`).
  - Probes `https://oauth21.vercel.app` to verify gateway availability.

---

## 4. Manual Deployment via GitHub CLI or Web UI

To trigger a deployment manually without making a commit:

### Via Web UI:
1. Go to **Actions** in your GitHub repository.
2. Select **Auto Deployment (Production)** from the left sidebar.
3. Click **Run workflow**.
4. Select the target component: `all`, `backend`, or `frontend`.

### Via GitHub CLI (`gh`):
```bash
# Deploy both frontend and backend
gh workflow run deploy.yml -f target=all

# Deploy only the backend to AWS Lambda
gh workflow run deploy.yml -f target=backend

# Deploy only the frontend to Vercel
gh workflow run deploy.yml -f target=frontend
```

---

## 5. Rollback Procedures

### Instant Backend Rollback (AWS Lambda / SAM)
If an issue occurs in production:
```bash
# Option A: Re-deploy previous git commit
git checkout HEAD~1 backend/
git commit -m "revert: rollback backend to previous release"
git push origin main

# Option B: Rollback via AWS CLI directly
aws lambda update-function-code \
  --function-name oauth-ApiFunction-YMDxfk7mCZda \
  --zip-file fileb://lambda.zip \
  --region ap-south-1 \
  --profile aws
```

### Instant Frontend Rollback (Vercel)
1. Go to [Vercel Dashboard](https://vercel.com) > **Deployments**.
2. Locate the previous successful deployment.
3. Click the three dots (`...`) > **Promote to Production** (instant zero-downtime rollback).
