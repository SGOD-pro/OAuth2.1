# Implementation Plan: Comprehensive Remediation of OAuth 2.1 Security Checkpoints

> **Repository File:** `SECURITY_REMEDIATION_PLAN.md`  
> **Source Spec:** [User Request / Security Contract](file:///home/swyra/projects/OAuth2.1/AGENTS.md)  
> **Target Date:** September 2026  

---

## 1. Goal Description

Completely eliminate cross-client token family leakage, enforce deterministic replay grace window semantics, align production environment self-checks with configuration contracts, and eradicate all hardcoded internal gateway secret fallbacks from CI/CD pipelines, AWS SAM templates, and configuration files.

---

## 2. User Review Required

> [!IMPORTANT]
> **AWS SAM Parameter Overrides & CI/CD Secret Requirement**  
> The hardcoded fallback `swyra_internal_gateway_secret_32char_prod_key` will be completely removed from `backend/template.yaml`, `backend/samconfig.toml`, and `.github/workflows/deploy.yml`. Consequently, deploying the production stack will strictly require the GitHub Actions secret `INTERNAL_GATEWAY_SECRET` ($\ge 32$ characters). Any deployment attempted without this secret or with a secret $< 32$ characters will fail preflight validation and block stack deployment.

> [!WARNING]
> **Defensive Client Ownership Boundary in `verifyAndRotateTokenFamily`**  
> `backend/src/db/state.ts`'s `verifyAndRotateTokenFamily` will be updated to accept and require `expectedClientId`. If a token family belongs to Client A and Client B invokes rotation or replay verification, the helper will fail closed without updating, locking, or revoking Client A's family.

---

## 3. Open Questions

None. All 4 primary objectives and 13 requirement sections are specified with unambiguous security invariants.

---

## 4. Proposed Changes

### Component 1: Database Layer & Token Family State Engine (`backend/src/db/`)

#### [MODIFY] [`backend/src/db/state.ts`](file:///home/swyra/projects/OAuth2.1/backend/src/db/state.ts)
- Update `verifyAndRotateTokenFamily` signature to accept `expectedClientId?: string`:
  ```typescript
  export async function verifyAndRotateTokenFamily(
    incomingTokenHash: string,
    newTokenHash: string,
    userId?: string,
    nowMs: number = Date.now(),
    expectedClientId?: string
  ): Promise<{
    valid: boolean;
    replayed: boolean;
    familyId?: string;
    clientId?: string;
    userId?: string;
    clientMismatch?: boolean;
  }>
  ```
- In `verifyAndRotateTokenFamily`:
  1. If `expectedClientId` is provided and `doc.clientId && doc.clientId !== expectedClientId`, immediately return `{ valid: false, replayed: false, clientMismatch: true }` without mutating the family or revoking it.
  2. Scope the replay cascade revocation update filter to `{ _id: doc._id, clientId: doc.clientId }`.
  3. Scope the atomic rotation `updateOne` filter to include `clientId: doc.clientId`.
- Update `registerTokenFamily` to ensure `clientId` is always non-empty and trimmed.

---

### Component 2: OAuth 2.1 Route Controller (`backend/src/routes/`)

#### [MODIFY] [`backend/src/routes/auth.ts`](file:///home/swyra/projects/OAuth2.1/backend/src/routes/auth.ts)
- In `POST /api/auth/oauth2/token` for `grant_type === "refresh_token"`:
  1. Authoritative client authentication validation: Ensure `canonicalClientId` is resolved and non-empty. If missing or invalid, return HTTP 400 `invalid_client`.
  2. When querying `existingFamily`, filter by:
     ```typescript
     const existingFamily = await database.collection("oauth_token_families").findOne({
         $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
     });
     ```
     Immediately enforce:
     ```typescript
     if (existingFamily && existingFamily.clientId && existingFamily.clientId !== canonicalClientId) {
         return c.json({
             error: "invalid_grant",
             error_description: "Refresh token was not issued to the authenticated client"
         }, 400);
     }
     ```
  3. Bind atomic Compare-and-Swap (CAS) rotation claim directly to `canonicalClientId`:
     ```typescript
     const claim = await database.collection("oauth_token_families").findOneAndUpdate(
         {
             activeTokenHash: incomingHash,
             clientId: canonicalClientId,
             status: "active",
             rotating: { $ne: true },
         },
         {
             $set: { rotating: true, rotatingAt: new Date() },
         },
         { returnDocument: "after" }
     );
     ```
  4. In `!claim` branch, scope in-flight check and replay verification by `canonicalClientId`:
     ```typescript
     const currentDoc = await database.collection("oauth_token_families").findOne({
         clientId: canonicalClientId,
         $or: [{ activeTokenHash: incomingHash }, { consumedTokenHashes: incomingHash }]
     });
     ```
     Pass `canonicalClientId` to `verifyAndRotateTokenFamily(incomingHash, "dummy", undefined, Date.now(), canonicalClientId)`.
  5. In failure branch (when Better Auth returns $\ne 200$), scope rotation unlock and replay check:
     ```typescript
     await database.collection("oauth_token_families").updateOne(
         { activeTokenHash: incomingHash, clientId: canonicalClientId, rotating: true },
         { $set: { rotating: false } }
     ).catch(() => {});
     const check = await verifyAndRotateTokenFamily(incomingHash, "dummy", undefined, Date.now(), canonicalClientId);
     ```
  6. In success branch, pass `canonicalClientId` to `verifyAndRotateTokenFamily(incomingHash, newHash, resolvedUserId, Date.now(), canonicalClientId)`.

---

### Component 3: Internal Gateway Protection & Middleware (`backend/src/middleware/`)

#### [MODIFY] [`backend/src/middleware/admin-auth.ts`](file:///home/swyra/projects/OAuth2.1/backend/src/middleware/admin-auth.ts)
- Upgrade `gatewayHeader !== config.internalGatewaySecret` to constant-time timing-safe comparison:
  ```typescript
  import { timingSafeEqualStr } from "../utils/security";
  ...
  if (config.internalGatewaySecret) {
    const gatewayHeader = c.req.header("x-gateway-secret") || c.req.header("x-internal-secret");
    if (!gatewayHeader || !timingSafeEqualStr(gatewayHeader, config.internalGatewaySecret)) {
      return c.json(
        { error: "forbidden", message: "Direct access to management endpoints forbidden; gateway authentication required" },
        403
      );
    }
  }
  ```

---

### Component 4: Deployment Configuration & CI/CD Pipeline

#### [MODIFY] [`backend/template.yaml`](file:///home/swyra/projects/OAuth2.1/backend/template.yaml)
- Remove `Default: "swyra_internal_gateway_secret_32char_prod_key"` on `InternalGatewaySecret`:
  ```yaml
    InternalGatewaySecret:
      Type: String
      NoEcho: true
      Description: Shared secret between reverse-proxy gateway and Lambda Function URL
  ```

#### [MODIFY] [`backend/samconfig.toml`](file:///home/swyra/projects/OAuth2.1/backend/samconfig.toml)
- Remove `InternalGatewaySecret` override from tracked `samconfig.toml`. It must be passed dynamically by CI/CD during deployment.
  ```toml
  parameter_overrides = "BetterAuthUrl=\"https://oauth21.vercel.app\" GoogleClientId=\"851793713357-efu64vah4peecto0r4l1vnc9ctlpc043.apps.googleusercontent.com\" FrontendUrl=\"https://oauth21.vercel.app\""
  ```

#### [MODIFY] [`.github/workflows/deploy.yml`](file:///home/swyra/projects/OAuth2.1/.github/workflows/deploy.yml)
- Eradicate `GATEWAY_SECRET="${INTERNAL_GATEWAY_SECRET:-swyra_internal_gateway_secret_32char_prod_key}"`.
- Add strict preflight validation step before SAM deployment:
  ```yaml
      - name: Validate Production Gateway Secret Preflight (Fail-Closed)
        run: |
          if [ -z "${{ secrets.INTERNAL_GATEWAY_SECRET }}" ]; then
            echo "FATAL: secrets.INTERNAL_GATEWAY_SECRET is missing. Production deployments fail closed."
            exit 1
          fi
          SECRET_LEN=${#INTERNAL_GATEWAY_SECRET}
          if [ "$SECRET_LEN" -lt 32 ]; then
            echo "FATAL: secrets.INTERNAL_GATEWAY_SECRET must be at least 32 characters (got $SECRET_LEN)."
            exit 1
          fi
        env:
          INTERNAL_GATEWAY_SECRET: ${{ secrets.INTERNAL_GATEWAY_SECRET }}

      - name: Deploy Stack via AWS SAM
        working-directory: backend
        env:
          INTERNAL_GATEWAY_SECRET: ${{ secrets.INTERNAL_GATEWAY_SECRET }}
        run: |
          sam deploy \
            --no-confirm-changeset \
            --no-fail-on-empty-changeset \
            --parameter-overrides \
              BetterAuthUrl="https://oauth21.vercel.app" \
              GoogleClientId="851793713357-efu64vah4peecto0r4l1vnc9ctlpc043.apps.googleusercontent.com" \
              FrontendUrl="https://oauth21.vercel.app" \
              InternalGatewaySecret="${INTERNAL_GATEWAY_SECRET}"
  ```

---

### Component 5: Production Configuration & Security Self-Check

#### [MODIFY] [`backend/scripts/security-self-check.ts`](file:///home/swyra/projects/OAuth2.1/backend/scripts/security-self-check.ts)
- Add comprehensive `envSchema` tests directly into `security-self-check.ts`:
  1. Production + missing `INTERNAL_GATEWAY_SECRET` => throws validation error.
  2. Production + weak `INTERNAL_GATEWAY_SECRET` (< 32 chars) => throws validation error.
  3. Production + valid `INTERNAL_GATEWAY_SECRET` ($\ge 32$ chars) => passes cleanly.
  4. Development/test modes => permitted without mandatory gateway secret.
  5. `ALLOW_DEV_CLIENTS_IN_PRODUCTION` enforcement: test both `allowDevInProd: false` (rejects loopback redirect) and `allowDevInProd: true` (permits loopback redirect for dev client).

---

### Component 6: Regression Test Suites & Deterministic Replay Gates

#### [NEW] [`backend/tests/security/cross-client-refresh-matrix.ts`](file:///home/swyra/projects/OAuth2.1/backend/tests/security/cross-client-refresh-matrix.ts)
Exhaustive suite covering Cases 1 through 6:
- **Case 1:** Client A valid active refresh token presented with Client B credentials:
  - Assert HTTP 400 with `error: "invalid_grant"`.
  - Assert zero new tokens issued.
  - Assert Client A family remains active, `rotating: false`, active token hash unchanged, consumed token hashes unchanged.
- **Case 2:** Client A consumed refresh token presented with Client B credentials:
  - Assert HTTP 400 with `error: "invalid_grant"`.
  - Assert Client A family is NOT revoked.
- **Case 3:** Wrong client ID + active token; Wrong client ID + recently consumed token; Missing/invalid client context.
- **Case 4:** Same client (Client A) with valid refresh token succeeds, rotates normally to R1.
- **Case 5:** Concurrent same-client refresh requests (5 parallel requests) preserve CAS race behavior: exactly 1 winner rotates to R2, 4 losers rejected, family remains active.
- **Case 6:** Cross-client misuse does NOT trigger cascade revocation or purge unrelated tokens.

#### [MODIFY] [`backend/tests/security/final-adversarial-gate.ts`](file:///home/swyra/projects/OAuth2.1/backend/tests/security/final-adversarial-gate.ts)
- Replace hardcoded production fallback with dedicated test secret fixture `"test_adversarial_gateway_secret_32_characters"`.
- Ensure all calls to `verifyAndRotateTokenFamily` explicitly supply `expectedClientId` and deterministic `nowMs` offsets.

#### [MODIFY] [`backend/tests/security/phase25-security-gate.ts`](file:///home/swyra/projects/OAuth2.1/backend/tests/security/phase25-security-gate.ts)
- Pass explicit `expectedClientId` and deterministic timestamps (`nowMs = baseTime + 2500`).

#### [MODIFY] [`backend/tests/security/second-pass-security-suite.ts`](file:///home/swyra/projects/OAuth2.1/backend/tests/security/second-pass-security-suite.ts)
- Pass explicit `expectedClientId` and deterministic timestamps in REFRESH-1 and REFRESH-2.

#### [MODIFY] [`backend/package.json`](file:///home/swyra/projects/OAuth2.1/backend/package.json)
- Add `"test:cross-client-refresh": "tsx tests/security/cross-client-refresh-matrix.ts"`.
- Include `test:cross-client-refresh` in `"test:all-security"`.

---

## 5. Verification Plan

### Automated Tests
1. **Security Self-Check:**
   ```bash
   npm run security:self-check
   ```
2. **Dedicated Cross-Client Refresh Matrix:**
   ```bash
   npm run test:cross-client-refresh
   ```
3. **Core Adversarial Suites:**
   ```bash
   npm run test:security
   npm run test:gate
   npm run test:second-pass
   npm run test:prod-config
   ```
4. **Master All-Security Gate:**
   ```bash
   npm run test:all-security
   ```
5. **Backend & Frontend Production Builds:**
   ```bash
   cd backend && npm run build
   cd ../frontend && npm run build
   ```
6. **Repository-Wide Sanitization Audit:**
   ```bash
   grep -rn "swyra_internal_gateway_secret_32char_prod_key" .
   ```
   (Must return 0 occurrences).

### Manual Verification
- Review CloudFormation template (`backend/template.yaml`) to verify `InternalGatewaySecret` has no default.
- Review GitHub Actions workflow (`deploy.yml`) to confirm fail-closed preflight and no secret leakage.
