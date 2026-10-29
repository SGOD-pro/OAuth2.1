# 0002. Runtime resilience and key resolution

**Date**: 2026-10-14
**Status**: Accepted

## Summary

This decision hardens runtime stability across three critical paths in the identity provider. It adds automatic reconnection for dropped MongoDB sockets during idle pauses on serverless and container hosts. It resolves public signing keys by key identifier header with graceful fallback so rotated keys verify cleanly, and it self heals private signing keys if decryption fails rather than silently falling back to opaque tokens. It also guarantees that concurrent refresh token requests within a two second grace window return clean errors without revoking the active token family.

## Requirements

**User stories**:
- As an API client, I want database operations to recover automatically when idle connections drop so that authentication requests never fail unexpectedly after periods of low traffic.
- As a token verifier, I want access tokens to resolve their signing keys by key identifier so that key rotation never invalidates active tokens.
- As an application user, I want concurrent network requests using refresh tokens to fail gracefully rather than revoking my active session.

**Acceptance criteria**:
- **AC-1**: MongoDB connection manager configures production timeouts (serverSelectionTimeoutMS 10s, socketTimeoutMS 30s, maxIdleTimeMS 60s, maxPoolSize 10, minPoolSize 1) and automatically reconnects on dropped or paused sockets via close and topologyClosed event listeners without requiring a process restart.
- **AC-2**: Background initial MongoDB connection failure resets the connection promise to allow subsequent `getDb()` calls to reconnect instead of returning an unauthenticated database handle.
- **AC-3**: Public key lookup `getIdpPublicKey(kid?: string)` supports key identifier lookups from token headers, matches corresponding keys in `jwks` collection, and caches keys in memory by key identifier with fallback to the latest key.
- **AC-4**: `getIdpSigningKey()` detects symmetric decryption failures on active keys (for example, after secret rotation), logs a warning, and self heals by generating and inserting a fresh RS256 keypair encrypted with the current secret, preventing silent fallback to opaque tokens.
- **AC-5**: Refresh token rotation tolerates concurrent in flight requests within a 2000ms grace window, returning `400 invalid_grant` on consumed tokens without revoking the active token family or purging active user sessions.
- **AC-6**: Refresh token presentation outside the 2000ms grace window continues to trigger cascade revocation across the token family and associated access tokens as a security defense against token replay theft.

## Decision

**Chosen option**: Option 1: Connection lifecycle manager with key identifier cache and self healing keypairs

We will configure MongoDB client timeouts with lifecycle event listeners that recreate the connection on close or topology drop. We will enhance public key resolution to read the key identifier from protected token headers and cache keys by identifier. We will add automatic RS256 keypair regeneration when symmetric decryption fails, and preserve the token family grace window for concurrent refresh requests.

**Implementation skills**: none

## Rationale

Reasoning and options: see [rationale.md](rationale.md).

## Feature design

**Data model sketch**:
- `jwks`: `_id` (ObjectId), `kid` (string), `publicKey` (string or JWK JSON), `privateKey` (string or encrypted JSON), `createdAt` (Date), `updatedAt` (Date). Indexes: `{ kid: 1 }`, `{ createdAt: -1 }`.
- `oauth_token_families`: `familyId` (string), `clientId` (string), `userId` (string), `activeTokenHash` (string), `consumedTokenHashes` (string[]), `status` ("active" or "revoked"), `updatedAt` (Date), `revokedAt` (Date). Indexes: `{ familyId: 1, unique: true }`, `{ activeTokenHash: 1 }`, `{ consumedTokenHashes: 1 }`.
- `oauthAccessToken`: `_id` (ObjectId), `token` (string), `clientId` (string), `userId` (string), `expiresAt` (Date), `createdAt` (Date), `scopes` (string[]).
- `oauthRefreshToken`: `_id` (ObjectId), `token` (string), `clientId` (string), `userId` (string), `expiresAt` (Date), `createdAt` (Date).

**API surface**:
| Endpoint or helper | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| `getDb()` | internal | none | database handle (`Db`) | internal | connection error |
| `getIdpPublicKey(kid?: string)` | internal | `kid` (optional string) | RS256 public key or null | internal | key not found |
| `getIdpSigningKey()` | internal | none | private key and kid | internal | key failure |
| `POST /api/auth/oauth2/token` | POST | `grant_type=refresh_token`, `refresh_token` | token response | client or public PKCE | 400 invalid_grant, 401 |

**Value sourcing**:
| Action | Value produced / displayed | Source |
|---|---|---|
| Database access | Database handle (`Db`) | `getDb()` connection manager via `MongoClient` |
| Token verification | Public key | `jwks` collection queried by `kid` extracted from token header |
| Token minting | RS256 signing key and kid | `jwks` collection decrypted via secret, or self healed keypair |
| Token family check | Rotation status | `oauth_token_families` collection evaluated against grace window |

**Key invariants**:
- The database connection must self heal after idle pauses without throwing unhandled rejections or freezing workers.
- Tokens signed with older keys must verify successfully as long as their public key exists in the `jwks` collection.
- The IdP must never fall back to opaque tokens when RS256 tokens are configured, even if private key decryption fails.
- Replay theft outside the grace window must cascade revoke the token family and revoke all active tokens for that user scope.

**Security model**:
- Public keys remain discoverable over `/.well-known/jwks.json`.
- Private keys remain encrypted in MongoDB and are never exposed across HTTP surfaces.
- Client token isolation is enforced on refresh: cross client callers cannot inspect, rotate, or revoke families belonging to another client.

**Critical test scenarios**:
- Idle connection recovery: Database queries succeed after a simulated socket drop or topology closed event, verifies **AC-1**, **AC-2**.
- Key identifier resolution: Tokens signed with rotated keypairs verify cleanly by matching `kid` in the JWKS store, verifies **AC-3**.
- Keypair self healing: Token minting generates a fresh keypair and returns valid JWTs when the stored private key is corrupted, verifies **AC-4**.
- Concurrent refresh tolerance: Two simultaneous refresh requests with the same token result in one success and one 400 error without family revocation, verifies **AC-5**.
- Replay theft revocation: Presenting a consumed refresh token after the grace window expires revokes the entire token family, verifies **AC-6**.

## Build plan

- [x] Configure connection timeouts and lifecycle event handlers in `backend/src/db/mongo.ts`, satisfies **AC-1**, **AC-2**.
- [x] Enhance `getIdpPublicKey` to accept an optional `kid` parameter and cache public keys by identifier in `backend/src/middleware/admin-auth.ts`, satisfies **AC-3**.
- [x] Extract `kid` from protected token headers before verification in `/oauth2/userinfo` and `/oauth2/introspect` in `backend/src/routes/auth.ts`, satisfies **AC-3**.
- [x] Implement self healing RS256 key generation on decryption error in `getIdpSigningKey` in `backend/src/routes/auth.ts`, satisfies **AC-4**.
- [x] Harden concurrent refresh token error handling in `backend/src/routes/auth.ts` and `backend/src/db/state.ts`, satisfies **AC-5**, **AC-6**.
- [x] Create automated unit and security tests in `backend/tests/` asserting connection recovery, key resolution, and refresh tolerance, satisfies **AC-1**, **AC-2**, **AC-3**, **AC-4**, **AC-5**, **AC-6**.

## Consequences

**Positive**:
- Prevents random 500 errors after days of low activity on serverless environments.
- Supports seamless key rotation without breaking existing valid tokens.
- Prevents silent degradation to opaque tokens that consumer apps cannot verify.
- Eliminates false positive session lockouts caused by concurrent browser refresh calls.

**Negative / tradeoffs**:
- Maintaining a small in memory key cache adds minimal memory footprint.
- Key generation on decryption failure incurs a one time compute cost during self healing.

**Neutral**:
- Fully backward compatible with existing valid tokens and stored token families.

## Follow-up

- [ ] Add metric logging for database reconnect attempts and key generation events.
