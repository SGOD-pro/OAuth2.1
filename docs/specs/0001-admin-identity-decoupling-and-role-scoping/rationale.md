# 0001. Admin identity decoupling and role scoping: Rationale

## Context

The identity provider shares a single central user collection across both central platform administrators and consumer application administrators. When AWS Lambda cold starts occur, background self heal routines iterate through application administrator records and synchronize them into the user collection.

Previously, this synchronization unconditionally set the user's scoped client identifier and updated their account password whenever an email matched. If a Global Super Admin email was also registered as an application administrator, the next Lambda cold start demoted the Super Admin into a scoped client administrator, causing immediate access denied errors upon visiting the central admin console.

Furthermore, scoping was stored as a single scalar field on the user document. This prevented a user from administering multiple applications without clobbering other client assignments, and allowed administrator roles to leak into access tokens minted for unrelated consumer applications. In addition, `requireScopedAdmin` and `getAuthenticatedUser` in `admin-auth.ts` compared the presented token scope strictly against `userDoc.scopedClientId`, rejecting valid multi app administrators with false cross tenant errors, while both direct JWT and proxy 200 OK paths of `GET /oauth2/userinfo` leaked the user document's scalar scoping. A clean separation between global platform administration and per client administration is necessary to maintain security invariants and operational stability.

## Options considered

### Option 1: Fix in place with dynamic role resolution (Chosen)

Separate global super admin status from application administrator records in place. Retain the central user collection, add `appRole` in `user_app_registrations`, guard `syncAppAdminIdentity` against mutating Super Admins, dynamically evaluate token claims per target client in token and userinfo endpoints, and check multi app membership in admin middleware.

**Pros**:
- Preserves single sign on architecture without duplicate user records or database schema splits.
- Eliminates cold start admin demotion and cross client privilege escalation with minimal code changes.
- Backward compatible with existing client tokens and user records.

**Cons**:
- Requires an extra database query during token minting when checking per client memberships for non super admin users.

### Option 2: Duplicate user accounts per application

Create distinct user documents in the user collection for each application an administrator manages (for example, separate email aliases per application).

**Pros**:
- Avoids modifying role resolution logic in token minting routes.

**Cons**:
- Destroys single sign on experience for multi app administrators.
- Complicates credential management and email verification across accounts.

### Option 3: Separate admin database collections entirely

Isolate central IdP administrators into a separate administrative collection disconnected from Better Auth's user collection.

**Pros**:
- Physically separates super admin storage from consumer users.

**Cons**:
- Requires rewriting authentication middleware and Better Auth session plugins.
- High migration risk with potential breakage across administrative routes.

## Rationale

Option 1 addresses the root cause directly without destabilizing the authentication architecture. The cold start lockout occurs because `syncAppAdminIdentity` assumes every record in `app_admins` owns the user's primary identity. By asserting that a Global Super Admin account is immutable during synchronization sweeps, and by storing per client admin memberships in `user_app_registrations`, multi app administration is supported cleanly without modifying the global user identity. Resolving role claims dynamically at token issuance and across all userinfo response paths ensures that an administrator of Client A never inherits administrative privileges inside Client B. Updating middleware to recognize multi client admin memberships removes false cross tenant rejections for legitimate administrators.
