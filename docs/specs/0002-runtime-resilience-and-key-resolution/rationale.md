# Rationale: Runtime resilience and key resolution

## Context

In production deployments on AWS Lambda and Vercel edge proxies, the identity provider encounters transient disruptions after several days of operation.

First, MongoDB Atlas clusters automatically close idle sockets after periods of inactivity. In the existing implementation, the MongoClient instance is created once at module load without explicit connection pool timeouts. If an idle socket is dropped by Atlas or an intermediary firewall, subsequent queries fail or hang because the client lacks event listeners to detect dropped topologies and reset its connection promise. In addition, the background initial connection catch block returns an unauthenticated database handle on failure rather than allowing future calls to retry.

Second, token verification routes query the newest record from the `jwks` collection rather than matching the key identifier specified in the token protected header. When signing keys are rotated, tokens issued prior to rotation fail validation. In token minting, if symmetric decryption of the stored private key fails because of a rotated authentication secret or corrupted data, the system falls back to opaque tokens. Consumer applications expecting RS256 JWTs fail with invalid token errors, rendering the IdP unusable until manual intervention.

Third, the refresh token rotation mechanism includes replay detection designed to catch token theft. However, web browsers, mobile clients, and React Server Components frequently emit concurrent refresh requests for the same token within milliseconds. When the losing request arrives after rotation, if the grace window logic fails to protect the active family, the IdP treats the concurrent request as a malicious replay, revoking the entire family and signing the user out.

## Options considered

### Option 1: Connection lifecycle manager with key identifier cache and self healing keypairs

Configure MongoClient with explicit connection pool timeouts (serverSelectionTimeoutMS 10s, socketTimeoutMS 30s, maxIdleTimeMS 60s) and event listeners for close and topologyClosed. Enhance public key resolution to read key identifiers from token headers and cache keys in memory by identifier. Add automatic RS256 keypair regeneration when private key decryption fails, and ensure concurrent refresh requests within the two second grace window return clean 400 errors without revoking the active family.

**Pros**:
- Eliminates silent database failures after idle pauses.
- Rotated keys remain verifiable as long as the public key remains in the store.
- Private key decryption failures self heal immediately, preventing opaque token fallback.
- Concurrent client requests do not cause unexpected session revocations.

**Cons**:
- Slightly increases memory usage to maintain an in memory key cache.
- Key regeneration incurs a one time compute overhead on decryption failure.

### Option 2: Passive query level reconnects with strict key matching and manual key regeneration

Rely on query level retries without event listeners. Enforce strict key identifier matching that rejects any token whose key identifier is missing from the database. On private key decryption failure, return 500 errors until an administrator manually executes a key generation script.

**Pros**:
- Slightly simpler code without event listeners.
- Strict key identifier matching enforces rigid key provenance.

**Cons**:
- Does not reliably detect closed MongoDB clients in long running processes.
- Fails closed on secret rotation, requiring manual operational intervention to restore service.
- Rejects legacy tokens issued without a key identifier header.

### Option 3: Stateless per request connections with opaque token fallback

Open and close a new MongoDB connection on each HTTP request, and continue falling back to opaque access tokens when private key operations fail.

**Pros**:
- Avoids connection pooling state entirely.

**Cons**:
- Severe latency penalty on every authentication request (200ms to 500ms handshake overhead).
- Opaque tokens break consumers that rely on offline RS256 verification against JWKS endpoints.
- Unacceptable user experience under real traffic.

## Rationale

Option 1 is the superior architectural choice because it directly addresses the root causes of multi day operational failures without introducing downtime or manual maintenance tasks.

By listening for `close` and `topologyClosed` events on the MongoClient, the connection manager resets internal state so that subsequent calls to `getDb()` cleanly re establish the connection pool. This is critical for AWS Lambda, where container instances can remain frozen for hours between invocations before resuming on a dead socket.

Matching keys by key identifier header aligns with standard OpenID Connect specifications. Storing multiple public keys and resolving them dynamically allows scheduled key rotation to proceed without invalidating existing access tokens. Self healing the private keypair ensures that even in catastrophic secret rotation scenarios, the server continues minting valid RS256 JWTs that consumer applications can verify offline.

Finally, preserving the 2000ms grace window for refresh tokens accommodates real world network jitter and duplicate requests from modern frontend frameworks, while preserving immediate family revocation for true replay attacks occurring outside the window.
