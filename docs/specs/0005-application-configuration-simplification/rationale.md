# Rationale: Application configuration simplification · spec 0005

## Context

When registering or updating OAuth 2.1 client applications, administrators previously had to manually populate both **Redirect URIs** (for OAuth authorization redirects) and **Allowed CORS Origins** (for browser based token exchanges and userinfo requests).

In almost all standard web application integrations, the CORS origin is simply the protocol, host, and port of the registered redirect URI (for example, redirect URI `https://app.example.com/oauth/callback` implies allowed origin `https://app.example.com`). Requiring developers to configure both fields separately led to frequent configuration oversights where developers registered callback endpoints but forgot allowed origins, resulting in silent browser cross origin request blocking during token exchange.

Furthermore, internal client document representations varied across subsystems: Better Auth defaults to camelCase fields (`redirectUris`, `allowedOrigins`, `isDev`, `isPublic`, `clientSecret`, `name`), while OAuth 2.1 RFC standards, external admin APIs, and database documents frequently employ snake_case (`redirect_uris`, `allowed_origins`, `is_dev`, `is_public`, `client_secret`, `client_name`). Ad hoc manual conversions scattered throughout route handlers introduced subtle mapping bugs and field omissions.

## Options considered

### Option 1: Automatic CORS origin derivation with explicit origin preservation and centralized dual casing normalization (Chosen)

Automatically extract unique, valid web origins (protocol, host, and optional port) from registered redirect URIs whenever `allowed_origins` is omitted or empty. Preserve explicit administrator supplied origins without overrides. Safely skip non web schemes (native mobile custom schemes like `myapp://callback` and URNs). Provide immediate visual feedback in the admin console with onAdd origin population and a one click auto derive helper button. Centralize all client field normalization in a shared utility `normalizeOAuthClientFields` returning canonical objects with both camelCase and snake_case properties.

**Pros**:
* Eliminates onboarding friction by automatically configuring allowed origins for common web applications.
* Prevents CORS blocking errors during initial integration.
* Preserves administrator control when external CDNs or separate API hosts must be explicitly allowed.
* Centralizes dual casing support, guaranteeing complete backward compatibility for all consumer SDKs and internal routes.
* Safely accommodates native mobile clients without generating invalid web CORS origins.

**Cons**:
* Requires URL parsing and deduplication logic across backend validation and frontend dialogs.

### Option 2: Wildcard CORS origin fallback (`*`)

Permit all origins by default if `allowed_origins` is omitted.

**Pros**:
* Simplest possible logic with zero parsing.

**Cons**:
* Critical security vulnerability. Allowing wildcard origins on authenticated endpoints permits malicious third party websites to execute credentialed cross origin requests against the identity provider, violating OAuth 2.1 and W3C security standards.

### Option 3: Retain mandatory manual origin entry

Continue requiring administrators to manually enter matching origins for every redirect URI.

**Pros**:
* Zero code changes to existing validation logic.

**Cons**:
* Preserves significant developer friction and recurring integration errors during application onboarding.

## Rationale

Option 1 provides the optimal balance of seamless developer onboarding and strict OAuth 2.1 security. By automatically deriving valid web origins from registered redirect URIs, developers can register an application in a single step with only the callback URL.

Preserving explicit origins ensures complex multi origin deployments remain supported, while skipping non web schemes ensures native mobile apps are handled cleanly without invalid origin errors. Dual casing normalization ensures that both legacy and modern consumer applications communicate with the identity provider without field naming mismatches.
