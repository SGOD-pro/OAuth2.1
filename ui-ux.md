
# UI/UX

## Design Language
- Clean, minimal, developer-focused. This is an auth service admin panel, not a consumer product.
- Integrated the "Cohere" design system: glassmorphism, animated mesh gradients, and unified background styling (`noise/grain`).
- Implemented `next-themes` for flawless light/dark mode toggling across the application.
- Typography: Unica77 Cohere Web (fallback to Inter/system sans-serif).
- Color: primary `#17171c`, canvas `#ffffff`, action-blue `#1863dc`, coral `#ff7759` for destructive accents.

## Public Auth Pages (End-user facing)
These pages are shown to end-users of consuming applications during the OAuth flow. They sit over premium animated mesh gradients (warm orange/pink/purple or deep blue/green) inside glassmorphism cards.

### Sign-in page
- Email + password fields. "Continue with Google" button. "Forgot password?" link.
- Graceful 2FA Login Interception: If credentials are valid but 2FA is enabled, suppress generic "Invalid credentials" toasts and cleanly redirect to the `[Enter 6-digit TOTP code]` screen.

### Sign-up page
- Email + password + confirm password fields. Password strength indicator.

### Consent screen & OAuth callback
- Clean UI showing app name, requested scopes, and authorize/deny buttons. Loading states for token exchange.

## Admin Panel (Self-hoster facing)
Dark mode primary. Sidebar navigation (dark primary background) + Main content area (soft-stone background). State managed by `zustand` with a 30-second TTL cache and optimistic UI updates.

### Admin Dashboard & Logs
- Stats cards (users, clients, logins) using Cohere component specs.
- Read view of recent sign-ins, styled as a modern data table.

### Admin Client Management (with App Admin Provisioning)
- List view: client name, client_id, status, actions (edit, delete).
- **App Administrator Section**: Inside the Client Detail view, an "App Administrator" section displays the provisioned admin's email. If none exists, a "Provision App Admin" popover allows the Auth Server admin to create an admin account (Name, Email, Password) specifically tied to that `oauthClient`.
- Helper text displays the App's `client_id` and JWKS URI instructions for the client app developer.

### 2FA Setup screen (admin or user enables TOTP)
1. User clicks "Enable 2FA" and enters their password.
2. Better Auth engine generates a TOTP secret and returns a `totpURI`.
3. Frontend renders QR code *locally* using `qrcode.react` (CRITICAL: No external API calls).
4. User scans with Google/Microsoft Authenticator.
5. UI immediately shows a 6-digit input field. User enters code to confirm setup.
6. Upon success, backup codes are shown once. UI transitions to "2FA is Enabled".

## Frontend Architecture
- React 19 + Vite + React Router v7.
- Static build — deployable to any static host (Scenario A) or fully replaceable by a custom frontend (Scenario B).
- Route guard (`AdminRoute.tsx`): UX-only. Server-side `requireAdmin` is the real gate.
- State management: `zustand` for server state, React context for session.