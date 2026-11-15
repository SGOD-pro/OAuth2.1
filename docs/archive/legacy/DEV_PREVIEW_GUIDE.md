# Developer Security Bypass & UI Preview Guide

> **Target Audience:** Developers testing, inspecting, or designing UI components without an active backend, live database, or full OAuth 2.1 handshake.

---

## 🔒 Production Security Architecture

By default, **SWYRA M Auth** strictly enforces the OAuth 2.1 specification:
1. **Query Parameter Validation:** Direct navigation to `/auth`, `/consent`, `/forgot-password`, or `/reset-password` without valid OAuth parameters (`client_id`, `redirect_uri`, `code_challenge`, etc.) triggers the `<InvalidRequest />` security card.
2. **PKCE & State Integrity:** Every authorization request requires `code_challenge_method=S256` and a cryptographic `state`.
3. **RBAC & Admin Guards:** All `/admin/*` routes require an authenticated session with `role: "admin"` and TOTP MFA verification.

---

## 🚀 Option 1: URL-Based Testing (Zero Code Changes — Recommended)

You can inspect the live flow without editing code by appending valid test query parameters to the URL:

```text
http://localhost:5174/auth?client_id=test-client&redirect_uri=https://oauth.pstmn.io/v1/callback&response_type=code&scope=openid%20profile%20email&state=xyz123&code_challenge=E9Melhoa2OwvFrGMTJguCH5rwKD4841UnbMTpmodBRU&code_challenge_method=S256
```

---

## 🛠️ Option 2: Temporary Code Bypasses for Fast UI Inspection

If you need to rapidly inspect or adjust page styling across all screens without entering credentials or configuring query parameters, use the following temporary flags:

---

### 1. Bypass OAuth Parameter Checks on User Pages

**File:** [`frontend/components/Layout.tsx`](file:///d:/WORK/OAuth2.1/frontend/components/Layout.tsx)

Allows direct navigation to `/auth`, `/consent`, `/forgot-password`, and `/reset-password` without query parameters:

```diff
 export const Layout = ({ children }: { children: React.ReactNode }) => {
   const { isValid } = useOAuthParams();
+  const DEV_BYPASS = true; // Set to false before deployment

-  if (!isValid) {
+  if (!isValid && !DEV_BYPASS) {
     return <InvalidRequest reason="missing_params" />;
   }
```

---

### 2. Bypass User Login Submission (Mock Sign-In)

**File:** [`frontend/pages/SignIn.tsx`](file:///d:/WORK/OAuth2.1/frontend/pages/SignIn.tsx)

Allows clicking "Authenticate" to instantly route to `/consent` without connecting to the API:

```diff
 export const SignIn: React.FC = () => {
+  const DEV_BYPASS = true; // Set to false before deployment

   const handleSignIn = async (values: z.infer<typeof signInSchema>) => {
     setLoading(true);
     setError(null);
+
+    if (DEV_BYPASS) {
+      toast.success('DEV PREVIEW: Authenticated successfully');
+      navigate(callbackURL || '/consent', { replace: true, viewTransition: true });
+      setLoading(false);
+      return;
+    }
```

---

### 3. Bypass Admin Route Guards & Role Check

**File:** [`frontend/components/AdminRoute.tsx`](file:///d:/WORK/OAuth2.1/frontend/components/AdminRoute.tsx)

Allows direct inspection of `/admin`, `/admin/clients`, `/admin/logs`, and `/admin/security` without logging in:

```diff
 export const AdminRoute: React.FC<AdminRouteProps> = ({ children }) => {
   const { data: session, isPending } = useSession();
+  const DEV_BYPASS = true; // Set to false before deployment
+
+  if (DEV_BYPASS) {
    return <>{children}</>;
  }

   const role = (session?.user as { role?: string })?.role;
```

---

## 🧹 Pre-Deployment Checklist (Reversing Bypasses)

Before committing code or deploying to production (AWS Lambda, Vercel, etc.):

1. **Verify No Bypass Flags Remain:**
   ```bash
   grep -rn "DEV_BYPASS" frontend/
   ```
   *Expected Output:* **0 matches**.

2. **Verify TypeScript & Vite Build:**
   ```bash
   cd frontend
   npm run build
   ```
   *Expected Output:* `✓ built in X.XXs` with 0 errors.

3. **Verify Route Protection:**
   - Navigating directly to `http://localhost:5174/auth` should display **"Invalid Request"**.
   - Navigating directly to `http://localhost:5174/admin` should redirect to **`/admin/login`**.
