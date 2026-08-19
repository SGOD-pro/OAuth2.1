import { Suspense, lazy, type ReactNode } from 'react';
import { RouterProvider, createBrowserRouter, Navigate } from 'react-router-dom';
import { AdminRoute } from '@/components/AdminRoute';
import { Layout } from '@/components/Layout';
import { RouteLoader } from '@/components/RouteLoader';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import './index.css';
import './App.css';

const SignIn = lazy(() => import('@/pages/SignIn').then((module) => ({ default: module.SignIn })));
const ForgotPassword = lazy(() =>
  import('@/pages/ForgotPassword').then((module) => ({ default: module.ForgotPassword }))
);
const ResetPassword = lazy(() =>
  import('@/pages/ResetPassword').then((module) => ({ default: module.ResetPassword }))
);
const Consent = lazy(() => import('@/pages/Consent').then((module) => ({ default: module.Consent })));
const AuthCallback = lazy(() =>
  import('@/pages/AuthCallback').then((module) => ({ default: module.AuthCallback }))
);
const SignOut = lazy(() =>
  import('@/pages/SignOut').then((module) => ({ default: module.SignOut }))
);
const NotFound = lazy(() =>
  import('@/pages/NotFound').then((module) => ({ default: module.NotFound }))
);
const AdminDashboard = lazy(() =>
  import('@/pages/admin/AdminDashboard').then((module) => ({ default: module.AdminDashboard }))
);
const AdminClients = lazy(() =>
  import('@/pages/admin/AdminClients').then((module) => ({ default: module.AdminClients }))
);
const AdminLogs = lazy(() =>
  import('@/pages/admin/AdminLogs').then((module) => ({ default: module.AdminLogs }))
);
const AdminLogin = lazy(() =>
  import('@/pages/admin/AdminLogin').then((module) => ({ default: module.AdminLogin }))
);
const AdminTwoFactor = lazy(() =>
  import('@/pages/admin/AdminTwoFactor').then((module) => ({ default: module.AdminTwoFactor }))
);
const AdminSecurity = lazy(() =>
  import('@/pages/admin/AdminSecurity').then((module) => ({ default: module.AdminSecurity }))
);

const withSuspense = (node: ReactNode) => (
  <Suspense fallback={<RouteLoader />}>{node}</Suspense>
);

const withLayout = (node: ReactNode) => <Layout>{withSuspense(node)}</Layout>;
const router = createBrowserRouter([
 
  { path: '/', element: <Navigate to="/auth" replace /> },
  { path: '/auth', element: withLayout(<SignIn />) },
  { path: '/forgot-password', element: withLayout(<ForgotPassword />) },
  { path: '/reset-password', element: withLayout(<ResetPassword />) },
  { path: '/consent', element: withLayout(<Consent />) },
  { path: '/callback', element: withLayout(<AuthCallback />) },
  { path: '/signout', element: <SignOut /> },

  // ── Admin panel (role-gated) ───────────────────────────────────
  { path: '/admin/login', element: withSuspense(<AdminLogin />) },
  // 2FA code entry — no AdminRoute guard (user is mid-authentication)
  { path: '/admin/two-factor', element: withSuspense(<AdminTwoFactor />) },
  {
    path: '/admin',
    element: withSuspense(
      <AdminRoute>
        <AdminDashboard />
      </AdminRoute>
    ),
  },
  {
    path: '/admin/clients',
    element: withSuspense(
      <AdminRoute>
        <AdminClients />
      </AdminRoute>
    ),
  },
  {
    path: '/admin/logs',
    element: withSuspense(
      <AdminRoute>
        <AdminLogs />
      </AdminRoute>
    ),
  },
  {
    path: '/admin/security',
    element: withSuspense(
      <AdminRoute>
        <AdminSecurity />
      </AdminRoute>
    ),
  },
  { path: '*', element: withLayout(<NotFound />) },
]);

function App() {
  return (
    <ErrorBoundary>
      <RouterProvider router={router} />
    </ErrorBoundary>
  );
}

export default App;
