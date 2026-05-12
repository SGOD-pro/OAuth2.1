import { Suspense, lazy, type ReactNode } from 'react';
import { RouterProvider, createBrowserRouter, Navigate } from 'react-router-dom';
import { AdminRoute } from '@/components/AdminRoute';
import { Layout } from '@/components/Layout';
import { RouteLoader } from '@/components/RouteLoader';
import './index.css';

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

  // ── Admin panel (role-gated) ───────────────────────────────────
  { path: '/admin/login', element: withSuspense(<AdminLogin />) },
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
  { path: '*', element: withLayout(<NotFound />) },
]);

function App() {
  return <RouterProvider router={router} />;
}

export default App;
