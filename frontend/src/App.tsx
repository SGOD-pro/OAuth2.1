import { RouterProvider, createBrowserRouter } from 'react-router-dom';
import { SignIn } from './pages/SignIn';
import { SignUp } from './pages/SignUp';
import { ForgotPassword } from './pages/ForgotPassword';
import { ResetPassword } from './pages/ResetPassword';
import { Consent } from './pages/Consent';
import { AuthCallback } from './pages/AuthCallback';
import { AdminDashboard } from './pages/admin/AdminDashboard';
import { AdminClients } from './pages/admin/AdminClients';
import { AdminLogs } from './pages/admin/AdminLogs';
import { AdminLogin } from './pages/admin/AdminLogin';
import { AdminRoute } from './components/AdminRoute';
import './index.css';

const router = createBrowserRouter([
  // ── Public auth pages ──────────────────────────────────────────
  { path: '/',                element: <SignIn /> },
  { path: '/sign-in',        element: <SignIn /> },
  { path: '/sign-up',        element: <SignUp /> },
  { path: '/forgot-password', element: <ForgotPassword /> },
  { path: '/reset-password', element: <ResetPassword /> },
  { path: '/consent',        element: <Consent /> },
  { path: '/callback',       element: <AuthCallback /> },

  // ── Admin panel (role-gated) ───────────────────────────────────
  { path: '/admin/login', element: <AdminLogin /> },
  {
    path: '/admin',
    element: (
      <AdminRoute>
        <AdminDashboard />
      </AdminRoute>
    ),
  },
  {
    path: '/admin/clients',
    element: (
      <AdminRoute>
        <AdminClients />
      </AdminRoute>
    ),
  },
  {
    path: '/admin/logs',
    element: (
      <AdminRoute>
        <AdminLogs />
      </AdminRoute>
    ),
  },
]);

function App() {
  return <RouterProvider router={router} />;
}

export default App;
