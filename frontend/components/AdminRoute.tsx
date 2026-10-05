import React from 'react';
import { Navigate } from 'react-router-dom';
import { useSession } from '../lib/auth-client';
import { RouteLoader } from './RouteLoader';
import { ErrorBoundary } from './ErrorBoundary';

interface AdminRouteProps {
  children: React.ReactNode;
}

/**
 * Route guard for all /admin/* routes.
 * Redirects to /admin/login if not authenticated.
 * Redirects to /admin/login?error=access_denied if authenticated but not admin.
 */
export const AdminRoute: React.FC<AdminRouteProps> = ({ children }) => {
  const { data: session, isPending } = useSession();
  const user = session?.user as { role?: string; scopedClientId?: string | null } | undefined;
  const isSuperAdmin = user?.role === 'admin' && !user?.scopedClientId;

  if (isPending) return <RouteLoader />;
  
  if (!session?.user) {
    return <Navigate to="/admin/login" replace />;
  }

  // Consumer application admins have scopedClientId set.
  // They are strictly admins for their assigned consumer application via OAuth,
  // and MUST NEVER be granted access to the central IdP management console.
  if (user?.role === 'admin' && Boolean(user?.scopedClientId)) {
    return <Navigate to="/admin/login?error=access_denied_scoped" replace />;
  }

  if (!isSuperAdmin) {
    return <Navigate to="/admin/login?error=access_denied" replace />;
  }

  return <ErrorBoundary fallbackTitle="Admin Panel Error">{children}</ErrorBoundary>;
};
