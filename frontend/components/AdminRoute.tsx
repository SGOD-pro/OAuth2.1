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
  const role = (session?.user as { role?: string })?.role;
  const isAdmin = role === 'admin';

  if (isPending) return <RouteLoader />;
  
  if (!session?.user) {
    return <Navigate to="/admin/login" replace />;
  }

  if (!isAdmin) {
    return <Navigate to="/admin/login?error=access_denied" replace />;
  }

  return <ErrorBoundary fallbackTitle="Admin Panel Error">{children}</ErrorBoundary>;
};
