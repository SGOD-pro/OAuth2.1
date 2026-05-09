import React from 'react';
import { Navigate } from 'react-router-dom';
import { useSession } from '../lib/auth-client';

const LoadingSpinner: React.FC = () => (
  <div
    style={{
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    }}
  >
    <div className="loading-spinner" />
  </div>
);

interface AdminRouteProps {
  children: React.ReactNode;
}

/**
 * Route guard for all /admin/* routes.
 * Redirects to /sign-in if not authenticated.
 * Redirects to / if authenticated but not admin.
 */
export const AdminRoute: React.FC<AdminRouteProps> = ({ children }) => {
  const { data: session, isPending } = useSession();

  if (isPending) return <LoadingSpinner />;
  
  if (!session?.user) {
    return <Navigate to="/admin/login" replace />;
  }

  const role = (session.user as { role?: string }).role;
  if (role !== 'admin') {
    return <Navigate to="/admin/login?error=access_denied" replace />;
  }

  return <>{children}</>;
};
