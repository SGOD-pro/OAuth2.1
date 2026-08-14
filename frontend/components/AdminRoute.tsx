import React, { useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { useSession } from '../lib/auth-client';
import { apiFetch } from '../lib/api';


const LoadingSpinner: React.FC = () => (
  <div className="w-full h-dvh px-6 grid place-items-center">
    <div className="w-full max-w-md mx-auto">
      <div className="glass-card rounded-[22px] p-12 text-center flex justify-center">
        <div className="h-9 w-9 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    </div>
  </div>
);

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

  useEffect(() => {
    if (!isAdmin) return;
    apiFetch('/api/admin/stats').catch(() => {
      // Silent fail - mutations will still be blocked if session is invalid.
    });
  }, [isAdmin]);

  if (isPending) return <LoadingSpinner />;
  
  if (!session?.user) {
    return <Navigate to="/admin/login" replace />;
  }

  if (!isAdmin) {
    return <Navigate to="/admin/login?error=access_denied" replace />;
  }

  return <>{children}</>;
};
