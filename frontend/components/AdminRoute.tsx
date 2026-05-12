import React from 'react';
import { Navigate } from 'react-router-dom';
import { useSession } from '../lib/auth-client';
import GlassSurface from '@/components/GlassSurface';

const LoadingSpinner: React.FC = () => (
  <div className="w-full h-dvh px-6 grid place-items-center">
    <GlassSurface
      width="100%"
      height="auto"
      borderRadius={28}
      backgroundOpacity={0.12}
      blur={12}
      saturation={1.6}
      className="w-full max-w-md mx-auto"
    >
      <div className="w-full px-8 py-10 text-center">
        <div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-white/30 border-t-white" />
      </div>
    </GlassSurface>
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
