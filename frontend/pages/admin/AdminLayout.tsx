import React, { useCallback } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { authClient, useSession } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';

const navItems = [
  {
    to: '/admin',
    label: 'Overview',
    end: true,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
      </svg>
    ),
  },
  {
    to: '/admin/clients',
    label: 'Applications',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      </svg>
    ),
  },
  {
    to: '/admin/logs',
    label: 'Logs',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
];

/**
 * Shared layout for all /admin/* pages.
 * Sidebar navigation + top bar with signed-in user info.
 */
export const AdminLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { data: session } = useSession();
  const navigate = useNavigate();

  const handleSignOut = useCallback(async () => {
    await authClient.signOut();
    navigate('/admin/login', { viewTransition: true });
  }, [navigate]);

  return (
    <div className="min-h-screen w-full grid grid-cols-[minmax(220px,260px)_1fr] gap-6 px-6 py-6">
      <GlassSurface
        width="100%"
        height="100%"
        borderRadius={24}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="h-full"
      >
        <aside className="flex h-full flex-col px-5 py-6">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl border border-white/10 bg-white/10 flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.16em] text-muted-foreground">SWYRA</p>
              <p className="text-sm font-semibold text-foreground">Admin Console</p>
            </div>
          </div>

          <nav className="mt-8 flex flex-col gap-2">
            {navItems.map(({ to, label, end, icon }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                viewTransition
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-2xl px-3 py-2 text-sm transition ${isActive
                    ? 'bg-white/15 text-foreground'
                    : 'text-muted-foreground hover:text-foreground hover:bg-white/10'
                  }`
                }
              >
                <span className="text-foreground/80">{icon}</span>
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>

          <div className="mt-auto">
            <NavLink
              to="/admin/login"
              viewTransition
              className="flex items-center gap-3 rounded-2xl px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-white/10 transition"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
              <span>Exit Admin</span>
            </NavLink>
          </div>
        </aside>
      </GlassSurface>

      <div className="flex flex-col gap-6">
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={24}
          backgroundOpacity={0.12}
          blur={12}
          saturation={1.6}
          className="w-full"
        >
          <header className="flex items-end justify-center px-6 py-4 flex-col w-full">
            <div className="text-xs text-muted-foreground">Signed in <span className="text-sm text-foreground">
              {(session?.user as { email?: string })?.email ?? ''}
            </span></div>
            <div className="flex items-center gap-4">

              <Button variant="destructive" size="sm" onClick={handleSignOut} className="ml-auto text-sm">
                Sign out
              </Button>
            </div>
          </header>
        </GlassSurface>

        <main className="flex-1">{children}</main>
      </div>
    </div>
  );
};
