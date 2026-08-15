import * as React from "react"
import { NavLink } from "react-router-dom"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
} from "@/components/ui/sidebar"

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
    label: 'Audit Logs',
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
  {
    to: '/admin/security',
    label: 'Security & 2FA',
    end: false,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  return (
    <Sidebar className="w-[260px] border-r border-border/50 bg-background" {...props}>
      <SidebarHeader className="h-16 flex items-center px-6 border-b border-border/50">
        <div className="flex items-center gap-3">
          <div className="flex h-3.5 gap-0.5 items-center">
            <div className="w-[3px] h-3.5 bg-[#0066B1] -skew-x-12" />
            <div className="w-[3px] h-3.5 bg-[#1C69D4] -skew-x-12" />
            <div className="w-[3px] h-3.5 bg-[#E22718] -skew-x-12" />
          </div>
          <div className="flex flex-col">
            <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">SWYRA</span>
            <span className="font-heading font-normal text-base tracking-tight text-foreground leading-tight">M Auth Console</span>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent className="p-4">
        <SidebarGroup>
          <SidebarMenu className="gap-1.5">
            {navItems.map(({ to, label, end, icon }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                viewTransition
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-3 rounded-md text-sm font-sans transition-all duration-200 ${
                    isActive
                      ? 'border-l-[3px] border-[#0066B1] bg-secondary/60 text-foreground font-medium pl-[13px]'
                      : 'text-muted-foreground hover:bg-secondary/40 hover:text-foreground'
                  }`
                }
              >
                <span className="opacity-80">{icon}</span>
                {label}
              </NavLink>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  )
}
