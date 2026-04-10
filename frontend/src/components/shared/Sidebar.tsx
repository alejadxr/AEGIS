'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  DashboardSquare01Icon,
  Radar01Icon,
  SecurityCheckIcon,
  Search01Icon,
  Settings01Icon,
  ArrowLeft01Icon,
  ArrowRight01Icon,
  Menu01Icon,
  ComputerIcon,
  FlashIcon,
} from 'hugeicons-react';
import { Ghost, GitFork, Atom, FileCheck, FileText, ShieldCheck, Sparkles, BookOpen } from 'lucide-react';
import { cn } from '@/lib/utils';

type IconComponent = React.ComponentType<{ className?: string; size?: number }>;

const iconMap: Record<string, IconComponent> = {
  DashboardSquare01Icon: DashboardSquare01Icon as IconComponent,
  Radar01Icon: Radar01Icon as IconComponent,
  SecurityCheckIcon: SecurityCheckIcon as IconComponent,
  Ghost: Ghost as IconComponent,
  Search01Icon: Search01Icon as IconComponent,
  Settings01Icon: Settings01Icon as IconComponent,
  ComputerIcon: ComputerIcon as IconComponent,
  GitFork: GitFork as IconComponent,
  Atom: Atom as IconComponent,
  FileCheck: FileCheck as IconComponent,
  FileText: FileText as IconComponent,
  ShieldCheck: ShieldCheck as IconComponent,
  FlashIcon: FlashIcon as IconComponent,
  Sparkles: Sparkles as IconComponent,
  BookOpen: BookOpen as IconComponent,
};

const NAV_SECTIONS = [
  {
    label: 'OVERVIEW',
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: 'DashboardSquare01Icon' },
    ],
  },
  {
    label: 'MODULES',
    items: [
      { label: 'Surface', href: '/dashboard/surface', icon: 'Radar01Icon' },
      { label: 'Response', href: '/dashboard/response', icon: 'SecurityCheckIcon' },
      { label: 'Phantom', href: '/dashboard/phantom', icon: 'Ghost' },
      { label: 'Deception', href: '/dashboard/deception', icon: 'Sparkles' },
      { label: 'Firewall', href: '/dashboard/firewall', icon: 'ShieldCheck' },
      { label: 'EDR / XDR', href: '/dashboard/edr', icon: 'GitFork' },
      { label: 'Antivirus', href: '/dashboard/antivirus', icon: 'ShieldAlert' },
      { label: 'Threats', href: '/dashboard/threats', icon: 'Search01Icon' },
      { label: 'Attack Path', href: '/dashboard/attack-path', icon: 'GitFork' },
      { label: 'Infra', href: '/dashboard/infra', icon: 'ComputerIcon' },
    ],
  },
  {
    label: 'SYSTEM',
    items: [
      { label: 'Quantum', href: '/dashboard/quantum', icon: 'Atom' },
      { label: 'Compliance', href: '/dashboard/compliance', icon: 'FileCheck' },
      { label: 'Reports', href: '/dashboard/reports', icon: 'FileText' },
      { label: 'Settings', href: '/dashboard/settings', icon: 'Settings01Icon' },
    ],
  },
];

interface SidebarProps {
  onCollapsedChange?: (collapsed: boolean) => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

export function Sidebar({ onCollapsedChange, mobileOpen, onMobileClose }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    onCollapsedChange?.(collapsed);
  }, [collapsed, onCollapsedChange]);

  const handleCollapse = () => {
    setCollapsed(!collapsed);
  };

  return (
    <>
      {/* Mobile overlay backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={onMobileClose}
        />
      )}

      <aside
        className={cn(
          'fixed left-0 top-0 z-40 h-screen flex flex-col transition-all duration-200',
          'bg-card border-r border-border',
          collapsed ? 'w-[56px]' : 'w-[220px]',
          'max-md:-translate-x-full max-md:w-[220px]',
          mobileOpen && 'max-md:translate-x-0'
        )}
      >
        {/* Logo */}
        <div className={cn(
          'flex items-center h-14 shrink-0 border-b border-border',
          collapsed ? 'justify-center px-0' : 'gap-2.5 px-4'
        )}>
          <div className="w-7 h-7 rounded-lg bg-muted flex items-center justify-center shrink-0">
            <span className="font-mono text-primary font-semibold text-[10px] tracking-wider">A</span>
          </div>
          {!collapsed && (
            <span className="text-foreground/90 font-semibold text-[14px] tracking-tight">
              AEGIS
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-3 px-2 overflow-y-auto space-y-5">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              {!collapsed && (
                <p className="text-[9px] font-medium text-muted-foreground/50 tracking-[0.08em] uppercase px-2.5 mb-1.5">
                  {section.label}
                </p>
              )}
              <div className="space-y-px">
                {section.items.map((item) => {
                  const Icon = iconMap[item.icon];
                  const isActive = pathname === item.href ||
                    (item.href !== '/dashboard' && pathname.startsWith(item.href));

                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={onMobileClose}
                      className={cn(
                        'group relative flex items-center gap-2.5 px-2.5 py-[7px] rounded-lg text-[13px] font-normal transition-all duration-150',
                        isActive
                          ? 'text-foreground/90'
                          : 'text-muted-foreground hover:text-foreground/60 hover:bg-muted/50'
                      )}
                    >
                      {/* Active indicator — subtle left accent bar */}
                      {isActive && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-4 rounded-full bg-primary" />
                      )}
                      {Icon && (
                        <Icon className={cn(
                          'shrink-0 transition-colors duration-150',
                          isActive ? 'text-primary' : 'text-muted-foreground/60 group-hover:text-muted-foreground'
                        )} size={16} />
                      )}
                      {!collapsed && (
                        <span className={cn(isActive && 'font-medium')}>{item.label}</span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer with version */}
        {!collapsed && (
          <div className="px-4 py-3 border-t border-border">
            <p className="text-[10px] text-muted-foreground/40 font-mono">v2.0.0</p>
          </div>
        )}

        {/* Collapse Toggle — desktop only */}
        <div className="p-1.5 border-t border-border shrink-0 hidden md:block">
          <button
            onClick={handleCollapse}
            className="w-full flex items-center justify-center py-1.5 rounded-lg text-muted-foreground/50 hover:text-muted-foreground hover:bg-muted/50 transition-all duration-150"
          >
            {collapsed
              ? <ArrowRight01Icon size={14} />
              : <ArrowLeft01Icon size={14} />
            }
          </button>
        </div>
      </aside>
    </>
  );
}

export function SidebarToggle({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground/60 hover:bg-muted/50 transition-all duration-150 md:hidden"
      aria-label="Open navigation"
    >
      <Menu01Icon size={18} />
    </button>
  );
}
