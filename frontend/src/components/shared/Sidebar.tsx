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
import { Ghost, GitFork, Atom, FileCheck, FileText, ShieldCheck, ShieldAlert, Sparkles, BookOpen, ShieldX } from 'lucide-react';
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
  ShieldAlert: ShieldAlert as IconComponent,
  ShieldX: ShieldX as IconComponent,
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
      { label: 'Ransomware', href: '/dashboard/ransomware', icon: 'ShieldX' },
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

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm md:hidden animate-fade-in"
          onClick={onMobileClose}
        />
      )}

      <aside
        className={cn(
          'fixed left-0 top-0 z-40 h-screen flex flex-col transition-[width,transform] duration-200 ease-out',
          'bg-sidebar border-r border-sidebar-border',
          collapsed ? 'w-[60px]' : 'w-[224px]',
          'max-md:-translate-x-full max-md:w-[224px]',
          mobileOpen && 'max-md:translate-x-0'
        )}
      >
        {/* Logo / Brand */}
        <div className={cn(
          'flex items-center h-[52px] shrink-0 border-b border-sidebar-border',
          collapsed ? 'justify-center px-0' : 'gap-2.5 px-4'
        )}>
          <div className="relative w-7 h-7 rounded-md bg-gradient-to-br from-primary/20 to-primary/5 border border-primary/30 flex items-center justify-center shrink-0">
            <span className="font-mono text-primary font-bold text-[11px] tracking-wider">A</span>
            <span className="absolute inset-0 rounded-md bg-primary/10 blur-md opacity-60 -z-10" />
          </div>
          {!collapsed && (
            <div className="flex items-baseline gap-1.5 min-w-0">
              <span className="text-sidebar-foreground font-semibold text-[14px] tracking-tight">
                AEGIS
              </span>
              <span className="text-[9px] font-mono text-muted-foreground/50 tracking-widest uppercase mt-px">
                v1.4
              </span>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-2 overflow-y-auto overflow-x-hidden">
          {NAV_SECTIONS.map((section, sIdx) => (
            <div key={section.label} className={cn(sIdx > 0 && 'mt-5')}>
              {!collapsed && (
                <p className="text-label-xs text-muted-foreground/60 px-2.5 mb-1.5">
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
                      title={collapsed ? item.label : undefined}
                      className={cn(
                        'group relative flex items-center gap-2.5 px-2.5 py-[7px] rounded-md text-[13px] transition-all duration-150',
                        isActive
                          ? 'text-sidebar-foreground bg-sidebar-accent'
                          : 'text-muted-foreground hover:text-sidebar-foreground hover:bg-sidebar-accent/60'
                      )}
                    >
                      {isActive && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[2px] h-[60%] rounded-r-full bg-primary" />
                      )}
                      {Icon && (
                        <Icon
                          className={cn(
                            'shrink-0 transition-colors duration-150',
                            isActive ? 'text-primary' : 'text-muted-foreground/70 group-hover:text-sidebar-foreground/80'
                          )}
                          size={16}
                        />
                      )}
                      {!collapsed && (
                        <span className={cn('flex-1 truncate', isActive && 'font-medium')}>
                          {item.label}
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse Toggle */}
        <div className="p-1.5 border-t border-sidebar-border shrink-0 hidden md:block">
          <button
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="w-full flex items-center justify-center py-1.5 rounded-md text-muted-foreground/60 hover:text-sidebar-foreground hover:bg-sidebar-accent/60 transition-all duration-150"
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
      className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-all duration-150 md:hidden"
      aria-label="Open navigation"
    >
      <Menu01Icon size={18} />
    </button>
  );
}
