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
      { label: 'Live View', href: '/dashboard/live', icon: 'FlashIcon' },
      { label: 'Guide', href: '/dashboard/guide', icon: 'BookOpen' },
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
          'fixed left-0 top-0 z-40 h-screen flex flex-col transition-all duration-300',
          'bg-[rgb(var(--c6-surface-rgb)/1)] border-r border-white/[0.06]',
          // Desktop: collapsed width
          collapsed ? 'w-[68px]' : 'w-[240px]',
          // Mobile: hidden by default, slide in as overlay
          'max-md:-translate-x-full max-md:w-[240px]',
          mobileOpen && 'max-md:translate-x-0'
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 h-16 shrink-0">
          <div className="w-8 h-8 rounded-xl bg-[#18181B] border border-white/[0.06] flex items-center justify-center shrink-0">
            <span className="font-mono text-[#22D3EE] font-semibold text-xs tracking-wider">C6</span>
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <h1 className="text-white font-semibold text-[15px] tracking-tight leading-none">
                AEGIS
              </h1>
            </div>
          )}
        </div>

        {/* Navigation Sections */}
        <nav className="flex-1 py-2 px-3 overflow-y-auto space-y-6">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              {!collapsed && (
                <p className="text-[10px] font-semibold text-zinc-600 tracking-widest uppercase px-3 mb-2">
                  {section.label}
                </p>
              )}
              <div className="space-y-0.5">
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
                        'flex items-center gap-3 px-3 py-2 rounded-xl text-[13px] font-medium transition-all duration-150',
                        isActive
                          ? 'bg-[#22D3EE]/[0.08] text-[#22D3EE]'
                          : 'text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.03]'
                      )}
                    >
                      {Icon && (
                        <Icon className={cn(
                          'shrink-0',
                          isActive ? 'text-[#22D3EE]' : 'text-zinc-600'
                        )} size={18} />
                      )}
                      {!collapsed && (
                        <span>{item.label}</span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer */}
        {!collapsed && (
          <div className="px-5 py-4 border-t border-white/[0.06]">
            <p className="text-[11px] text-zinc-600 font-medium">AEGIS Defense</p>
            <p className="text-[10px] text-zinc-700 font-mono">v1.0.0</p>
          </div>
        )}

        {/* Collapse Toggle — desktop only */}
        <div className="p-2 border-t border-white/[0.06] shrink-0 hidden md:block">
          <button
            onClick={handleCollapse}
            className="w-full flex items-center justify-center py-2 rounded-xl text-zinc-600 hover:text-zinc-400 hover:bg-white/[0.03] transition-colors"
          >
            {collapsed
              ? <ArrowRight01Icon size={16} className="text-zinc-600" />
              : <ArrowLeft01Icon size={16} className="text-zinc-600" />
            }
          </button>
        </div>
      </aside>
    </>
  );
}

// Hamburger button to export for mobile use in Header
export function SidebarToggle({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="p-2 rounded-xl text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.03] transition-colors md:hidden"
      aria-label="Open navigation"
    >
      <Menu01Icon size={20} />
    </button>
  );
}
