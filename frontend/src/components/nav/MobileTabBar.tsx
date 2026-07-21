'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  DashboardSpeed02Icon,
  Alert02Icon,
  Shield01Icon,
  ServerStack01Icon,
} from 'hugeicons-react';
import { cn } from '@/lib/utils';
import { TOP_NAV_SECTIONS, getActiveSectionId } from '@/components/shared/TopNav';

/**
 * MobileTabBar — the bottom tab bar that replaces the hamburger + push-down
 * drawer below 768px. This is the single piece that makes the dashboard
 * feel like a native app instead of a squeezed desktop page: four
 * top-level destinations, always visible, in the thumb zone.
 *
 * Desktop guarantee: the root <nav> carries `md:hidden`, so at >=768px it
 * computes to `display: none` and paints nothing. `--mobile-tab-h` is also
 * forced to 0px at >=768px in globals.css, so even the (unrendered) height
 * resolves to zero. This file has no importers other than
 * dashboard/layout.tsx, so it cannot alter any existing selector, cascade
 * order or DOM position at desktop widths.
 *
 * Sections and active-route logic are read from TopNav — not duplicated —
 * so this bar can never drift out of sync with the desktop primary nav.
 */

const SECTION_ICONS: Record<string, typeof DashboardSpeed02Icon> = {
  dashboard: DashboardSpeed02Icon,
  threats: Alert02Icon,
  defense: Shield01Icon,
  assets: ServerStack01Icon,
};

export function MobileTabBar() {
  const pathname = usePathname() || '';
  const activeId = getActiveSectionId(pathname);

  return (
    <nav
      role="navigation"
      aria-label="Primary mobile"
      className="md:hidden fixed inset-x-0 bottom-0 z-40 border-t border-border"
      style={{
        background: 'color-mix(in oklab, var(--background) 88%, transparent)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        paddingBottom: 'var(--safe-bottom)',
        paddingLeft: 'var(--safe-left)',
        paddingRight: 'var(--safe-right)',
      }}
    >
      <ul className="flex items-stretch h-[var(--mobile-tab-h)]">
        {TOP_NAV_SECTIONS.map((section) => {
          const isActive = section.id === activeId;
          const Icon = SECTION_ICONS[section.id];
          return (
            <li key={section.id} className="flex-1 flex">
              <Link
                href={section.href}
                aria-current={isActive ? 'page' : undefined}
                className={cn(
                  'relative flex flex-1 flex-col items-center justify-center gap-[3px] rounded-[10px] select-none outline-none',
                  'motion-safe:transition-[transform,opacity] motion-safe:duration-[120ms] motion-safe:ease-out',
                  'active:opacity-70 motion-safe:active:scale-[0.94]',
                  'focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--ring)]',
                  isActive ? 'text-foreground' : 'text-muted-foreground'
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    'absolute top-0 h-[2px] w-[18px] rounded-full motion-safe:transition-opacity motion-safe:duration-150',
                    isActive ? 'opacity-100' : 'opacity-0'
                  )}
                  style={{ backgroundColor: 'var(--brand-accent)' }}
                />
                {Icon && <Icon size={22} />}
                <span className="text-[10px] font-medium leading-[12px] tracking-[0.01em]">
                  {section.label}
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
