'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { getActiveSectionId } from '@/components/shared/TopNav';

interface SubTab {
  label: string;
  href: string;
}

const SUB_TABS: Record<string, SubTab[]> = {
  threats: [
    { label: 'Incidents', href: '/dashboard/response' },
    { label: 'Threats', href: '/dashboard/threats' },
    { label: 'Campaigns', href: '/dashboard/threats/campaigns' },
    { label: 'Sharing', href: '/dashboard/threats/sharing' },
    { label: 'IP Intel', href: '/dashboard/ip-intel' },
  ],
  defense: [
    { label: 'Firewall', href: '/dashboard/firewall' },
    { label: 'Phantom', href: '/dashboard/phantom' },
    { label: 'Deception', href: '/dashboard/deception' },
    { label: 'Antivirus', href: '/dashboard/antivirus' },
    { label: 'Ransomware', href: '/dashboard/ransomware' },
    { label: 'EDR / XDR', href: '/dashboard/edr' },
    { label: 'DoS Shield', href: '/dashboard/dos' },
  ],
  assets: [
    { label: 'Surface', href: '/dashboard/surface' },
    { label: 'Infra', href: '/dashboard/infra' },
    { label: 'Attack Path', href: '/dashboard/attack-path' },
  ],
  reports: [
    { label: 'Reports', href: '/dashboard/reports' },
    { label: 'Compliance', href: '/dashboard/compliance' },
    { label: 'Quantum', href: '/dashboard/quantum' },
  ],
};

function isTabActive(pathname: string, href: string): boolean {
  if (pathname === href) return true;
  // For nested routes (campaigns is /dashboard/threats/campaigns), prefer
  // the longest matching prefix — only mark active if no other tab matches deeper.
  return false;
}

function pickActiveHref(pathname: string, tabs: SubTab[]): string | null {
  let best: { href: string; len: number } | null = null;
  for (const t of tabs) {
    if (pathname === t.href || pathname.startsWith(t.href + '/')) {
      if (!best || t.href.length > best.len) best = { href: t.href, len: t.href.length };
    }
  }
  return best?.href ?? null;
}

export function SectionTabs() {
  const pathname = usePathname() || '';
  const sectionId = getActiveSectionId(pathname);
  const tabs = SUB_TABS[sectionId];

  // Render an empty slot to avoid layout shift on initial mount
  if (!tabs || tabs.length === 0) {
    return null;
  }

  const activeHref = pickActiveHref(pathname, tabs);

  return (
    <div className="border-b border-border bg-background">
      <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8">
        <nav
          role="navigation"
          aria-label="Section"
          className="flex items-center gap-1 overflow-x-auto py-2 -mx-1 px-1"
        >
          {tabs.map((tab) => {
            const active = tab.href === activeHref;
            return (
              <Link
                key={tab.href}
                href={tab.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'inline-flex items-center px-3 py-1.5 rounded-md text-[12px] font-medium whitespace-nowrap transition-colors duration-150 outline-none',
                  'focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklab,var(--brand-accent)_55%,transparent)]',
                  active
                    ? 'text-foreground bg-[color-mix(in_oklab,var(--brand-accent)_12%,transparent)] border border-[color-mix(in_oklab,var(--brand-accent)_30%,transparent)]'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/50 border border-transparent'
                )}
                style={active ? { color: 'var(--brand-accent)' } : undefined}
              >
                {tab.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
