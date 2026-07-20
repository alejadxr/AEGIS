'use client';

import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';
import { TopNav } from '@/components/shared/TopNav';
import { SectionTabs } from '@/components/nav/SectionTabs';
import { AskAI } from '@/components/shared/AskAI';

// v1.6.3: routes accessible without an API key (public guide / docs).
const PUBLIC_DASHBOARD_PATHS = new Set<string>(['/dashboard/guide']);

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname() || '';
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // v1.6.3: redirect to /login (not /) with ?next= so user lands on the
    // page they intended after sign-in. /dashboard/guide stays public.
    if (PUBLIC_DASHBOARD_PATHS.has(pathname)) {
      setReady(true);
      return;
    }
    if (!hasAuth()) {
      const next = encodeURIComponent(pathname || '/dashboard');
      router.replace(`/login?next=${next}`);
    } else {
      setReady(true);
    }
  }, [router, pathname]);

  if (!ready) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="w-4 h-4 border border-border border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div
      className="min-h-screen bg-background text-foreground"
      style={
        {
          // Sticky header stack height. TopNav (TopNav.tsx, inner h-16 + 1px
          // border-b) = 65px. CommandBar (CommandBar.tsx, inner h-[52px] +
          // 1px border-b) = 53px. Stuck bottom edge of the pair = 118px.
          // Defined once here (the layout every dashboard page shares) so
          // WatchPanel.tsx, Ledger.tsx and CommandBar.tsx all read the same
          // value instead of repeating a magic number that can drift.
          '--nav-h': '65px',
          '--cmdbar-h': '53px',
          '--sticky-top': '118px',
        } as CSSProperties
      }
    >
      <TopNav />
      <SectionTabs />
      <main className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>
      <AskAI />
    </div>
  );
}
